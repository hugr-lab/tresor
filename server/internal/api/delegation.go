package api

// Delegation (specs/007, protocol *Delegation*): a secret's rules say which servers may use it for which
// users; a server exchanges a user's token for a grant and then calls with its own token plus the grant.
// Under a grant every check uses the user's principals - the actor policy only takes away, and material
// needs an explicit rule: a server never adds its own authority.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hugr-lab/tresor/server/internal/auth"
	"github.com/hugr-lab/tresor/server/internal/store"
)

const (
	defaultGrantTTL = time.Hour
	maxGrantTTL     = 8 * time.Hour
)

// grant is a delegation grant: in memory only - a bearer credential is never written to disk.
type grant struct {
	actorOwner  string // the subject: of the server it was issued to - only it may present the grant
	actorClient string // its client: principal
	user        auth.Caller
	expires     time.Time
}

type grants struct {
	mu   sync.Mutex
	byID map[string]*grant
}

func (g *grants) put(gr *grant) string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic(err) // no randomness, no grants
	}
	id := hex.EncodeToString(raw)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.byID == nil {
		g.byID = map[string]*grant{}
	}
	g.byID[id] = gr
	return id
}

func (g *grants) get(id string, now time.Time) *grant {
	g.mu.Lock()
	defer g.mu.Unlock()
	for key, gr := range g.byID { // expired grants go whenever one is looked up
		if !now.Before(gr.expires) {
			delete(g.byID, key)
		}
	}
	return g.byID[id]
}

func (g *grants) remove(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.byID, id)
}

// actorVerbs is what the policy lets this server do for users; nil when it may not act at all.
func (s *Server) actorVerbs(client string) []string {
	for _, a := range s.cfg.Policy.Actors {
		if client != "" && a.Principal == client {
			return a.Verbs
		}
	}
	return nil
}

func (s *Server) actorAllowed(client string) bool {
	for _, a := range s.cfg.Policy.Actors {
		if client != "" && a.Principal == client {
			return true
		}
	}
	return false
}

// ruleMatches: a rule of sec delegates to this actor for this user (shared mode - the only one here).
func ruleMatches(sec *store.Secret, c *auth.Caller) bool {
	for _, r := range sec.Rules {
		if r.Mode == "shared" && slices.Contains(r.Actors, c.Actor) && slices.ContainsFunc(r.Subjects, c.Has) {
			return true
		}
	}
	return false
}

// delegated resolves the Delegation header: the effective caller (the user, with Actor set), or an error
// that is always unauthenticated to the client - a grant presented by anyone but its actor is no grant.
func (s *Server) delegated(r *http.Request, actor *auth.Caller) (*auth.Caller, error) {
	id := strings.TrimSpace(r.Header.Get("Delegation"))
	gr := s.grants.get(id, s.now())
	if gr == nil {
		return nil, errors.New("no such delegation grant (or expired)")
	}
	if gr.actorOwner != actor.Owner() {
		return nil, errors.New("a delegation grant presented by another actor")
	}
	user := gr.user
	user.Principals = slices.Clone(gr.user.Principals)
	user.Actor = gr.actorClient
	user.ExpiresAt = gr.expires
	return &user, nil
}

// --- rules -------------------------------------------------------------------------------------------

type ruleBody struct {
	Actors     []string `json:"actors"`
	Subjects   []string `json:"subjects"`
	Mode       string   `json:"mode"`
	Operations []string `json:"operations"`
	Scope      []string `json:"scope"`
	TTL        int64    `json:"ttl"`
}

func ruleJSON(r store.Rule) map[string]any {
	orEmpty := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	return map[string]any{"id": r.ID, "actors": orEmpty(r.Actors), "subjects": orEmpty(r.Subjects), "mode": r.Mode,
		"operations": orEmpty(r.Operations), "scope": orEmpty(r.Scope), "ttl": r.TTL}
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	sec, verbs, ok := s.visible(w, callerOf(r), r.PathValue("name"))
	if !ok {
		return
	}
	if !slices.Contains(verbs, "delegate") {
		s.refuse(w, callerOf(r), sec, "delegate")
		return
	}
	out := []map[string]any{}
	for _, rule := range sec.Rules {
		out = append(out, ruleJSON(rule))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) addRule(w http.ResponseWriter, r *http.Request) {
	var body ruleBody
	if err := readJSON(r, &body); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "a rule is {actors[], subjects[], mode, ...}")
		return
	}
	var added store.Rule
	_, ok := s.mutate(w, r, "delegate", func(current *store.Secret) (*store.Secret, error) {
		if len(body.Actors) == 0 || len(body.Subjects) == 0 {
			return nil, fmt.Errorf("%w: a rule names its actors and subjects", errInvalid)
		}
		for _, a := range body.Actors {
			if !strings.HasPrefix(a, "client:") || len(a) <= len("client:") {
				return nil, fmt.Errorf("%w: an actor is a service, client:<id>", errInvalid)
			}
		}
		for _, p := range body.Subjects {
			if !validPrincipal(p) {
				return nil, fmt.Errorf("%w: a subject is a role:, group:, subject: or client: principal", errInvalid)
			}
		}
		switch body.Mode {
		case "shared":
		case "user":
			return nil, fmt.Errorf("%w: mode user needs personal credentials, which this server cannot issue", errInvalid)
		default:
			return nil, fmt.Errorf("%w: mode is shared or user", errInvalid)
		}
		if body.TTL < 0 {
			return nil, fmt.Errorf("%w: ttl is seconds, not negative", errInvalid)
		}
		raw := make([]byte, 6)
		_, _ = rand.Read(raw)
		added = store.Rule{ID: "d-" + hex.EncodeToString(raw), Actors: body.Actors, Subjects: body.Subjects,
			Mode: body.Mode, Operations: body.Operations, Scope: body.Scope, TTL: body.TTL}
		current.Rules = append(current.Rules, added)
		current.Version++
		current.UpdatedAt = s.now()
		return current, nil
	})
	if ok {
		writeJSON(w, http.StatusCreated, ruleJSON(added))
	}
}

func (s *Server) removeRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, ok := s.mutate(w, r, "delegate", func(current *store.Secret) (*store.Secret, error) {
		kept := current.Rules[:0]
		found := false
		for _, rule := range current.Rules {
			if rule.ID == id {
				found = true
				continue
			}
			kept = append(kept, rule)
		}
		if !found {
			return nil, store.ErrNotFound
		}
		current.Rules = kept
		current.Version++
		current.UpdatedAt = s.now()
		return current, nil
	})
	if ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- grants ------------------------------------------------------------------------------------------

func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	actor := callerOf(r)
	if actor.Actor != "" {
		problem(w, http.StatusForbidden, "actor_not_allowed", "a grant is exchanged with the server's own token only")
		return
	}
	client := actor.Client()
	if !actor.Service || !s.actorAllowed(client) {
		problem(w, http.StatusForbidden, "actor_not_allowed", "this caller may not act for users")
		return
	}
	var body struct {
		SubjectToken string `json:"subject_token"`
		TTL          int64  `json:"ttl"`
	}
	if err := readJSON(r, &body); err != nil || body.SubjectToken == "" {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "an exchange is {subject_token, ttl?}")
		return
	}
	user, err := s.verifier.Verify(r.Context(), body.SubjectToken)
	if err != nil {
		s.log.Warn("subject token refused", "actor", client, "reason", err.Error())
		problem(w, http.StatusUnauthorized, "unauthenticated", "the subject token is missing, invalid or expired")
		return
	}
	ttl := defaultGrantTTL
	if body.TTL > 0 {
		ttl = time.Duration(body.TTL) * time.Second
	}
	if ttl > maxGrantTTL {
		ttl = maxGrantTTL
	}
	expires := s.now().Add(ttl)
	id := s.grants.put(&grant{actorOwner: actor.Owner(), actorClient: client, user: *user, expires: expires})
	s.log.Info("delegation granted", "actor", client, "user", user.Owner(), "expires", expires.UTC())
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "subject": user.Subject, "actor": client, "expires_at": expires.UTC().Format(time.RFC3339),
	})
}

func (s *Server) revokeGrant(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	gr := s.grants.get(r.PathValue("id"), s.now())
	if gr == nil || c.Actor != "" || (gr.actorOwner != c.Owner() && !s.isAdmin(c)) {
		problem(w, http.StatusNotFound, "not_found", "no such delegation grant")
		return
	}
	s.grants.remove(r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// refuse answers a missing verb: under a grant, a verb the user holds but the actor may not exercise is
// actor_not_allowed; otherwise no_verb.
func (s *Server) refuse(w http.ResponseWriter, c *auth.Caller, sec *store.Secret, verb string) {
	if c.Actor != "" && slices.Contains(s.userVerbs(c, sec), verb) {
		problem(w, http.StatusForbidden, "actor_not_allowed", "this server may not "+verb+" for users")
		return
	}
	problem(w, http.StatusForbidden, "no_verb", "the caller's roles do not hold "+verb)
}
