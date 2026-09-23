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
	"github.com/hugr-lab/tresor/server/internal/config"
	"github.com/hugr-lab/tresor/server/internal/store"
)

const (
	defaultGrantTTL = time.Hour
	maxGrantTTL     = 8 * time.Hour
	maxGrants       = 100000 // in memory: an allowed actor must not be able to exhaust it
)

// grant is a delegation grant: in memory only - a bearer credential is never written to disk.
type grant struct {
	actorOwner  string // the subject: of the server it was issued to - only it may present the grant
	actorClient string // its client: principal
	actorIssuer string
	user        auth.Caller
	expires     time.Time
}

type grants struct {
	mu     sync.Mutex
	byID   map[string]*grant
	purged time.Time
}

var errTooManyGrants = errors.New("too many delegation grants")

func (g *grants) put(gr *grant, now time.Time) (string, error) {
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
	g.purge(now, true)
	if len(g.byID) >= maxGrants {
		return "", errTooManyGrants
	}
	g.byID[id] = gr
	return id, nil
}

// purge drops expired grants; at most once a second unless forced (a lookup must not scan the map).
func (g *grants) purge(now time.Time, force bool) {
	if !force && now.Sub(g.purged) < time.Second {
		return
	}
	g.purged = now
	for key, gr := range g.byID {
		if !now.Before(gr.expires) {
			delete(g.byID, key)
		}
	}
}

func (g *grants) get(id string, now time.Time) *grant {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.purge(now, false)
	gr := g.byID[id]
	if gr == nil || !now.Before(gr.expires) {
		return nil
	}
	return gr
}

// revokeWhere removes every grant `match` accepts; how many.
func (g *grants) revokeWhere(match func(*grant) bool) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for key, gr := range g.byID {
		if match(gr) {
			delete(g.byID, key)
			n++
		}
	}
	return n
}

func (g *grants) remove(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.byID, id)
}

// actorVerbs is what the policy lets this server (its client: principal, from this issuer) do for users;
// nil when it may not act at all.
func (s *Server) actorVerbs(client, issuer string) []string {
	for _, a := range s.cfg.Policy.Actors {
		if client != "" && a.Principal == client &&
			(a.Issuer == "" || config.IssuerKey(a.Issuer) == config.IssuerKey(issuer)) {
			return a.Verbs
		}
	}
	return nil
}

func (s *Server) actorAllowed(client, issuer string) bool {
	return len(s.actorVerbs(client, issuer)) > 0
}

// grantable is what the caller may pass on to others: the user's own verbs, and under a grant only those
// the actor may exercise. A `use` that comes from a delegation rule is never among them - a server must
// not turn a rule into a standing grant, for the user or for itself.
func (s *Server) grantable(c *auth.Caller, sec *store.Secret) []string {
	user := s.userVerbs(c, sec)
	if c.Actor == "" {
		return user
	}
	allowed := s.actorVerbs(c.Actor, c.ActorIssuer)
	var out []string
	for _, v := range user {
		if slices.Contains(allowed, v) {
			out = append(out, v)
		}
	}
	return out
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
	user.ActorIssuer = gr.actorIssuer
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
	c := callerOf(r)
	_, ok := s.mutate(w, r, "delegate", func(current *store.Secret) (*store.Secret, error) {
		// a shared rule passes on use: its author must hold use itself (delegate alone is not more than use)
		if !slices.Contains(s.grantable(c, current), "use") {
			return nil, fmt.Errorf("%w: a delegation rule passes on use, which the caller does not hold", errNotHeld)
		}
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
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
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
	if !actor.Service || !s.actorAllowed(client, actor.Issuer) {
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
	// a grant is a person's, for a server: not a service's, and never the actor's own
	if user.Service || user.Owner() == actor.Owner() {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "the subject token must be a person's")
		return
	}
	ttl := defaultGrantTTL
	if body.TTL > 0 && body.TTL < int64(maxGrantTTL/time.Second) { // bounded before the multiplication
		ttl = time.Duration(body.TTL) * time.Second
	} else if body.TTL > 0 {
		ttl = maxGrantTTL
	}
	expires := s.now().Add(ttl)
	id, err := s.grants.put(&grant{actorOwner: actor.Owner(), actorClient: client, actorIssuer: actor.Issuer,
		user: *user, expires: expires}, s.now())
	if err != nil {
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "too many delegation grants")
		return
	}
	s.log.Info("delegation granted", "actor", client, "user", user.Owner(), "expires", expires.UTC())
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "subject": user.Subject, "actor": client, "expires_at": expires.UTC().Format(time.RFC3339),
	})
}

// revokeGrants is central revocation (DELETE /v1/delegations?actor=client:x&subject=subject:...): an
// admin revokes every grant matching the filters (at least one); anyone else revokes the grants made
// for themselves - a user ends every session a server holds for them.
func (s *Server) revokeGrants(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	if c.Actor != "" {
		problem(w, http.StatusForbidden, "actor_not_allowed", "grants are revoked with the caller's own token")
		return
	}
	actor, subject := r.URL.Query().Get("actor"), r.URL.Query().Get("subject")
	var n int
	if s.isAdmin(c) {
		if actor == "" && subject == "" {
			problem(w, http.StatusUnprocessableEntity, "invalid_secret", "name an actor or a subject to revoke")
			return
		}
		n = s.grants.revokeWhere(func(g *grant) bool {
			return (actor == "" || g.actorClient == actor) && (subject == "" || g.user.Owner() == subject)
		})
	} else {
		n = s.grants.revokeWhere(func(g *grant) bool {
			return g.user.Owner() == c.Owner() && (actor == "" || g.actorClient == actor)
		})
	}
	s.log.Info("delegation grants revoked", "by", c.Owner(), "actor", actor, "subject", subject, "count", n)
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
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
