package api

// Delegation (specs/007, specs/009, protocol *Delegation*): a server allowed to act for users (the actor
// policy) exchanges a user's token for a grant and then calls with its own token plus the grant. A grant
// proves "this request is for user X's session". `use` is the ACTOR's own - the user gets nothing beyond what
// an admin granted the server; management passes through only for a user who is an admin, and only the
// verbs the actor policy lists (administration through a duckdb-acl node).

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hugr-lab/tresor/server/internal/auth"
	"github.com/hugr-lab/tresor/server/internal/config"
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
	minted      *grantTokens // the user's tokens minted at the exchange (specs/010), in memory with the grant
}

type grantKey struct{}

// grantOf is the delegation grant the request was made under, or nil.
func grantOf(r *http.Request) *grant {
	gr, _ := r.Context().Value(grantKey{}).(*grant)
	return gr
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

// full: no room for another grant (after purging the expired ones).
func (g *grants) full(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.purge(now, true)
	return len(g.byID) >= maxGrants
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

// delegated resolves the Delegation header: the effective caller - the user's identity, with Actor set and
// the actor's own principals for every permission check - or an error that is always unauthenticated to the
// client: a grant presented by anyone but its actor is no grant.
func (s *Server) delegated(r *http.Request, actor *auth.Caller) (*auth.Caller, *grant, error) {
	id := strings.TrimSpace(r.Header.Get("Delegation"))
	gr := s.grants.get(id, s.now())
	if gr == nil {
		return nil, nil, errors.New("no such delegation grant (or expired)")
	}
	if gr.actorOwner != actor.Owner() {
		return nil, nil, errors.New("a delegation grant presented by another actor")
	}
	user := gr.user
	user.Principals = slices.Clone(gr.user.Principals)
	user.Actor = gr.actorClient
	user.ActorIssuer = gr.actorIssuer
	user.ActorPrincipals = slices.Clone(actor.Principals)
	user.ExpiresAt = gr.expires
	return &user, gr, nil
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
	gr := &grant{actorOwner: actor.Owner(), actorClient: client, actorIssuer: actor.Issuer, user: *user,
		expires: expires}
	if s.grants.full(s.now()) { // before any exchange at the IdP
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "too many delegation grants")
		return
	}
	// the user's tokens for what the server may mint (specs/010): now, while the subject token lives
	s.mintAtGrant(r.Context(), gr, body.SubjectToken, actor)
	if r.Context().Err() != nil {
		return // the server gave up waiting: no grant nobody holds, with its refresh tokens
	}
	id, err := s.grants.put(gr, s.now())
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

// refuse answers a missing verb: under a grant it is the actor policy's (a server uses only what it was
// granted, and passes on management only for admins, as its policy lists), otherwise no_verb.
func (s *Server) refuse(w http.ResponseWriter, c *auth.Caller, verb string) {
	if c.Actor != "" {
		problem(w, http.StatusForbidden, "actor_not_allowed", "this server may not "+verb+" for users")
		return
	}
	problem(w, http.StatusForbidden, "no_verb", "the caller's roles do not hold "+verb)
}
