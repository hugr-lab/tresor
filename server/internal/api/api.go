// Package api is the duckdb-secrets/1 HTTP surface of the reference server (specs/003,
// website/docs/protocol.md). Every decision uses the caller's own principals; nothing here logs a token
// or a secret's material.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hugr-lab/tresor/server/internal/auth"
	"github.com/hugr-lab/tresor/server/internal/config"
	"github.com/hugr-lab/tresor/server/internal/store"
)

// Protocol is the discovery document's protocol string.
const Protocol = "duckdb-secrets/1"

// the per-secret verbs, in the protocol's order
var allVerbs = []string{"use", "update", "delete", "annotate", "grant", "delegate"}

// Server serves the protocol.
type Server struct {
	cfg      *config.Config
	verifier *auth.Verifier
	store    *store.Store
	log      *slog.Logger
	now      func() time.Time
	grants   grants
}

// New wires a server; the verifier and the store are the caller's.
func New(cfg *config.Config, verifier *auth.Verifier, st *store.Store, log *slog.Logger) *Server {
	return &Server{cfg: cfg, verifier: verifier, store: st, log: log, now: time.Now}
}

// Handler returns the routes, under the path of public_url (a service may live below a base path: the
// client asks <base>/.well-known/duckdb-secrets and appends /v1/... to `api`).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/duckdb-secrets", s.discovery)
	mux.HandleFunc("GET /v1/whoami", s.authed(s.whoami))
	mux.HandleFunc("GET /v1/secrets", s.authed(s.listSecrets))
	mux.HandleFunc("GET /v1/secrets/{name}", s.authed(s.getSecret))
	mux.HandleFunc("PUT /v1/secrets/{name}", s.authed(s.putSecret))
	mux.HandleFunc("DELETE /v1/secrets/{name}", s.authed(s.deleteSecret))
	mux.HandleFunc("PATCH /v1/secrets/{name}", s.authed(s.patchSecret))
	mux.HandleFunc("GET /v1/secrets/{name}/grants", s.authed(s.listGrants))
	mux.HandleFunc("PUT /v1/secrets/{name}/grants/{id}", s.authed(s.putGrant))
	mux.HandleFunc("DELETE /v1/secrets/{name}/grants/{id}", s.authed(s.deleteGrant))
	mux.HandleFunc("GET /v1/secrets/{name}/delegations", s.authed(s.listRules))
	mux.HandleFunc("POST /v1/secrets/{name}/delegations", s.authed(s.addRule))
	mux.HandleFunc("DELETE /v1/secrets/{name}/delegations/{id}", s.authed(s.removeRule))
	mux.HandleFunc("POST /v1/delegations", s.authed(s.exchange))
	mux.HandleFunc("DELETE /v1/delegations/{id}", s.authed(s.revokeGrant))
	mux.HandleFunc("DELETE /v1/delegations", s.authed(s.revokeGrants))
	// anything else - an unknown path, a known path with another method - is a problem document too
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		problem(w, http.StatusNotFound, "not_found", "no such resource: "+r.Method+" "+r.URL.Path)
	})
	var h http.Handler = mux
	if u, err := url.Parse(s.cfg.PublicURL); err == nil && strings.TrimRight(u.Path, "/") != "" {
		h = http.StripPrefix(strings.TrimRight(u.Path, "/"), mux)
	}
	return s.logged(h)
}

// --- plumbing --------------------------------------------------------------------------------------

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

type callerKey struct{}

func callerOf(r *http.Request) *auth.Caller {
	c, _ := r.Context().Value(callerKey{}).(*auth.Caller)
	return c
}

// logged is the request log: method, path, status, subject - never a header or a body.
func (s *Server) logged(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		start := time.Now()
		holder := &auth.Caller{}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), loggedCallerKey{}, holder)))
		s.log.Info("request", "method", r.Method, "path", loggedPath(r.URL.Path), "status", rec.status,
			"subject", holder.Subject, "ms", time.Since(start).Milliseconds())
	})
}

type loggedCallerKey struct{}

// loggedPath is a request's path as logged: a delegation grant's id is a bearer credential, so the path
// that names one (DELETE /v1/delegations/{id}) is logged without it.
func loggedPath(path string) string {
	if i := strings.Index(path, "/v1/delegations/"); i >= 0 {
		return path[:i] + "/v1/delegations/…"
	}
	return path
}

// authed verifies the bearer token; a failure is 401 unauthenticated with the reason in the log only.
func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// the scheme is case-insensitive (RFC 9110 §11.1)
		header := r.Header.Get("Authorization")
		scheme, raw, ok := strings.Cut(header, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(raw) == "" {
			problem(w, http.StatusUnauthorized, "unauthenticated", "a bearer token is required")
			return
		}
		caller, err := s.verifier.Verify(r.Context(), strings.TrimSpace(raw))
		if err != nil {
			s.log.Warn("token refused", "reason", err.Error())
			problem(w, http.StatusUnauthorized, "unauthenticated", "token missing, invalid or expired")
			return
		}
		if r.Header.Get("Delegation") != "" {
			// a server acting for a user: its own token proved who it is, the grant says for whom
			user, err := s.delegated(r, caller)
			if err != nil {
				s.log.Warn("delegation refused", "actor", caller.Owner(), "reason", err.Error())
				problem(w, http.StatusUnauthorized, "unauthenticated", "the delegation grant is not valid for this caller")
				return
			}
			caller = user
		}
		if holder, ok := r.Context().Value(loggedCallerKey{}).(*auth.Caller); ok {
			subject := caller.Owner() // never the grant id
			if caller.Actor != "" {
				subject += " via " + caller.Actor
			}
			*holder = auth.Caller{Subject: subject}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, caller)))
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// problem is an RFC 9457 error with a type from the protocol's list.
func problem(w http.ResponseWriter, status int, kind, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": kind, "title": kind, "status": status, "detail": detail})
}

// readJSON reads one JSON document of at most 1 MiB, with no unknown fields and nothing after it.
func readJSON(r *http.Request, into any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil {
		return err
	}
	if len(body) > 1<<20 {
		return errors.New("the body is larger than 1 MiB")
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}

// --- permissions ------------------------------------------------------------------------------------

func (s *Server) isAdmin(c *auth.Caller) bool {
	return slices.ContainsFunc(s.cfg.Policy.Admins, c.Has)
}

// verbs is what the caller may do with sec. Without a grant: every verb for an admin or the owner, else
// its grants'. Under a grant: the user's verbs the actor may exercise - but `use` only through a rule
// (a secret without a rule is not delegated), and then even if the user does not hold `use` (shared).
func (s *Server) verbs(c *auth.Caller, sec *store.Secret) []string {
	user := s.userVerbs(c, sec)
	if c.Actor == "" {
		return user
	}
	allowed := s.actorVerbs(c.Actor, c.ActorIssuer)
	out := []string{} // a list, never null: a secret the user sees but the actor may not act on is []
	for _, v := range allVerbs {
		switch {
		case v == "use":
			if slices.Contains(allowed, "use") && ruleMatches(sec, c) {
				out = append(out, v)
			}
		case slices.Contains(user, v) && slices.Contains(allowed, v):
			out = append(out, v)
		}
	}
	return out
}

// userVerbs is what the user alone may do: every verb for an admin or the owner, else its grants'.
func (s *Server) userVerbs(c *auth.Caller, sec *store.Secret) []string {
	if s.isAdmin(c) || c.Owner() == sec.Owner {
		return slices.Clone(allVerbs)
	}
	var out []string
	for _, v := range allVerbs { // in the protocol's order
		if slices.Contains(store.VerbsOf(sec, c.Principals), v) {
			out = append(out, v)
		}
	}
	return out
}

// createPatterns is `permissions.create`: true (anything), false, or the name patterns.
func (s *Server) createPatterns(c *auth.Caller) (all bool, patterns []string) {
	if s.isAdmin(c) {
		return true, nil
	}
	for _, rule := range s.cfg.Policy.Create {
		if !c.Has(rule.Principal) {
			continue
		}
		for _, n := range rule.Names {
			if n == "*" {
				return true, nil
			}
			if !slices.Contains(patterns, n) {
				patterns = append(patterns, n)
			}
		}
	}
	return false, patterns
}

func (s *Server) mayCreate(c *auth.Caller, name string) bool {
	if c.Actor != "" && !slices.Contains(s.actorVerbs(c.Actor, c.ActorIssuer), "create") {
		return false // creating for users is a management verb: denied unless the actor policy lists it
	}
	all, patterns := s.createPatterns(c)
	if all {
		return true
	}
	for _, p := range patterns {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

// visible fetches a secret the caller holds any verb on (under a grant: the user sees it, or a rule
// delegates it); an invisible one is the same 404 as a missing one, so a name's existence does not leak.
func (s *Server) visible(w http.ResponseWriter, c *auth.Caller, name string) (*store.Secret, []string, bool) {
	sec, err := s.store.Get(name)
	if err == nil {
		verbs := s.verbs(c, sec)
		if len(verbs) > 0 || (c.Actor != "" && len(s.userVerbs(c, sec)) > 0) {
			return sec, verbs, true
		}
	}
	problem(w, http.StatusNotFound, "not_found", fmt.Sprintf("no secret %q", name))
	return nil, nil, false
}

// --- discovery and identity ------------------------------------------------------------------------

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	issuers := make([]map[string]any, 0, len(s.cfg.Issuers))
	for _, is := range s.cfg.Issuers {
		entry := map[string]any{"issuer": is.Issuer, "audience": is.Audience}
		if is.ClientID != "" {
			entry["client_id"] = is.ClientID
		}
		if is.Scopes != nil {
			entry["scopes"] = is.Scopes
		}
		if is.HumanFlows != nil {
			entry["human_flows"] = is.HumanFlows
		}
		if is.ServiceFlows != nil {
			entry["service_flows"] = is.ServiceFlows
		}
		issuers = append(issuers, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"protocol": Protocol,
		"api":      strings.TrimRight(s.cfg.PublicURL, "/"),
		"issuers":  issuers,
		"capabilities": map[string]bool{
			"write": true, "annotate": true, "dynamic": false, "delegation": true,
		},
	})
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	var create any = false
	if c.Actor != "" && !slices.Contains(s.actorVerbs(c.Actor, c.ActorIssuer), "create") {
		// under a grant: what the user may create through this server - nothing, unless the policy says so
	} else if all, patterns := s.createPatterns(c); all {
		create = true
	} else if len(patterns) > 0 {
		create = patterns
	}
	roles := []string{}
	for _, p := range c.Principals {
		if !strings.HasPrefix(p, "subject:") {
			roles = append(roles, p)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":      c.Issuer,
		"subject":     c.Subject,
		"roles":       roles,
		"actor":       nilIfEmpty(c.Actor),
		"expires_at":  c.ExpiresAt.UTC().Format(time.RFC3339),
		"permissions": map[string]any{"create": create},
	})
}

func nilIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// --- secrets -----------------------------------------------------------------------------------------

func descriptor(sec *store.Secret, verbs []string) map[string]any {
	if verbs == nil {
		verbs = []string{}
	}
	// the rules are summarised to callers who may manage them
	var delegation any
	if slices.Contains(verbs, "delegate") {
		delegation = map[string]any{"rules": len(sec.Rules)}
	}
	scope := sec.Scope
	if scope == nil {
		scope = []string{}
	}
	return map[string]any{
		"name":        sec.Name,
		"type":        sec.Type,
		"provider":    sec.Provider,
		"scope":       scope,
		"comment":     sec.Comment,
		"owner":       sec.Owner,
		"created_at":  sec.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":  sec.UpdatedAt.UTC().Format(time.RFC3339),
		"version":     strconv.FormatInt(sec.Version, 10),
		"dynamic":     false,
		"permissions": verbs,
		"delegation":  delegation,
	}
}

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	typ := r.URL.Query().Get("type")
	out := []map[string]any{}
	for _, sec := range s.store.List() {
		if typ != "" && !strings.EqualFold(sec.Type, typ) {
			continue
		}
		verbs := s.verbs(c, sec)
		if len(verbs) > 0 || (c.Actor != "" && len(s.userVerbs(c, sec)) > 0) {
			out = append(out, descriptor(sec, verbs))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getSecret(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	sec, verbs, ok := s.visible(w, c, r.PathValue("name"))
	if !ok {
		return
	}
	if !slices.Contains(verbs, "use") {
		switch {
		case c.Actor != "" && !slices.Contains(s.actorVerbs(c.Actor, c.ActorIssuer), "use"):
			problem(w, http.StatusForbidden, "actor_not_allowed", "this server may not use secrets for users")
		case c.Actor != "":
			problem(w, http.StatusForbidden, "not_delegable", "no delegation rule lets this server use it for this user")
		default:
			problem(w, http.StatusForbidden, "no_verb", "the caller's roles do not hold use")
		}
		return
	}
	body := descriptor(sec, verbs)
	params := sec.Params
	if params == nil {
		params = map[string]json.RawMessage{}
	}
	redact := sec.RedactKeys
	if redact == nil {
		redact = []string{}
	}
	body["params"] = params
	body["redact_keys"] = redact
	body["expires_at"] = nil
	if c.Actor != "" {
		// through a grant: the matching rule's ttl bounds how long the server may hold the material
		var ttl int64
		for _, rule := range sec.Rules {
			if rule.Mode == "shared" && rule.TTL > 0 && slices.Contains(rule.Actors, c.Actor) &&
				slices.ContainsFunc(rule.Subjects, c.Has) && (ttl == 0 || rule.TTL < ttl) {
				ttl = rule.TTL
			}
		}
		if ttl > 0 {
			body["expires_at"] = s.now().Add(time.Duration(ttl) * time.Second).UTC().Format(time.RFC3339)
		}
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(sec.Version, 10)))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, body)
}

type secretBody struct {
	Type       string                     `json:"type"`
	Provider   string                     `json:"provider"`
	Scope      []string                   `json:"scope"`
	Params     map[string]json.RawMessage `json:"params"`
	RedactKeys []string                   `json:"redact_keys"`
	Comment    *string                    `json:"comment"`
}

// validParams: every value a string or {type, value} (protocol, Material).
func validParams(params map[string]json.RawMessage, redact []string) error {
	for key, raw := range params {
		if key == "" {
			return errors.New("an empty parameter name")
		}
		if strings.TrimSpace(string(raw)) == "null" {
			return fmt.Errorf("parameter %q is null", key)
		}
		var str string
		if json.Unmarshal(raw, &str) == nil {
			continue
		}
		var typed struct {
			Type  string          `json:"type"`
			Value json.RawMessage `json:"value"`
		}
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if dec.Decode(&typed) != nil || typed.Type == "" || typed.Value == nil || string(typed.Value) == "null" {
			return fmt.Errorf("parameter %q is neither a string nor {type, value}", key)
		}
	}
	for _, k := range redact {
		if _, ok := params[k]; !ok {
			return fmt.Errorf("redact key %q is not a parameter", k)
		}
	}
	return nil
}

func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	c := callerOf(r)
	name := r.PathValue("name")
	var body secretBody
	if err := readJSON(r, &body); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "the body is not a secret: "+err.Error())
		return
	}
	if body.Type == "" {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "type is required")
		return
	}
	if err := validParams(body.Params, body.RedactKeys); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", err.Error())
		return
	}
	// If-None-Match: "*" (CREATE) fails on any existing secret; with an ETag, on that version only
	ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match"))
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	type refusal struct {
		status       int
		kind, detail string
	}
	var refused *refusal
	now := s.now()
	created := false
	saved, err := s.store.Update(name, func(current *store.Secret) (*store.Secret, error) {
		if current == nil {
			if ifMatch != "" {
				return nil, store.ErrPrecondition
			}
			if !s.mayCreate(c, name) {
				refused = &refusal{http.StatusForbidden, "no_verb", "the caller may not create " + strconv.Quote(name)}
				return nil, errors.New("refused")
			}
			created = true
			return &store.Secret{
				Type: body.Type, Provider: body.Provider, Scope: body.Scope, Params: body.Params,
				RedactKeys: body.RedactKeys, Comment: deref(body.Comment), Owner: c.Owner(),
				CreatedAt: now, UpdatedAt: now, Version: 1,
			}, nil
		}
		verbs := s.verbs(c, current)
		if len(verbs) == 0 {
			// invisible: creating it would collide with a name the caller must not learn exists
			refused = &refusal{http.StatusForbidden, "no_verb", "the caller may not create " + strconv.Quote(name)}
			return nil, errors.New("refused")
		}
		currentTag := strconv.Quote(strconv.FormatInt(current.Version, 10))
		if ifNoneMatch == "*" || (ifNoneMatch != "" && ifNoneMatch == currentTag) {
			return nil, store.ErrPrecondition
		}
		if ifMatch != "" && ifMatch != currentTag && ifMatch != "*" {
			return nil, store.ErrPrecondition
		}
		if !slices.Contains(verbs, "update") {
			refused = &refusal{http.StatusForbidden, "no_verb", "the caller's roles do not hold update"}
			return nil, errors.New("refused")
		}
		next := *current
		next.Type, next.Provider, next.Scope = body.Type, body.Provider, body.Scope
		next.Params, next.RedactKeys = body.Params, body.RedactKeys
		if body.Comment != nil {
			next.Comment = *body.Comment
		}
		next.UpdatedAt = now
		next.Version++
		return &next, nil
	})
	switch {
	case refused != nil:
		problem(w, refused.status, refused.kind, refused.detail)
	case errors.Is(err, store.ErrPrecondition):
		problem(w, http.StatusPreconditionFailed, "precondition_failed", "If-None-Match / If-Match not met")
	case err != nil:
		s.log.Error("store write failed", "secret", name, "error", err.Error())
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "the store could not be written")
	default:
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(saved.Version, 10)))
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		writeJSON(w, status, descriptor(saved, s.verbs(c, saved)))
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// mutate runs a change that needs `verb` on a visible secret; fn may refuse with a problem of its own.
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, verb string,
	fn func(current *store.Secret) (*store.Secret, error)) (*store.Secret, bool) {
	c := callerOf(r)
	name := r.PathValue("name")
	var missing, forbidden bool
	var refusedOn *store.Secret
	saved, err := s.store.Update(name, func(current *store.Secret) (*store.Secret, error) {
		if current == nil {
			missing = true
			return nil, store.ErrNotFound
		}
		verbs := s.verbs(c, current)
		if len(verbs) == 0 && !(c.Actor != "" && len(s.userVerbs(c, current)) > 0) {
			missing = true
			return nil, store.ErrNotFound
		}
		if !slices.Contains(verbs, verb) {
			forbidden = true
			refusedOn = current
			return nil, errors.New("refused")
		}
		return fn(current)
	})
	switch {
	case missing:
		problem(w, http.StatusNotFound, "not_found", fmt.Sprintf("no secret %q", name))
	case forbidden:
		s.refuse(w, c, refusedOn, verb)
	case errors.Is(err, errNotHeld):
		problem(w, http.StatusForbidden, "no_verb", strings.TrimPrefix(err.Error(), errNotHeld.Error()+": "))
	case errors.Is(err, errInvalid):
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", strings.TrimPrefix(err.Error(), errInvalid.Error()+": "))
	case errors.Is(err, store.ErrNotFound):
		problem(w, http.StatusNotFound, "not_found", "no such grant")
	case err != nil:
		s.log.Error("store write failed", "secret", name, "error", err.Error())
		problem(w, http.StatusServiceUnavailable, "service_unavailable", "the store could not be written")
	default:
		return saved, true
	}
	return nil, false
}

var (
	errInvalid = errors.New("invalid")
	errNotHeld = errors.New("not held")
)

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.mutate(w, r, "delete", func(*store.Secret) (*store.Secret, error) { return nil, nil }); ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) patchSecret(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Comment *string `json:"comment"`
	}
	if err := readJSON(r, &body); err != nil || body.Comment == nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "PATCH takes {\"comment\": \"...\"}")
		return
	}
	now := s.now()
	saved, ok := s.mutate(w, r, "annotate", func(current *store.Secret) (*store.Secret, error) {
		current.Comment = *body.Comment
		current.UpdatedAt = now
		current.Version++
		return current, nil
	})
	if ok {
		writeJSON(w, http.StatusOK, descriptor(saved, s.verbs(callerOf(r), saved)))
	}
}

// --- grants ------------------------------------------------------------------------------------------

func grantList(sec *store.Secret) []store.Grant {
	if sec.Grants == nil {
		return []store.Grant{}
	}
	return sec.Grants
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	sec, verbs, ok := s.visible(w, callerOf(r), r.PathValue("name"))
	if !ok {
		return
	}
	if !slices.Contains(verbs, "grant") {
		s.refuse(w, callerOf(r), sec, "grant")
		return
	}
	writeJSON(w, http.StatusOK, grantList(sec))
}

func (s *Server) putGrant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Principal string   `json:"principal"`
		Verbs     []string `json:"verbs"`
	}
	if err := readJSON(r, &body); err != nil {
		problem(w, http.StatusUnprocessableEntity, "invalid_secret", "a grant is {principal, verbs[]}")
		return
	}
	id := r.PathValue("id")
	c := callerOf(r)
	saved, ok := s.mutate(w, r, "grant", func(current *store.Secret) (*store.Secret, error) {
		if !validPrincipal(body.Principal) || len(body.Verbs) == 0 {
			return nil, fmt.Errorf("%w: a grant is {principal, verbs[]} with a role:, group:, subject: or client: principal", errInvalid)
		}
		held := s.grantable(c, current)
		for _, v := range body.Verbs {
			if !config.KnownVerb(v) {
				return nil, fmt.Errorf("%w: unknown verb %q", errInvalid, v)
			}
			// a grant never passes on more than its grantor holds: `grant` alone must not become `use`
			if !slices.Contains(held, v) {
				return nil, fmt.Errorf("%w: the caller does not hold %q, so it cannot grant it", errNotHeld, v)
			}
		}
		grant := store.Grant{ID: id, Principal: body.Principal, Verbs: body.Verbs}
		replaced := false
		for i := range current.Grants {
			if current.Grants[i].ID == id {
				current.Grants[i] = grant
				replaced = true
			}
		}
		if !replaced {
			current.Grants = append(current.Grants, grant)
		}
		current.Version++
		current.UpdatedAt = s.now()
		return current, nil
	})
	if ok {
		writeJSON(w, http.StatusOK, grantList(saved))
	}
}

func (s *Server) deleteGrant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_, ok := s.mutate(w, r, "grant", func(current *store.Secret) (*store.Secret, error) {
		kept := current.Grants[:0]
		found := false
		for _, g := range current.Grants {
			if g.ID == id {
				found = true
				continue
			}
			kept = append(kept, g)
		}
		if !found {
			return nil, store.ErrNotFound
		}
		current.Grants = kept
		current.Version++
		current.UpdatedAt = s.now()
		return current, nil
	})
	if ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func validPrincipal(p string) bool {
	for _, prefix := range []string{"role:", "group:", "subject:", "client:"} {
		if strings.HasPrefix(p, prefix) && len(p) > len(prefix) {
			return true
		}
	}
	return false
}
