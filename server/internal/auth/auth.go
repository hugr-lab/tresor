// Package auth verifies bearer tokens against the configured issuers and turns their claims into
// principals (specs/003). It never logs or returns a token.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/hugr-lab/tresor/server/internal/config"
)

// Caller is who a verified token speaks for.
type Caller struct {
	Issuer     string
	Subject    string
	Principals []string // subject:, role:, group:, client:
	Service    bool     // a client-credentials token (the issuer's service rule): Principals carries client:
	ExpiresAt  time.Time
	// Actor is set when a server acts for this user through a delegation grant (specs/007): its client:
	// principal. The rest of the Caller is the user's, as taken at the grant's exchange.
	Actor string
}

// Client is the caller's client: principal (a service), or "".
func (c *Caller) Client() string {
	for _, p := range c.Principals {
		if strings.HasPrefix(p, "client:") {
			return p
		}
	}
	return ""
}

// Owner is the principal a caller's creations belong to: always its subject: - iss and sub, unique
// across issuers and across callers. (A client: principal is a client's name, shared by every token
// of that client and, with several issuers, by same-named clients of each: it names who may do
// something, never who someone is.)
func (c *Caller) Owner() string {
	return "subject:" + c.Issuer + "|" + c.Subject
}

// Has says whether the caller holds principal p.
func (c *Caller) Has(p string) bool { return slices.Contains(c.Principals, p) }

// ErrUnauthenticated is every verification failure, as the client sees it; the wrapped reason is for
// the server's log only.
var ErrUnauthenticated = errors.New("unauthenticated")

// Verifier checks tokens of every configured issuer. Issuers are discovered lazily and retried, so the
// server may start before its identity provider does.
type Verifier struct {
	issuers map[string]*issuer
	// Now is the clock (tests move it).
	Now func() time.Time
}

type issuer struct {
	cfg        config.Issuer
	mu         sync.Mutex
	verifier   *oidc.IDTokenVerifier
	failedAt   time.Time // the last failed discovery: retried after retryAfter, not on every request
	lastFailed error
}

// discoveryTimeout bounds one discovery (the lock is held across it); retryAfter spaces the retries
// after a failure, so tokens naming an unreachable issuer do not each trigger an outbound request.
const (
	discoveryTimeout = 10 * time.Second
	retryAfter       = 5 * time.Second
)

// NewVerifier prepares (without contacting them) the issuers of cfg.
func NewVerifier(cfg []config.Issuer) *Verifier {
	v := &Verifier{issuers: map[string]*issuer{}, Now: time.Now}
	for _, is := range cfg {
		v.issuers[config.IssuerKey(is.Issuer)] = &issuer{cfg: is}
	}
	return v
}

func (is *issuer) get(ctx context.Context, now func() time.Time) (*oidc.IDTokenVerifier, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	if is.verifier != nil {
		return is.verifier, nil
	}
	if is.lastFailed != nil && now().Sub(is.failedAt) < retryAfter {
		return nil, is.lastFailed
	}
	// bounded, and not the request's context: one caller's deadline must not fail the discovery for
	// everyone, and a hung IdP must not hold the lock for long
	discoverCtx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()
	discoverCtx = oidc.ClientContext(discoverCtx, &http.Client{Timeout: discoveryTimeout})
	provider, err := oidc.NewProvider(discoverCtx, is.cfg.Issuer) // discovery + the RFC 8414 issuer check
	if err != nil {
		is.failedAt, is.lastFailed = now(), fmt.Errorf("issuer %s not reachable yet: %w", is.cfg.Issuer, err)
		return nil, is.lastFailed
	}
	// the JWKS is fetched later, by Verify, under the same bounded client (go-oidc keeps the client
	// of this context, not its deadline)
	is.verifier = provider.Verifier(&oidc.Config{
		// the audience is checked below against the configured one: go-oidc's ClientID check is the
		// same test, but an access token's aud is not a client id, so it is done explicitly
		SkipClientIDCheck:    true,
		SupportedSigningAlgs: is.cfg.Algorithms,
		Now:                  now,
	})
	return is.verifier, nil
}

// Verify checks a raw bearer token and returns its caller. Every failure wraps ErrUnauthenticated.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Caller, error) {
	iss, err := unverifiedIssuer(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	is, ok := v.issuers[config.IssuerKey(iss)]
	if !ok {
		return nil, fmt.Errorf("%w: issuer %q is not configured", ErrUnauthenticated, iss)
	}
	verifier, err := is.get(ctx, v.Now)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	token, err := verifier.Verify(ctx, raw) // signature, iss, exp, the configured algorithms
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	if !slices.Contains(token.Audience, is.cfg.Audience) {
		return nil, fmt.Errorf("%w: aud %v does not contain %q", ErrUnauthenticated, token.Audience, is.cfg.Audience)
	}
	var claims map[string]any
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrUnauthenticated, err)
	}
	if token.Subject == "" {
		return nil, fmt.Errorf("%w: no sub", ErrUnauthenticated)
	}
	return callerFrom(is.cfg, token.Issuer, token.Subject, token.Expiry, claims), nil
}

// callerFrom maps claims to principals: identity is iss+sub, never an email or a username. A service
// is recognised only by the issuer's configured rule: no claim marks one by convention.
func callerFrom(cfg config.Issuer, iss, sub string, exp time.Time, claims map[string]any) *Caller {
	c := &Caller{Issuer: iss, Subject: sub, ExpiresAt: exp}
	c.Principals = append(c.Principals, "subject:"+iss+"|"+sub)
	for _, r := range stringsAt(claims, cfg.RolesClaim) {
		c.Principals = append(c.Principals, "role:"+r)
	}
	for _, g := range stringsAt(claims, cfg.GroupsClaim) {
		c.Principals = append(c.Principals, "group:"+strings.TrimPrefix(g, "/")) // Keycloak's groups are paths
	}
	if rule := cfg.Service; rule != nil {
		marker, present := claims[rule.Claim]
		matches := present && (rule.Equals == "" || marker == rule.Equals)
		if client := firstString(claims, rule.ClientClaim); matches && client != "" {
			c.Service = true
			c.Principals = append(c.Principals, "client:"+client)
		}
	}
	return c
}

func firstString(claims map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := claims[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// stringsAt reads a dotted path (realm_access.roles, resource_access.duckdb.roles, groups) as a list
// of strings; anything of another shape is nothing.
func stringsAt(claims map[string]any, dotted string) []string {
	if dotted == "" {
		return nil
	}
	var node any = claims
	for _, part := range strings.Split(dotted, ".") {
		m, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		node = m[part]
	}
	list, ok := node.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range list {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// unverifiedIssuer reads iss from a JWT's payload only to choose the verifier; nothing else of an
// unverified token is used.
func unverifiedIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("malformed payload")
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Iss == "" {
		return "", errors.New("no iss")
	}
	return claims.Iss, nil
}
