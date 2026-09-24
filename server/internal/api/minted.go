package api

// Secrets minted for the caller (specs/010): `provider: token_exchange`, an `audience` (and a `scope`); the
// material is a token for the caller at the identity provider - the caller's own when it reads directly, the
// grant's user's under a delegation grant (never the server's). Tokens are never logged nor put in an error.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hugr-lab/tresor/server/internal/auth"
	"github.com/hugr-lab/tresor/server/internal/config"
	"github.com/hugr-lab/tresor/server/internal/mint"
	"github.com/hugr-lab/tresor/server/internal/store"
)

const (
	tokenExchangeProvider = "token_exchange"
	mintMargin            = 30 * time.Second // a minted token is renewed this long before it expires
	mintNoExpiry          = 60 * time.Second // a minted token the IdP gave no expiry is reused this long
	grantMintDeadline     = 10 * time.Second // all of a grant's exchanges, together
	refreshTimeout        = 15 * time.Second
)

// tokenParam is where a minted token goes, per secret type; a type not listed cannot be minted.
var tokenParam = map[string]string{"http": "bearer_token", "quack": "token"}

var errNoExchange = errors.New("this service cannot mint tokens for the caller's issuer (no exchange client)")

func isMinted(sec *store.Secret) bool { return sec.Provider == tokenExchangeProvider }

// mintTarget is a minted secret's audience and scope, from its params.
func mintTarget(params map[string]json.RawMessage) (audience, scope string) {
	str := func(key string) string {
		var v string
		if raw, ok := params[key]; ok {
			_ = json.Unmarshal(raw, &v)
		}
		return v
	}
	return str("audience"), str("scope")
}

// validMinted checks a token_exchange secret at PUT: a known type, a text audience that is not this
// service's own, a text scope if any, and no token of its own.
func (s *Server) validMinted(typ string, params map[string]json.RawMessage) error {
	param, ok := tokenParam[strings.ToLower(typ)]
	if !ok {
		return fmt.Errorf("a %s secret has no token parameter to mint (http, quack)", tokenExchangeProvider)
	}
	audience, scope := mintTarget(params)
	if audience == "" {
		return fmt.Errorf("a %s secret names its audience (a string parameter)", tokenExchangeProvider)
	}
	if raw, has := params["scope"]; has && scope == "" && string(raw) != `""` {
		return fmt.Errorf("a %s secret's scope is a string", tokenExchangeProvider)
	}
	for _, is := range s.cfg.Issuers {
		if audience == is.Audience {
			// a user's token for this service, in a secret sent to another server, could be replayed here
			return fmt.Errorf("a %s secret's audience is another service's, never this one's", tokenExchangeProvider)
		}
	}
	for key := range params {
		if strings.EqualFold(key, param) {
			return fmt.Errorf("a %s secret stores no %s: the service mints it", tokenExchangeProvider, param)
		}
	}
	return nil
}

// mintKey identifies a minted token: the audience and the scope - all a token depends on.
func mintKey(audience, scope string) string { return audience + "\x00" + scope }

// mintEntry is one audience's token under a grant; its own lock serialises that audience's mints and
// refreshes (refresh tokens rotate) without holding up the grant's other audiences.
type mintEntry struct {
	mu     sync.Mutex
	token  *mint.Token
	failed string // why minting for the user failed for good (the IdP refused), never a token
}

// grantTokens are a grant's minted tokens (in memory only, with the grant): the user's, per audience. The
// grant's subject token is kept until it expires: a secret the IdP could not mint at the exchange (an outage)
// or one granted to the server since is minted from it lazily, while it lives.
type grantTokens struct {
	mu         sync.Mutex
	entries    map[string]*mintEntry
	subject    string
	subjectExp time.Time
}

func (g *grantTokens) entry(key string) *mintEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entries[key]
	if e == nil {
		e = &mintEntry{}
		g.entries[key] = e
	}
	return e
}

// liveSubject is the grant's subject token while it lives; an expired one is dropped.
func (g *grantTokens) liveSubject(now time.Time) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.subject != "" && now.Before(g.subjectExp) {
		return g.subject
	}
	g.subject = ""
	return ""
}

// directCache caches the tokens minted for callers reading directly, until shortly before they expire.
type directCache struct {
	mu     sync.Mutex
	tokens map[string]*mint.Token // caller owner \x00 audience \x00 scope -> token
}

// mintProblem is a minted secret's refusal: status, type and a detail with no token in it.
type mintProblem struct {
	status       int
	kind, detail string
}

func refusedMint(detail string) *mintProblem {
	return &mintProblem{http.StatusForbidden, "mint_refused", detail}
}

func unavailableMint(detail string) *mintProblem {
	return &mintProblem{http.StatusServiceUnavailable, "service_unavailable", detail}
}

func (s *Server) mintClient(ctx context.Context, issuer string) (*mint.Client, *mintProblem) {
	var ex *config.ExchangeClient
	for i := range s.cfg.Issuers {
		if config.IssuerKey(s.cfg.Issuers[i].Issuer) == config.IssuerKey(issuer) {
			ex = s.cfg.Issuers[i].Exchange
		}
	}
	if ex == nil {
		return nil, &mintProblem{http.StatusUnprocessableEntity, "invalid_secret", errNoExchange.Error()}
	}
	tokenURL, err := s.verifier.TokenURL(ctx, issuer)
	if err != nil {
		return nil, unavailableMint("the identity provider's token endpoint is not known yet")
	}
	// the client secret goes there: https, or http only to this machine (as the issuers themselves)
	if u, err := url.Parse(tokenURL); err != nil ||
		!(u.Scheme == "https" || (u.Scheme == "http" && config.IsLoopback(u.Hostname()))) {
		return nil, unavailableMint("the identity provider's token endpoint is not https")
	}
	return &mint.Client{TokenURL: tokenURL, ClientID: ex.ClientID, ClientSecret: ex.ClientSecret, Now: s.now}, nil
}

// checkMinted refuses a token not meant for the audience asked, or meant for this service itself: an IdP
// that ignored the audience must not have a token for the service end up in a secret sent elsewhere.
func (s *Server) checkMinted(token *mint.Token, audience string) error {
	auds, isJWT := mint.Audiences(token.Access)
	if !isJWT {
		return nil // an opaque token: its audience is the IdP's word
	}
	if !slices.Contains(auds, audience) {
		return errors.New("the identity provider minted a token not meant for " + audience)
	}
	for _, is := range s.cfg.Issuers {
		if slices.Contains(auds, is.Audience) {
			return errors.New("the identity provider minted a token meant for this service")
		}
	}
	return nil
}

// mintAtGrant: at a grant's exchange, the user's token is exchanged - with a refresh token - for every
// audience the actor may mint, concurrently and under one deadline; the results stay with the grant. The
// subject token is kept until it expires, for what could not be minted now.
func (s *Server) mintAtGrant(ctx context.Context, gr *grant, subject string, actor *auth.Caller) {
	gr.minted = &grantTokens{entries: map[string]*mintEntry{}, subject: subject, subjectExp: gr.user.ExpiresAt}
	if !slices.Contains(s.actorVerbs(actor.Client(), actor.Issuer), "use") {
		return
	}
	targets := map[string][2]string{}
	for _, sec := range s.store.List() {
		if isMinted(sec) && usable(sec, actor.Principals) {
			audience, scope := mintTarget(sec.Params)
			targets[mintKey(audience, scope)] = [2]string{audience, scope}
		}
	}
	if len(targets) == 0 {
		return
	}
	client, problem := s.mintClient(ctx, gr.user.Issuer)
	if problem != nil {
		return // minted lazily from the subject token, or refused at the read with the reason
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), grantMintDeadline)
	defer cancel()
	var wg sync.WaitGroup
	for key, target := range targets {
		entry := gr.minted.entry(key)
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := client.Exchange(ctx, subject, target[0], target[1], true)
			if err == nil {
				err = s.checkMinted(token, target[0])
			}
			entry.mu.Lock()
			defer entry.mu.Unlock()
			switch {
			case err == nil:
				entry.token = token
			case isRefusal(err):
				entry.failed = err.Error() // the IdP's word, redacted; lazily retried only for outages
				fallthrough
			default:
				s.log.Warn("minting at a grant failed", "actor", actor.Client(), "user", gr.user.Owner(),
					"audience", target[0], "reason", err.Error())
			}
		}()
	}
	wg.Wait()
}

// isRefusal: the IdP answered no (a lasting refusal), as opposed to not answering (an outage).
func isRefusal(err error) bool {
	var e *mint.Error
	return errors.As(err, &e) && !e.Transient()
}

// mintedToken is the token a minted secret's material carries for this request's caller, or the problem.
func (s *Server) mintedToken(r *http.Request, c *auth.Caller, sec *store.Secret) (*mint.Token, *mintProblem) {
	audience, scope := mintTarget(sec.Params)
	key := mintKey(audience, scope)
	now := s.now()
	fresh := func(t *mint.Token) bool { return t != nil && t.Expiry.Sub(now) > mintMargin }
	if gr := grantOf(r); gr != nil {
		return s.mintedForGrant(r, gr, key, audience, scope, fresh)
	}
	// directly: the caller's own token, exchanged on demand; cached per caller and audience until shortly
	// before it expires
	cacheKey := c.Owner() + "\x00" + key
	s.direct.mu.Lock()
	if token := s.direct.tokens[cacheKey]; fresh(token) {
		s.direct.mu.Unlock()
		return token, nil
	}
	s.direct.mu.Unlock()
	client, problem := s.mintClient(r.Context(), c.Issuer)
	if problem != nil {
		return nil, problem
	}
	token, err := client.Exchange(r.Context(), bearerOf(r), audience, scope, false)
	if err == nil {
		err = s.checkMinted(token, audience)
	}
	if err != nil {
		s.log.Warn("minting for the caller failed", "caller", c.Owner(), "audience", audience, "reason", err.Error())
		if isRefusal(err) || strings.Contains(err.Error(), "minted a token") {
			return nil, refusedMint("the identity provider refused to mint a token for the caller: " + err.Error())
		}
		return nil, unavailableMint("the identity provider did not answer")
	}
	if token.Expiry.IsZero() {
		token.Expiry = now.Add(mintNoExpiry)
	}
	s.direct.mu.Lock()
	if s.direct.tokens == nil {
		s.direct.tokens = map[string]*mint.Token{}
	}
	for k, t := range s.direct.tokens { // expired entries go: a bounded cache
		if !t.Expiry.After(now) {
			delete(s.direct.tokens, k)
		}
	}
	s.direct.tokens[cacheKey] = token
	s.direct.mu.Unlock()
	return token, nil
}

// mintedForGrant: under a grant, the grant's user's token - minted at the exchange (or lazily from the
// subject token while it lives), renewed from its refresh token.
func (s *Server) mintedForGrant(r *http.Request, gr *grant, key, audience, scope string,
	fresh func(*mint.Token) bool) (*mint.Token, *mintProblem) {
	if gr.minted == nil {
		return nil, refusedMint("this grant carries no minted tokens")
	}
	entry := gr.minted.entry(key)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if fresh(entry.token) || (entry.token != nil && entry.token.Expiry.IsZero()) {
		return entry.token, nil
	}
	client, problem := s.mintClient(r.Context(), gr.user.Issuer)
	if problem != nil {
		return nil, problem
	}
	// detached from the request: a refresh token the IdP rotated must not be lost with a dropped connection
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), refreshTimeout)
	defer cancel()
	if entry.token != nil && entry.token.Refresh != "" {
		renewed, err := client.Refresh(ctx, entry.token.Refresh)
		if err == nil {
			if err = s.checkMinted(renewed, audience); err == nil {
				entry.token = renewed
				return renewed, nil
			}
		}
		if mint.IsInvalidGrant(err) {
			entry.token = nil
			entry.failed = "the user's session at the identity provider has ended"
			return nil, refusedMint(entry.failed)
		}
		s.log.Warn("renewing a minted token failed", "user", gr.user.Owner(), "audience", audience, "reason", err.Error())
		if !isRefusal(err) {
			return nil, unavailableMint("the identity provider did not renew the token")
		}
		entry.token, entry.failed = nil, err.Error()
		return nil, refusedMint("renewing the user's token was refused: " + err.Error())
	}
	if entry.failed != "" {
		return nil, refusedMint("minting for the user was refused: " + entry.failed)
	}
	// nothing minted yet (an outage at the exchange, or a secret granted to the server since): from the
	// subject token, while it lives
	subject := gr.minted.liveSubject(s.now())
	if subject == "" {
		return nil, refusedMint("the grant's user token has expired: a new session mints it")
	}
	token, err := client.Exchange(ctx, subject, audience, scope, true)
	if err == nil {
		err = s.checkMinted(token, audience)
	}
	if err != nil {
		s.log.Warn("minting for the grant's user failed", "user", gr.user.Owner(), "audience", audience,
			"reason", err.Error())
		if isRefusal(err) || strings.Contains(err.Error(), "minted a token") {
			entry.failed = err.Error()
			return nil, refusedMint("minting for the user was refused: " + err.Error())
		}
		return nil, unavailableMint("the identity provider did not answer")
	}
	entry.token = token
	return token, nil
}

// bearerOf is the raw bearer token of the request (verified already by authed).
func bearerOf(r *http.Request) string {
	_, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	return strings.TrimSpace(raw)
}
