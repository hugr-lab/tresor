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
)

// tokenParam is where a minted token goes, per secret type; a type not listed cannot be minted.
var tokenParam = map[string]string{"http": "bearer_token", "quack": "token"}

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

// validMinted checks a token_exchange secret at PUT: a known type, an audience, no token of its own.
func validMinted(typ string, params map[string]json.RawMessage) error {
	param, ok := tokenParam[strings.ToLower(typ)]
	if !ok {
		return fmt.Errorf("a %s secret has no token parameter to mint (http, quack)", tokenExchangeProvider)
	}
	if audience, _ := mintTarget(params); audience == "" {
		return fmt.Errorf("a %s secret names its audience (a string parameter)", tokenExchangeProvider)
	}
	if _, has := params[param]; has {
		return fmt.Errorf("a %s secret stores no %s: the service mints it", tokenExchangeProvider, param)
	}
	return nil
}

// mintKey identifies a minted token: the audience and the scope.
func mintKey(audience, scope string) string { return audience + "\x00" + scope }

// grantTokens are a grant's minted tokens (in memory only, with the grant): the user's, per audience.
type grantTokens struct {
	mu     sync.Mutex
	tokens map[string]*mint.Token
	failed map[string]string // audience -> why the grant's exchange for it failed (never a token)
}

// direct caches the tokens minted for callers reading directly, until shortly before they expire.
type directCache struct {
	mu     sync.Mutex
	tokens map[string]*mint.Token // caller owner \x00 secret \x00 version -> token
}

func (s *Server) mintClient(ctx context.Context, issuer string) (*mint.Client, error) {
	var ex *config.ExchangeClient
	for i := range s.cfg.Issuers {
		if config.IssuerKey(s.cfg.Issuers[i].Issuer) == config.IssuerKey(issuer) {
			ex = s.cfg.Issuers[i].Exchange
		}
	}
	if ex == nil {
		return nil, errors.New("this service cannot mint tokens for the caller's issuer (no exchange client)")
	}
	url, err := s.verifier.TokenURL(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return &mint.Client{TokenURL: url, ClientID: ex.ClientID, ClientSecret: ex.ClientSecret, Now: s.now}, nil
}

// mintAtGrant: at a grant's exchange, the user's token is exchanged - with a refresh token - for every
// audience the actor may mint; the results stay with the grant.
func (s *Server) mintAtGrant(ctx context.Context, gr *grant, subject string, actor *auth.Caller) {
	gr.minted = &grantTokens{tokens: map[string]*mint.Token{}, failed: map[string]string{}}
	var client *mint.Client
	for _, sec := range s.store.List() {
		if !isMinted(sec) || !slices.Contains(s.actorVerbs(actor.Client(), actor.Issuer), "use") ||
			!usable(sec, actor.Principals) {
			continue
		}
		audience, scope := mintTarget(sec.Params)
		key := mintKey(audience, scope)
		if _, done := gr.minted.tokens[key]; done {
			continue
		}
		if client == nil {
			var err error
			if client, err = s.mintClient(ctx, gr.user.Issuer); err != nil {
				gr.minted.failed[key] = err.Error()
				continue
			}
		}
		token, err := client.Exchange(ctx, subject, audience, scope, true)
		if err != nil {
			s.log.Warn("minting at a grant failed", "actor", actor.Client(), "user", gr.user.Owner(),
				"audience", audience, "reason", err.Error())
			gr.minted.failed[key] = err.Error()
			continue
		}
		gr.minted.tokens[key] = token
	}
}

// mintedToken is the token a minted secret's material carries for this request's caller; an error is the
// problem to answer (status, type, detail).
func (s *Server) mintedToken(r *http.Request, c *auth.Caller, sec *store.Secret) (*mint.Token, int, string, string) {
	audience, scope := mintTarget(sec.Params)
	key := mintKey(audience, scope)
	now := s.now()
	if gr := grantOf(r); gr != nil {
		// under a grant: the grant's user's token - minted at the exchange, renewed from its refresh token
		if gr.minted == nil {
			return nil, http.StatusForbidden, "no_verb", "this grant carries no minted tokens"
		}
		gr.minted.mu.Lock()
		defer gr.minted.mu.Unlock()
		token := gr.minted.tokens[key]
		if token == nil {
			if why, failed := gr.minted.failed[key]; failed {
				return nil, http.StatusForbidden, "no_verb", "minting for the user failed at the grant: " + why
			}
			return nil, http.StatusForbidden, "no_verb", "the grant predates this secret: a new session picks it up"
		}
		if token.Expiry.IsZero() || token.Expiry.Sub(now) > mintMargin {
			return token, 0, "", ""
		}
		if token.Refresh == "" {
			return nil, http.StatusForbidden, "no_verb", "the user's token expired and cannot be renewed"
		}
		client, err := s.mintClient(r.Context(), gr.user.Issuer)
		if err == nil {
			var fresh *mint.Token
			if fresh, err = client.Refresh(r.Context(), token.Refresh); err == nil {
				gr.minted.tokens[key] = fresh
				return fresh, 0, "", ""
			}
		}
		if mint.IsInvalidGrant(err) {
			delete(gr.minted.tokens, key)
			return nil, http.StatusForbidden, "no_verb", "the user's session at the identity provider has ended"
		}
		s.log.Warn("renewing a minted token failed", "user", gr.user.Owner(), "audience", audience, "reason", err.Error())
		return nil, http.StatusServiceUnavailable, "service_unavailable", "the identity provider did not renew the token"
	}
	// directly: the caller's own token, exchanged on demand; cached until shortly before it expires
	cacheKey := c.Owner() + "\x00" + sec.Name + "\x00" + fmt.Sprint(sec.Version)
	s.direct.mu.Lock()
	if token := s.direct.tokens[cacheKey]; token != nil && (token.Expiry.IsZero() || token.Expiry.Sub(now) > mintMargin) {
		s.direct.mu.Unlock()
		return token, 0, "", ""
	}
	s.direct.mu.Unlock()
	client, err := s.mintClient(r.Context(), c.Issuer)
	if err != nil {
		return nil, http.StatusUnprocessableEntity, "invalid_secret", err.Error()
	}
	token, err := client.Exchange(r.Context(), bearerOf(r), audience, scope, false)
	if err != nil {
		s.log.Warn("minting for the caller failed", "caller", c.Owner(), "audience", audience, "reason", err.Error())
		return nil, http.StatusForbidden, "no_verb", "the identity provider refused to mint a token for the caller: " +
			err.Error()
	}
	s.direct.mu.Lock()
	if s.direct.tokens == nil {
		s.direct.tokens = map[string]*mint.Token{}
	}
	for k, t := range s.direct.tokens { // expired entries go: a bounded cache
		if !t.Expiry.IsZero() && !t.Expiry.After(now) {
			delete(s.direct.tokens, k)
		}
	}
	s.direct.tokens[cacheKey] = token
	s.direct.mu.Unlock()
	return token, 0, "", ""
}

// bearerOf is the raw bearer token of the request (verified already by authed).
func bearerOf(r *http.Request) string {
	_, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	return strings.TrimSpace(raw)
}
