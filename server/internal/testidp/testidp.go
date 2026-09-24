// Package testidp is an in-process OIDC issuer for the server's tests: discovery, a JWKS, and tokens
// signed with its key (or with anything else a test needs to see refused).
package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// IdP serves an issuer at URL; Issuer is its identifier (URL, or URL + "/" for NewSlashed).
type IdP struct {
	URL    string
	Issuer string
	Key    *rsa.PrivateKey
	server *httptest.Server
	t      *testing.T

	// the token endpoint (specs/010): RFC 8693 exchange and refresh, for ExchangeClient/ExchangeSecret
	mu        sync.Mutex
	refreshes map[string]Claims // refresh token -> the claims its tokens carry
	Exchanges int               // exchanges answered
	Refreshed int               // refreshes answered
	LastForm  url.Values        // the last token request (tests read the parameters)
}

// The service's exchange client at this IdP (specs/010).
const (
	ExchangeClient = "duckdb-secrets"
	ExchangeSecret = "svc-secret"
)

// New starts an issuer; it stops with the test.
func New(t *testing.T) *IdP { return start(t, "") }

// NewSlashed starts an issuer whose identifier ends in '/' (Auth0, Entra v1).
func NewSlashed(t *testing.T) *IdP { return start(t, "/") }

func start(t *testing.T, suffix string) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &IdP{Key: key, t: t, refreshes: map[string]Claims{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.Issuer,
			"jwks_uri":                              idp.URL + "/jwks",
			"authorization_endpoint":                idp.URL + "/authorize",
			"token_endpoint":                        idp.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", idp.token)
	idp.server = httptest.NewServer(mux)
	idp.URL = idp.server.URL
	idp.Issuer = idp.URL + suffix
	t.Cleanup(idp.server.Close)
	return idp
}

// Claims are a token's claims; Token fills iss/iat/exp when absent.
type Claims map[string]any

// Token signs claims with the issuer's key (RS256, kid k1).
func (idp *IdP) Token(t *testing.T, claims Claims) string {
	t.Helper()
	return Sign(t, idp.Key, "k1", jose.RS256, idp.fill(claims))
}

func (idp *IdP) fill(claims Claims) Claims {
	out := Claims{"iss": idp.Issuer, "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
	for k, v := range claims {
		out[k] = v
	}
	return out
}

// Person is alice with Keycloak-shaped realm roles, for the audience given.
func (idp *IdP) Person(t *testing.T, audience string, roles ...string) string {
	t.Helper()
	anyRoles := make([]any, len(roles))
	for i, r := range roles {
		anyRoles[i] = r
	}
	return idp.Token(t, Claims{"sub": "alice-id", "aud": []string{audience, "account"}, "azp": "duckdb",
		"realm_access": map[string]any{"roles": anyRoles}, "preferred_username": "alice"})
}

// Service is a Keycloak service-account token of client `client`.
func (idp *IdP) Service(t *testing.T, audience, client string, roles ...string) string {
	t.Helper()
	anyRoles := make([]any, len(roles))
	for i, r := range roles {
		anyRoles[i] = r
	}
	return idp.Token(t, Claims{"sub": "sa-" + client, "aud": audience, "azp": client, "client_id": client,
		"realm_access": map[string]any{"roles": anyRoles}})
}

// Sign signs claims with any key and algorithm - the refusal tests' tool.
func Sign(t *testing.T, key any, kid string, alg jose.SignatureAlgorithm, claims Claims) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(map[string]any(claims)).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// token answers the service's exchanges and refreshes: the minted token keeps the subject's sub and roles,
// with aud = the requested audience; a refresh token is issued when asked for. "dead-refresh" and a subject
// token "refused" are the IdP's refusals.
func (idp *IdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	deny := func(code, desc string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.LastForm = r.PostForm
	if r.PostForm.Get("client_id") != ExchangeClient || r.PostForm.Get("client_secret") != ExchangeSecret {
		deny("invalid_client", "bad client")
		return
	}
	var claims Claims
	withRefresh := false
	switch r.PostForm.Get("grant_type") {
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		subject := r.PostForm.Get("subject_token")
		payload, ok := unverifiedClaims(subject)
		if !ok || subject == "refused" {
			deny("invalid_grant", "the subject token "+subject+" is not valid")
			return
		}
		aud := r.PostForm.Get("audience")
		if aud == "ignored-api" { // an IdP that ignores the audience asked for
			aud = "somewhere-else"
		}
		claims = Claims{"sub": payload["sub"], "aud": aud, "azp": ExchangeClient,
			"realm_access": payload["realm_access"]}
		withRefresh = r.PostForm.Get("requested_token_type") == "urn:ietf:params:oauth:token-type:refresh_token"
		idp.Exchanges++
	case "refresh_token":
		stored, ok := idp.refreshes[r.PostForm.Get("refresh_token")]
		if !ok {
			deny("invalid_grant", "refresh token not active")
			return
		}
		claims, withRefresh = stored, true
		idp.Refreshed++
	default:
		deny("unsupported_grant_type", "")
		return
	}
	answer := map[string]any{"access_token": idp.Token(idp.t, claims), "token_type": "Bearer", "expires_in": 300,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token"}
	if withRefresh {
		refresh := fmt.Sprintf("rt-%d-%d", time.Now().UnixNano(), len(idp.refreshes))
		idp.refreshes[refresh] = claims
		answer["refresh_token"] = refresh
		answer["issued_token_type"] = "urn:ietf:params:oauth:token-type:refresh_token"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(answer)
}

// Kill ends every refresh token: the users' IdP sessions are over.
func (idp *IdP) Kill() {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.refreshes = map[string]Claims{}
}

func unverifiedClaims(raw string) (map[string]any, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var out map[string]any
	return out, json.Unmarshal(data, &out) == nil
}
