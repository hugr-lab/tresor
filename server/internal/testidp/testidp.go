// Package testidp is an in-process OIDC issuer for the server's tests: discovery, a JWKS, and tokens
// signed with its key (or with anything else a test needs to see refused).
package testidp

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// IdP serves an issuer at URL.
type IdP struct {
	URL    string
	Key    *rsa.PrivateKey
	server *httptest.Server
}

// New starts an issuer; it stops with the test.
func New(t *testing.T) *IdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &IdP{Key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.URL,
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
	idp.server = httptest.NewServer(mux)
	idp.URL = idp.server.URL
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
	out := Claims{"iss": idp.URL, "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
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
