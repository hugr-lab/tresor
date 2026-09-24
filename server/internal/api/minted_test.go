package api

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const mintedSecret = `{"type":"http","provider":"token_exchange","scope":["https://echo.example"],
  "params":{"audience":"echo-api","extra_http_headers":{"type":"MAP(VARCHAR, VARCHAR)","value":{"X-From":"tresor"}}},
  "redact_keys":[]}`

// claimsOf reads a minted token's payload (the test IdP signed it; only its claims matter here).
func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	data, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}

func (f *fixture) mintedMaterial(token string, headers ...string) (string, map[string]any, reply) {
	f.t.Helper()
	r := f.do("GET", "/v1/secrets/echo", token, "", headers...)
	if r.status != 200 {
		return "", nil, r
	}
	body := r.json(f.t)
	bearer, _ := body["params"].(map[string]any)["bearer_token"].(string)
	return bearer, body, r
}

func TestMintedValidation(t *testing.T) {
	f := newFixture(t, "")
	for name, body := range map[string]string{
		"a type with no token": `{"type":"s3","provider":"token_exchange","params":{"audience":"x"}}`,
		"no audience":          `{"type":"http","provider":"token_exchange","params":{}}`,
		"a token of its own":   `{"type":"http","provider":"token_exchange","params":{"audience":"x","bearer_token":"t"}}`,
		"quack with its token": `{"type":"quack","provider":"token_exchange","params":{"audience":"x","token":"t"}}`,
		"an audience not text": `{"type":"http","provider":"token_exchange","params":{"audience":{"type":"INTEGER","value":1}}}`,
		"this service's own":   `{"type":"http","provider":"token_exchange","params":{"audience":"duckdb-secrets"}}`,
		"a scope not text":     `{"type":"http","provider":"token_exchange","params":{"audience":"x","scope":{"type":"INTEGER","value":1}}}`,
		"its token, any case":  `{"type":"http","provider":"token_exchange","params":{"audience":"x","BEARER_TOKEN":"t"}}`,
	} {
		if r := f.do("PUT", "/v1/secrets/m", f.admin, body); r.status != 422 {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	r := f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	if r.status != 201 || r.json(t)["dynamic"] != true {
		t.Fatalf("a minted secret is dynamic: %d %s", r.status, r.body)
	}
}

// a user reading directly gets a token of their own for the audience, minted on demand and cached
func TestMintedDirect(t *testing.T) {
	f := newFixture(t, "")
	f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	bearer, body, r := f.mintedMaterial(f.alice)
	if bearer == "" {
		t.Fatalf("material: %d %s", r.status, r.body)
	}
	if c := claimsOf(t, bearer); c["sub"] != "alice-id" || c["aud"] != "echo-api" {
		t.Fatalf("the token is alice's, for echo-api: %v", c)
	}
	if !strings.Contains(string(r.body), `"X-From"`) || !strings.Contains(string(r.body), `"bearer_token"`) {
		t.Fatalf("the other params pass through, the token is redacted: %s", r.body)
	}
	if redact := body["redact_keys"].([]any); len(redact) != 1 || redact[0] != "bearer_token" {
		t.Fatalf("redact_keys: %v", redact)
	}
	if expires, err := time.Parse(time.RFC3339, body["expires_at"].(string)); err != nil || time.Until(expires) > 6*time.Minute {
		t.Fatalf("expires_at: %v", body["expires_at"])
	}
	f.idp.LastForm = nil
	if again, _, _ := f.mintedMaterial(f.alice); again != bearer || f.idp.Exchanges != 1 {
		t.Fatalf("cached until it nears its expiry: %d exchanges", f.idp.Exchanges)
	}
	if strings.Contains(f.logs.String(), bearer) || strings.Contains(f.logs.String(), f.alice) {
		t.Fatal("a token reached the log")
	}
}

// under a delegation grant the token is the grant's user's - minted at the exchange with a refresh token,
// renewed from it - never the server's
func TestMintedUnderGrant(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/echo/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	g, r := f.grantFor(node, f.alice)
	if g == "" {
		t.Fatalf("exchange: %d %s", r.status, r.body)
	}
	if f.idp.Exchanges != 1 || f.idp.LastForm.Get("requested_token_type") != "urn:ietf:params:oauth:token-type:refresh_token" {
		t.Fatalf("the grant's exchange asks for a refresh token: %d %v", f.idp.Exchanges, f.idp.LastForm)
	}
	bearer, _, r := f.mintedMaterial(node, "Delegation", g)
	if bearer == "" {
		t.Fatalf("under the grant: %d %s", r.status, r.body)
	}
	if c := claimsOf(t, bearer); c["sub"] != "alice-id" || c["aud"] != "echo-api" {
		t.Fatalf("the grant's user's token, never the node's: %v", c)
	}
	// the node itself holds use too, and reads it as itself: its own token
	own, _, _ := f.mintedMaterial(node)
	if c := claimsOf(t, own); c["sub"] != "sa-node" {
		t.Fatalf("the node as itself: %v", c)
	}
	// near its expiry the user's token is renewed from the refresh token
	f.srv.now = func() time.Time { return time.Now().Add(290 * time.Second) }
	renewed, _, r := f.mintedMaterial(node, "Delegation", g)
	if renewed == "" || f.idp.Refreshed != 1 || claimsOf(t, renewed)["sub"] != "alice-id" {
		t.Fatalf("renewed: %d %s (refreshes %d)", r.status, r.body, f.idp.Refreshed)
	}
	// the user's IdP session ends: nothing more is minted for her
	f.idp.Kill()
	f.srv.now = func() time.Time { return time.Now().Add(590 * time.Second) }
	if _, _, r := f.mintedMaterial(node, "Delegation", g); r.status != 403 || r.problemType(t) != "mint_refused" ||
		!strings.Contains(string(r.body), "session at the identity provider has ended") {
		t.Fatalf("after the IdP session: %d %s", r.status, r.body)
	}
	if _, _, r := f.mintedMaterial(node, "Delegation", g); !strings.Contains(string(r.body), "session at the identity provider has ended") {
		t.Fatalf("and it stays said: %d %s", r.status, r.body)
	}
	f.srv.now = time.Now
	// a secret the node was granted after the grant was made: minted lazily from the grant's subject token
	// while it lives (an outage at the exchange heals the same way); after it, a new session mints it
	f.do("PUT", "/v1/secrets/later", f.admin, strings.Replace(mintedSecret, "echo-api", "later-api", 1))
	f.do("PUT", "/v1/secrets/later/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	if r := f.do("GET", "/v1/secrets/later", node, "", "Delegation", g); r.status != 200 ||
		claimsOf(t, r.json(t)["params"].(map[string]any)["bearer_token"].(string))["sub"] != "alice-id" {
		t.Fatalf("a secret newer than the grant, while its subject token lives: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/later2", f.admin, strings.Replace(mintedSecret, "echo-api", "later2-api", 1))
	f.do("PUT", "/v1/secrets/later2/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	f.srv.now = func() time.Time { return time.Now().Add(6 * time.Minute) }
	if r := f.do("GET", "/v1/secrets/later2", node, "", "Delegation", g); r.status != 403 ||
		r.problemType(t) != "mint_refused" || !strings.Contains(string(r.body), "a new session mints it") {
		t.Fatalf("after the subject token: %d %s", r.status, r.body)
	}
	f.srv.now = time.Now
	// revocation drops the grant, and its tokens with it
	f.do("DELETE", "/v1/delegations/"+g, node, "")
	if r := f.do("GET", "/v1/secrets/echo", node, "", "Delegation", g); r.status != 401 {
		t.Fatalf("a revoked grant: %d", r.status)
	}
	if strings.Contains(f.logs.String(), bearer) {
		t.Fatal("a minted token reached the log")
	}
}

// the IdP refuses: the refusal names no token, and a user's own token is never quoted back
func TestMintedRefused(t *testing.T) {
	f := newFixture(t, "")
	f.do("PUT", "/v1/secrets/echo", f.admin, strings.Replace(mintedSecret, "echo-api", "refused-api", 1))
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.idp.Kill()
	// the test IdP refuses a subject token literally "refused"; here: a wrong client makes it refuse
	f.srv.cfg.Issuers[0].Exchange.ClientSecret = "wrong"
	r := f.do("GET", "/v1/secrets/echo", f.alice, "")
	if r.status != 403 || !strings.Contains(string(r.body), "invalid_client") || strings.Contains(string(r.body), f.alice) {
		t.Fatalf("refused: %d %s", r.status, r.body)
	}
}

// the direct cache is keyed by what a token depends on: a secret deleted and recreated for another audience
// never serves the old audience's token
func TestMintedRecreated(t *testing.T) {
	f := newFixture(t, "")
	f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	first, _, _ := f.mintedMaterial(f.alice)
	f.do("DELETE", "/v1/secrets/echo", f.admin, "")
	f.do("PUT", "/v1/secrets/echo", f.admin, strings.Replace(mintedSecret, "echo-api", "other-api", 1))
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	second, _, r := f.mintedMaterial(f.alice)
	if second == "" || second == first || claimsOf(t, second)["aud"] != "other-api" {
		t.Fatalf("the recreated secret's own audience: %d %s", r.status, r.body)
	}
}

// an IdP that ignores the audience: a token not meant for it is never served
func TestMintedAudienceChecked(t *testing.T) {
	f := newFixture(t, "")
	f.do("PUT", "/v1/secrets/echo", f.admin, strings.Replace(mintedSecret, "echo-api", "ignored-api", 1))
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	r := f.do("GET", "/v1/secrets/echo", f.alice, "")
	if r.status != 403 || r.problemType(t) != "mint_refused" || !strings.Contains(string(r.body), "not meant for ignored-api") {
		t.Fatalf("a token for another audience: %d %s", r.status, r.body)
	}
}

// no exchange client for the caller's issuer: a minted secret cannot be served
func TestMintedWithoutExchangeClient(t *testing.T) {
	f := newFixtureWith(t, "", false)
	f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	if r := f.do("GET", "/v1/secrets/echo", f.alice, ""); r.status != 422 || r.problemType(t) != "invalid_secret" {
		t.Fatalf("no exchange client: %d %s", r.status, r.body)
	}
}
