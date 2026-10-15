package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hugr-lab/tresor/server/internal/store"
	"github.com/hugr-lab/tresor/server/internal/testidp"
)

// specs/029: any parameter of any type may be generated per caller (mint+exchange://, mint+claim://)

func (f *fixture) genMaterial(name, token string, headers ...string) (map[string]any, map[string]any, reply) {
	f.t.Helper()
	r := f.do("GET", "/v1/secrets/"+name, token, "", headers...)
	if r.status != 200 {
		return nil, nil, r
	}
	body := r.json(f.t)
	return body["params"].(map[string]any), body, r
}

func redactKeys(body map[string]any) []string {
	var out []string
	for _, k := range body["redact_keys"].([]any) {
		out = append(out, k.(string))
	}
	return out
}

func TestGeneratorValidation(t *testing.T) {
	f := newFixture(t, "")
	for name, value := range map[string]string{
		"no kind":            "mint+nothing",
		"an unknown kind":    "mint+vault://s3cr3t-value",
		"no audience":        "mint+exchange://",
		"no audience, scope": "mint+exchange://?scope=x",
		"another query key":  "mint+exchange://api?resource=x",
		"two scopes":         "mint+exchange://api?scope=a&scope=b",
		"no claim":           "mint+claim://",
		"login (not here)":   "mint+login://x",
		"rule (not here)":    "mint+rule://x",
		"this service's own": "mint+exchange://duckdb-secrets",
		"its own, encoded":   "mint+exchange://duckdb%2Dsecrets",
		"a session claim":    "mint+claim://sid",
		"a token's id":       "mint+claim://jti",
	} {
		body := `{"type":"postgres","provider":"config","params":{"password":"` + value + `"},"redact_keys":[]}`
		r := f.do("PUT", "/v1/secrets/g", f.admin, body)
		if r.status != 422 || r.problemType(t) != "invalid_secret" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
		if strings.Contains(string(r.body), "s3cr3t-value") {
			t.Errorf("%s: the refusal quotes the value: %s", name, r.body)
		}
	}
	// only administrators write: a user's PUT is refused before any generator
	r := f.do("PUT", "/v1/secrets/g", f.alice, `{"type":"http","provider":"config","params":{"bearer_token":"mint+claim://sub"}}`)
	if r.status != 403 {
		t.Fatalf("a user writes no generator: %d %s", r.status, r.body)
	}
	// a typed value is literal, and a plain secret is not dynamic
	r = f.do("PUT", "/v1/secrets/typed", f.admin,
		`{"type":"http","provider":"config","params":{"bearer_token":{"type":"VARCHAR","value":"mint+whatever"}}}`)
	if r.status != 201 || r.json(t)["dynamic"] != false {
		t.Fatalf("a typed value is literal: %d %s", r.status, r.body)
	}
}

// the escape: a literal beginning with mint+ is stored as mint++…, served with one + dropped; not dynamic
func TestGeneratorEscape(t *testing.T) {
	f := newFixture(t, "")
	r := f.do("PUT", "/v1/secrets/lit", f.admin, `{"type":"http","provider":"config","scope":["https://lit.example"],
		"params":{"bearer_token":"mint++claim://sub","other":"mint+++x","plain":"mint"},"redact_keys":["bearer_token"]}`)
	if r.status != 201 || r.json(t)["dynamic"] != false {
		t.Fatalf("an escaped literal: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/lit/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	params, body, r := f.genMaterial("lit", f.alice)
	if params == nil {
		t.Fatalf("material: %d %s", r.status, r.body)
	}
	if params["bearer_token"] != "mint+claim://sub" || params["other"] != "mint++x" || params["plain"] != "mint" {
		t.Fatalf("one + dropped: %v", params)
	}
	if body["expires_at"] != nil || len(redactKeys(body)) != 1 {
		t.Fatalf("a static secret: %v %v", body["expires_at"], body["redact_keys"])
	}
}

// a claim of the caller's verified token - never the token - for the direct caller and under a grant (the
// grant's user's); redacted, as long as the token (the grant), the provider served as stored
func TestGeneratedClaim(t *testing.T) {
	f := newFixture(t, "")
	r := f.do("PUT", "/v1/secrets/who", f.admin, `{"type":"postgres","provider":"config","scope":["postgres://db"],
		"params":{"host":"db.example","user":"mint+claim://preferred_username","password":"mint+claim://azp"},
		"redact_keys":["password"]}`)
	if r.status != 201 || r.json(t)["dynamic"] != true || r.json(t)["provider"] != "config" {
		t.Fatalf("a claim makes it dynamic: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/who/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.do("PUT", "/v1/secrets/who/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	params, body, r := f.genMaterial("who", f.alice)
	if params == nil {
		t.Fatalf("material: %d %s", r.status, r.body)
	}
	if params["user"] != "alice" || params["password"] != "duckdb" || params["host"] != "db.example" {
		t.Fatalf("alice's claims: %v", params)
	}
	if body["provider"] != "config" || body["dynamic"] != true {
		t.Fatalf("the provider as stored: %v", body)
	}
	if keys := redactKeys(body); len(keys) != 2 || keys[0] != "password" || keys[1] != "user" {
		t.Fatalf("every generated key redacted, once: %v", keys)
	}
	if expires, err := time.Parse(time.RFC3339, body["expires_at"].(string)); err != nil || time.Until(expires) > 2*time.Hour {
		t.Fatalf("expires with the token: %v", body["expires_at"])
	}
	if strings.Contains(string(r.body), f.alice) {
		t.Fatal("the caller's token in the material")
	}
	// under a grant: the grant's user's claims, never the node's
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	g, gr := f.grantFor(node, f.alice)
	if g == "" {
		t.Fatalf("exchange: %d %s", gr.status, gr.body)
	}
	if params, _, r := f.genMaterial("who", node, "Delegation", g); params == nil || params["user"] != "alice" ||
		params["password"] != "duckdb" {
		t.Fatalf("the grant's user's claims: %d %s", r.status, r.body)
	}
	// the node as itself: its own claims
	f.do("PUT", "/v1/secrets/azp", f.admin, `{"type":"postgres","provider":"config","params":{"user":"mint+claim://azp"}}`)
	f.do("PUT", "/v1/secrets/azp/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	if params, _, r := f.genMaterial("azp", node); params["user"] != "node" {
		t.Fatalf("the node's own claims: %d %s", r.status, r.body)
	}
	// a claim the caller's token does not carry (the node has no preferred_username): refused, never empty
	if r := f.do("GET", "/v1/secrets/who", node, ""); r.status != 403 || r.problemType(t) != "mint_refused" {
		t.Fatalf("no such claim: %d %s", r.status, r.body)
	}
	// a claim that is no text (an object): refused
	f.do("PUT", "/v1/secrets/who3", f.admin, `{"type":"postgres","provider":"config","params":{"user":"mint+claim://realm_access"}}`)
	f.do("PUT", "/v1/secrets/who3/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	if r := f.do("GET", "/v1/secrets/who3", f.alice, ""); r.status != 403 || r.problemType(t) != "mint_refused" {
		t.Fatalf("an object claim: %d %s", r.status, r.body)
	}
}

// an exchange of any type, under any key: the direct caller's token, and under a grant the grant's user's
// (minted at the grant's exchange, as the alias); the provider served as stored
func TestGeneratedExchange(t *testing.T) {
	f := newFixture(t, "")
	r := f.do("PUT", "/v1/secrets/aad", f.admin, `{"type":"mssql","provider":"access_token","scope":["mssql://sql"],
		"params":{"host":"sql.example","access_token":"mint+exchange://echo-api?scope=read+write","user":"mint+claim://sub"},
		"redact_keys":[]}`)
	if r.status != 201 || r.json(t)["dynamic"] != true {
		t.Fatalf("an exchange generator: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/aad/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.do("PUT", "/v1/secrets/aad/grants/n", f.admin, `{"principal":"role:nodes","verbs":["use"]}`)
	params, body, r := f.genMaterial("aad", f.alice)
	if params == nil {
		t.Fatalf("material: %d %s", r.status, r.body)
	}
	token, _ := params["access_token"].(string)
	if c := claimsOf(t, token); c["sub"] != "alice-id" || c["aud"] != "echo-api" {
		t.Fatalf("alice's token for echo-api: %v", c)
	}
	if f.idp.LastForm.Get("scope") != "read write" || f.idp.LastForm.Get("audience") != "echo-api" {
		t.Fatalf("the audience and scope asked: %v", f.idp.LastForm)
	}
	if body["provider"] != "access_token" || params["user"] != "alice-id" {
		t.Fatalf("the provider as stored, the claim beside it: %v %v", body["provider"], params)
	}
	if keys := redactKeys(body); len(keys) != 2 {
		t.Fatalf("both generated keys redacted: %v", keys)
	}
	// the earliest expiry: the minted token's (300 s), before the caller's token's
	if expires, err := time.Parse(time.RFC3339, body["expires_at"].(string)); err != nil || time.Until(expires) > 6*time.Minute {
		t.Fatalf("expires_at: %v", body["expires_at"])
	}
	// under a grant: minted at the exchange for the grant's user
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	before := f.idp.Exchanges
	g, gr := f.grantFor(node, f.alice)
	if g == "" || f.idp.Exchanges != before+1 {
		t.Fatalf("minted at the grant: %d %s (%d exchanges)", gr.status, gr.body, f.idp.Exchanges-before)
	}
	params, _, r = f.genMaterial("aad", node, "Delegation", g)
	if params == nil || claimsOf(t, params["access_token"].(string))["sub"] != "alice-id" || params["user"] != "alice-id" {
		t.Fatalf("the grant's user's, never the node's: %d %s", r.status, r.body)
	}
	if strings.Contains(f.logs.String(), token) {
		t.Fatal("a minted token reached the log")
	}
	// the IdP refuses: 403 mint_refused, never an empty value
	f.do("PUT", "/v1/secrets/aad2", f.admin, `{"type":"mssql","provider":"access_token","params":{"access_token":"mint+exchange://x"}}`)
	f.do("PUT", "/v1/secrets/aad2/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	f.srv.cfg.Issuers[0].Exchange.ClientSecret = "wrong"
	if r := f.do("GET", "/v1/secrets/aad2", f.alice, ""); r.status != 403 || r.problemType(t) != "mint_refused" {
		t.Fatalf("refused: %d %s", r.status, r.body)
	}
}

// provider: token_exchange stays an alias of mint+exchange:// on the type's token param
func TestTokenExchangeAlias(t *testing.T) {
	f := newFixture(t, "")
	f.do("PUT", "/v1/secrets/echo", f.admin, mintedSecret)
	f.do("PUT", "/v1/secrets/echo/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	params, body, r := f.genMaterial("echo", f.alice)
	if params == nil || body["provider"] != "config" || body["dynamic"] != true {
		t.Fatalf("the alias, served with the consumer's provider: %d %s", r.status, r.body)
	}
	if keys := redactKeys(body); len(keys) != 1 || keys[0] != "bearer_token" {
		t.Fatalf("the alias's token redacted: %v", keys)
	}
	if c := claimsOf(t, params["bearer_token"].(string)); c["aud"] != "echo-api" || c["sub"] != "alice-id" {
		t.Fatalf("the alias's token: %v", c)
	}
	// its audience is its own, never generated
	r = f.do("PUT", "/v1/secrets/m", f.admin, `{"type":"http","provider":"token_exchange","params":{"audience":"mint+claim://aud"}}`)
	if r.status != 422 {
		t.Fatalf("a generated audience: %d %s", r.status, r.body)
	}
}

// claims of every scalar kind: a 64-bit number with every digit, a boolean; a JWT-shaped claim is never served
func TestGeneratedClaimKinds(t *testing.T) {
	f := newFixture(t, "")
	dana := f.idp.Token(t, testidp.Claims{"sub": "dana-id", "aud": "duckdb-secrets", "uid": int64(9007199254740993),
		"admin": true, "nested_token": "eyJh.eyJi.c2ln", "realm_access": map[string]any{"roles": []any{"analysts"}}})
	f.do("PUT", "/v1/secrets/kinds", f.admin, `{"type":"postgres","provider":"config",
		"params":{"user":"mint+claim://uid","options":"mint+claim://admin"}}`)
	f.do("PUT", "/v1/secrets/kinds/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	params, _, r := f.genMaterial("kinds", dana)
	if params == nil || params["user"] != "9007199254740993" || params["options"] != "true" {
		t.Fatalf("scalar claims as their JSON text: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/tok", f.admin, `{"type":"postgres","provider":"config","params":{"password":"mint+claim://nested_token"}}`)
	f.do("PUT", "/v1/secrets/tok/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	if r := f.do("GET", "/v1/secrets/tok", dana, ""); r.status != 403 || r.problemType(t) != "mint_refused" ||
		strings.Contains(string(r.body), "eyJh") {
		t.Fatalf("a token in a claim: %d %s", r.status, r.body)
	}
}

// a mint+ value stored before generators were checked is never served, and the refusal names no value
func TestGeneratorStoredMalformed(t *testing.T) {
	f := newFixture(t, "")
	f.do("PUT", "/v1/secrets/old", f.admin, `{"type":"postgres","provider":"config","params":{"password":"x"}}`)
	f.do("PUT", "/v1/secrets/old/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	_, _ = f.srv.store.Update("old", func(cur *store.Secret) (*store.Secret, error) {
		cur.Params = map[string]json.RawMessage{"password": json.RawMessage(`"mint+vault://hunter2"`)}
		return cur, nil
	})
	r := f.do("GET", "/v1/secrets/old", f.alice, "")
	if r.status != 500 || r.problemType(t) != "service_error" || strings.Contains(string(r.body), "hunter2") {
		t.Fatalf("a malformed stored generator: %d %s", r.status, r.body)
	}
}

// the alias beside a generator on another key: both generated, both redacted
func TestAliasWithGenerator(t *testing.T) {
	f := newFixture(t, "")
	r := f.do("PUT", "/v1/secrets/both", f.admin, `{"type":"http","provider":"token_exchange",
		"params":{"audience":"echo-api","http_proxy_username":"mint+claim://preferred_username"}}`)
	if r.status != 201 {
		t.Fatalf("the alias with a generator: %d %s", r.status, r.body)
	}
	f.do("PUT", "/v1/secrets/both/grants/a", f.admin, `{"principal":"role:analysts","verbs":["use"]}`)
	params, body, r := f.genMaterial("both", f.alice)
	if params == nil || params["http_proxy_username"] != "alice" ||
		claimsOf(t, params["bearer_token"].(string))["sub"] != "alice-id" {
		t.Fatalf("both made: %d %s", r.status, r.body)
	}
	if keys := redactKeys(body); len(keys) != 2 {
		t.Fatalf("both redacted: %v", keys)
	}
}
