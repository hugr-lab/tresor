package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hugr-lab/tresor/server/internal/auth"
	"github.com/hugr-lab/tresor/server/internal/config"
	"github.com/hugr-lab/tresor/server/internal/store"
	"github.com/hugr-lab/tresor/server/internal/testidp"
)

type fixture struct {
	t        *testing.T
	idp      *testidp.IdP
	server   *httptest.Server
	base     string
	logs     *bytes.Buffer
	alice    string // role:analysts: uses what is granted to analysts, manages nothing
	admin    string // role:secrets_admin: manages everything, uses only what its roles are granted
	etl      string // client:etl, an admin too (policy.admins)
	carol    string // no roles at all
	stranger string // a valid token for another audience
	srv      *Server
}

func newFixture(t *testing.T, basePath string) *fixture {
	t.Helper()
	idp := testidp.New(t)
	f := &fixture{t: t, idp: idp, logs: &bytes.Buffer{}}
	f.server = httptest.NewUnstartedServer(nil)
	f.base = "http://" + f.server.Listener.Addr().String() + basePath
	cfg, err := config.Parse([]byte(`
listen: 127.0.0.1:0
public_url: ` + f.base + `
issuers:
  - issuer: ` + idp.URL + `
    audience: duckdb-secrets
    client_id: duckdb
    scopes: [openid, duckdb-secrets]
    human_flows: [authorization_code]
    roles_claim: realm_access.roles
    service: {claim: client_id}
policy:
  admins: [role:secrets_admin, client:etl]
  actors:
    - {principal: client:node, verbs: [use]}
    - {principal: client:admin-node, verbs: [use, create, update, delete, annotate, grant]}
    - {principal: client:other-node, verbs: [use]}
    - {principal: client:pinned, issuer: https://elsewhere.example, verbs: [use]}
`))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := store.Open("", nil)
	log := slog.New(slog.NewTextHandler(f.logs, nil))
	f.srv = New(cfg, auth.NewVerifier(cfg.Issuers), st, log)
	f.server.Config.Handler = f.srv.Handler()
	f.server.Start()
	t.Cleanup(f.server.Close)
	f.alice = idp.Person(t, "duckdb-secrets", "analysts")
	f.admin = idp.Token(t, testidp.Claims{"sub": "bob-id", "aud": "duckdb-secrets",
		"realm_access": map[string]any{"roles": []any{"secrets_admin"}}})
	f.etl = idp.Service(t, "duckdb-secrets", "etl")
	f.carol = idp.Token(t, testidp.Claims{"sub": "carol-id", "aud": "duckdb-secrets"})
	f.stranger = idp.Person(t, "account", "secrets_admin")
	return f
}

type reply struct {
	status int
	header http.Header
	body   []byte
}

func (r reply) json(t *testing.T) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(r.body, &out); err != nil {
		t.Fatalf("not an object: %s", r.body)
	}
	return out
}

func (r reply) problemType(t *testing.T) string {
	t.Helper()
	if r.header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("not a problem: %d %s", r.status, r.body)
	}
	return r.json(t)["type"].(string)
}

func (f *fixture) do(method, path, token, body string, headers ...string) reply {
	f.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, f.base+path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return reply{res.StatusCode, res.Header, data}
}

const s3Secret = `{"type":"s3","provider":"config","scope":["s3://lake"],
  "params":{"key_id":"AKIA","secret":{"type":"VARCHAR","value":"hunter2"},"region":"eu-west-1"},
  "redact_keys":["secret"]}`

func TestDiscoveryAndWhoami(t *testing.T) {
	for _, basePath := range []string{"", "/tresor"} {
		f := newFixture(t, basePath)
		d := f.do("GET", "/.well-known/duckdb-secrets", "", "").json(t)
		if d["protocol"] != Protocol || d["api"] != f.base {
			t.Fatalf("discovery under %q: %v", basePath, d)
		}
		issuer := d["issuers"].([]any)[0].(map[string]any)
		if issuer["client_id"] != "duckdb" || issuer["audience"] != "duckdb-secrets" {
			t.Fatalf("issuer entry: %v", issuer)
		}
		if _, ok := issuer["service_flows"]; ok {
			t.Fatal("an unconfigured flow list is absent, not empty (empty means none)")
		}

		w := f.do("GET", "/v1/whoami", f.alice, "").json(t)
		if w["subject"] != "alice-id" || w["issuer"] != f.idp.URL {
			t.Fatalf("whoami: %v", w)
		}
		if roles := w["roles"].([]any); len(roles) != 1 || roles[0] != "role:analysts" {
			t.Fatalf("roles: %v", roles)
		}
		// only admins create (specs/009)
		for name, token := range map[string]string{"alice": f.alice, "carol": f.carol} {
			if w := f.do("GET", "/v1/whoami", token, "").json(t); w["permissions"].(map[string]any)["create"] != false {
				t.Fatalf("%s create: %v", name, w)
			}
		}
		for name, token := range map[string]string{"admin": f.admin, "etl": f.etl} {
			if w := f.do("GET", "/v1/whoami", token, "").json(t); w["permissions"].(map[string]any)["create"] != true {
				t.Fatalf("%s create: %v", name, w)
			}
		}
	}
}

func TestUnauthenticated(t *testing.T) {
	f := newFixture(t, "")
	for name, token := range map[string]string{"none": "", "garbage": "x.y.z", "other audience": f.stranger} {
		r := f.do("GET", "/v1/whoami", token, "")
		if r.status != 401 || r.problemType(t) != "unauthenticated" {
			t.Fatalf("%s: %d %s", name, r.status, r.body)
		}
	}
	if strings.Contains(f.logs.String(), f.stranger) {
		t.Fatal("a token reached the log")
	}
}

func TestSecretsLifecycle(t *testing.T) {
	f := newFixture(t, "")

	// users do not create secrets (specs/009): they keep their own locally
	if r := f.do("PUT", "/v1/secrets/lake", f.alice, s3Secret); r.status != 403 || r.problemType(t) != "no_verb" {
		t.Fatalf("a user creating: %d %s", r.status, r.body)
	}
	r := f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret, "If-None-Match", "*")
	if r.status != 201 || r.header.Get("ETag") != `"1"` {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	d := r.json(t)
	if d["owner"] != "subject:"+f.idp.URL+"|bob-id" || d["version"] != "1" || d["params"] != nil {
		t.Fatalf("the descriptor (and never material): %v", d)
	}
	if _, ok := d["delegation"]; ok {
		t.Fatal("no delegation rules any more")
	}
	if r := f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret, "If-None-Match", "*"); r.status != 412 ||
		r.problemType(t) != "precondition_failed" {
		t.Fatalf("create twice: %d", r.status)
	}

	// an admin manages, but an admin role implies no use: the material only through a grant to its roles
	if r := f.do("GET", "/v1/secrets/lake", f.admin, ""); r.status != 403 || r.problemType(t) != "no_verb" {
		t.Fatalf("the admin's material without a grant: %d", r.status)
	}
	perms := f.do("GET", "/v1/secrets/lake", f.alice, "")
	if perms.status != 404 {
		t.Fatalf("alice before the grant: %d", perms.status)
	}

	// grants: roles and groups only, use only
	for name, body := range map[string]string{
		"a subject":         `{"principal":"subject:` + f.idp.URL + `|carol-id","verbs":["use"]}`,
		"a client":          `{"principal":"client:etl","verbs":["use"]}`,
		"a management verb": `{"principal":"role:analysts","verbs":["update"]}`,
		"use and more":      `{"principal":"role:analysts","verbs":["use","grant"]}`,
		"an unknown verb":   `{"principal":"role:analysts","verbs":["fly"]}`,
		"a bare prefix":     `{"principal":"role:","verbs":["use"]}`,
	} {
		if r := f.do("PUT", "/v1/secrets/lake/grants/g", f.admin, body); r.status != 422 {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	if r := f.do("PUT", "/v1/secrets/lake/grants/analysts", f.admin, `{"principal":"role:analysts","verbs":["use"]}`); r.status != 200 {
		t.Fatalf("grant: %d %s", r.status, r.body)
	}
	if r := f.do("PUT", "/v1/secrets/lake/grants/ops", f.admin, `{"principal":"group:ops","verbs":["use"]}`); r.status != 200 {
		t.Fatalf("grant to a group: %d %s", r.status, r.body)
	}
	var list []map[string]any
	_ = json.Unmarshal(f.do("GET", "/v1/secrets?type=S3", f.alice, "").body, &list)
	if len(list) != 1 || len(list[0]["permissions"].([]any)) != 1 || list[0]["permissions"].([]any)[0] != "use" {
		t.Fatalf("alice's list after the grant: %v", list)
	}
	m := f.do("GET", "/v1/secrets/lake", f.alice, "")
	if m.status != 200 || m.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("material: %d", m.status)
	}
	params := m.json(t)["params"].(map[string]any)
	if params["secret"].(map[string]any)["value"] != "hunter2" || params["region"] != "eu-west-1" {
		t.Fatalf("params: %v", params)
	}

	// carol, in no granted role, sees nothing: an invisible secret is the same 404 as a missing one
	for _, path := range []string{"/v1/secrets/lake", "/v1/secrets/nope"} {
		if r := f.do("GET", path, f.carol, ""); r.status != 404 || r.problemType(t) != "not_found" {
			t.Fatalf("%s for carol: %d", path, r.status)
		}
	}
	_ = json.Unmarshal(f.do("GET", "/v1/secrets", f.carol, "").body, &list)
	if len(list) != 0 {
		t.Fatalf("carol's list: %v", list)
	}

	// alice uses, and manages nothing
	for _, probe := range [][3]string{
		{"PATCH", "/v1/secrets/lake", `{"comment":"mine"}`},
		{"GET", "/v1/secrets/lake/grants", ""},
		{"PUT", "/v1/secrets/lake/grants/x", `{"principal":"role:analysts","verbs":["use"]}`},
		{"PUT", "/v1/secrets/lake", s3Secret},
		{"DELETE", "/v1/secrets/lake", ""},
	} {
		if r := f.do(probe[0], probe[1], f.alice, probe[2]); r.status != 403 || r.problemType(t) != "no_verb" {
			t.Errorf("alice %s %s: %d %s", probe[0], probe[1], r.status, r.body)
		}
	}

	// the admin annotates and replaces, with preconditions
	if r := f.do("PATCH", "/v1/secrets/lake", f.admin, `{"comment":"the lake"}`); r.status != 200 ||
		r.json(t)["comment"] != "the lake" {
		t.Fatalf("annotate: %d %s", r.status, r.body)
	}
	if r := f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret, "If-Match", `"1"`); r.status != 412 {
		t.Fatalf("stale If-Match: %d", r.status)
	}
	r = f.do("PUT", "/v1/secrets/lake", f.admin, s3Secret, "If-Match", `"4"`)
	if r.status != 200 || r.json(t)["comment"] != "the lake" {
		t.Fatalf("replace keeps the comment it was not given: %d %s", r.status, r.body)
	}
	if r := f.do("DELETE", "/v1/secrets/lake/grants/ops", f.admin, ""); r.status != 204 {
		t.Fatalf("delete grant: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/secrets/lake/grants/ops", f.admin, ""); r.status != 404 {
		t.Fatalf("delete a missing grant: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/secrets/lake", f.admin, ""); r.status != 204 {
		t.Fatalf("admin delete: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/secrets/lake", f.admin, ""); r.status != 404 {
		t.Fatalf("delete twice: %d", r.status)
	}
	if strings.Contains(f.logs.String(), "hunter2") {
		t.Fatal("material reached the log")
	}
}

func TestServiceOwnsWhatItCreates(t *testing.T) {
	f := newFixture(t, "")
	r := f.do("PUT", "/v1/secrets/anything", f.etl, `{"type":"http","params":{"bearer_token":"t"}}`)
	if r.status != 201 || r.json(t)["owner"] != "subject:"+f.idp.URL+"|sa-etl" {
		t.Fatalf("etl create: %d %s", r.status, r.body)
	}
	if r := f.do("PUT", "/v1/secrets/anything", f.etl, `{"type":"http","params":{}}`); r.status != 200 {
		t.Fatalf("etl replace (OR REPLACE, as an admin): %d", r.status)
	}
	// creating is not using: the service's roles hold no grant on it yet
	if r := f.do("GET", "/v1/secrets/anything", f.etl, ""); r.status != 403 {
		t.Fatalf("an admin's own creation, without a grant: %d", r.status)
	}
}

// an admin uses a secret exactly when one of its roles is granted it
func TestAdminImpliesNoUse(t *testing.T) {
	f := newFixture(t, "")
	f.do("PUT", "/v1/secrets/s", f.admin, s3Secret)
	if r := f.do("GET", "/v1/secrets/s", f.admin, ""); r.status != 403 {
		t.Fatalf("before the grant: %d", r.status)
	}
	f.do("PUT", "/v1/secrets/s/grants/a", f.admin, `{"principal":"role:secrets_admin","verbs":["use"]}`)
	if r := f.do("GET", "/v1/secrets/s", f.admin, ""); r.status != 200 {
		t.Fatalf("after the grant to its role: %d", r.status)
	}
}

func TestPreconditionsAndBodies(t *testing.T) {
	f := newFixture(t, "")
	if r := f.do("PUT", "/v1/secrets/p", f.admin, s3Secret, "If-Match", `"1"`); r.status != 412 {
		t.Fatalf("If-Match on a missing secret: %d", r.status)
	}
	f.do("PUT", "/v1/secrets/p", f.admin, s3Secret)
	if r := f.do("PUT", "/v1/secrets/p", f.admin, s3Secret, "If-None-Match", `"1"`); r.status != 412 {
		t.Fatalf("If-None-Match with the current ETag: %d", r.status)
	}
	if r := f.do("PUT", "/v1/secrets/p", f.admin, s3Secret, "If-None-Match", `"7"`); r.status != 200 {
		t.Fatalf("If-None-Match with another ETag: %d", r.status)
	}
	if r := f.do("PUT", "/v1/secrets/p", f.admin, s3Secret, "If-Match", "*"); r.status != 200 {
		t.Fatalf("If-Match: * on an existing secret: %d", r.status)
	}
	for name, body := range map[string]string{
		"a null param":       `{"type":"s3","params":{"a":null}}`,
		"a null typed value": `{"type":"s3","params":{"a":{"type":"INTEGER","value":null}}}`,
		"trailing data":      `{"type":"s3"} garbage`,
		"a second document":  `{"type":"s3"}{"type":"s3"}`,
	} {
		if r := f.do("PUT", "/v1/secrets/q", f.admin, body); r.status != 422 {
			t.Errorf("%s: %d", name, r.status)
		}
	}
}

func TestProtocolEdges(t *testing.T) {
	f := newFixture(t, "")
	// the scheme is case-insensitive
	req, _ := http.NewRequest("GET", f.base+"/v1/whoami", nil)
	req.Header.Set("Authorization", "bearer "+f.alice)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("lower-case bearer: %v %v", res, err)
	}
	res.Body.Close()
	// unknown routes and methods answer problem documents - the delegation rules' routes are gone too
	for _, probe := range [][2]string{{"GET", "/v1/nothing"}, {"POST", "/v1/secrets/x"},
		{"GET", "/v1/secrets/x/delegations"}} {
		if r := f.do(probe[0], probe[1], f.alice, "{}"); r.status != 404 || r.problemType(t) != "not_found" {
			t.Errorf("%s %s: %d %s", probe[0], probe[1], r.status, r.body)
		}
	}
}

func TestInvalidSecrets(t *testing.T) {
	f := newFixture(t, "")
	for name, body := range map[string]string{
		"no type":         `{"params":{}}`,
		"a bad param":     `{"type":"s3","params":{"x":{"value":1}}}`,
		"a number param":  `{"type":"s3","params":{"x":1}}`,
		"a stray redact":  `{"type":"s3","params":{"a":"b"},"redact_keys":["c"]}`,
		"an unknown key":  `{"type":"s3","material":{}}`,
		"not json at all": `secret`,
	} {
		if r := f.do("PUT", "/v1/secrets/x", f.admin, body); r.status != 422 || r.problemType(t) != "invalid_secret" {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
}
