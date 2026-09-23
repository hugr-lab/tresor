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
	alice    string // role:analysts: may create team_a_*
	admin    string // role:secrets_admin
	etl      string // client:etl: may create anything
	carol    string // no roles at all
	stranger string // a valid token for another audience
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
  admins: [role:secrets_admin]
  create:
    - {principal: role:analysts, names: ["team_a_*"]}
    - {principal: client:etl, names: ["*"]}
  actors:
    - {principal: client:node, verbs: [use]}
    - {principal: client:admin-node, verbs: [use, annotate]}
`))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := store.Open("", nil)
	log := slog.New(slog.NewTextHandler(f.logs, nil))
	f.server.Config.Handler = New(cfg, auth.NewVerifier(cfg.Issuers), st, log).Handler()
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
		if create := w["permissions"].(map[string]any)["create"].([]any); create[0] != "team_a_*" {
			t.Fatalf("create: %v", create)
		}
		if w := f.do("GET", "/v1/whoami", f.etl, "").json(t); w["permissions"].(map[string]any)["create"] != true {
			t.Fatalf("etl create: %v", w)
		}
		if w := f.do("GET", "/v1/whoami", f.carol, "").json(t); w["permissions"].(map[string]any)["create"] != false {
			t.Fatalf("carol create: %v", w)
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

	// alice may create team_a_* only
	if r := f.do("PUT", "/v1/secrets/lake", f.alice, s3Secret); r.status != 403 || r.problemType(t) != "no_verb" {
		t.Fatalf("outside the pattern: %d %s", r.status, r.body)
	}
	r := f.do("PUT", "/v1/secrets/team_a_lake", f.alice, s3Secret, "If-None-Match", "*")
	if r.status != 201 || r.header.Get("ETag") != `"1"` {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	d := r.json(t)
	if d["owner"] != "subject:"+f.idp.URL+"|alice-id" || d["version"] != "1" || d["params"] != nil {
		t.Fatalf("the descriptor (and never material): %v", d)
	}
	// CREATE (not IF NOT EXISTS / OR REPLACE) of an existing name: 412
	if r := f.do("PUT", "/v1/secrets/team_a_lake", f.alice, s3Secret, "If-None-Match", "*"); r.status != 412 ||
		r.problemType(t) != "precondition_failed" {
		t.Fatalf("create twice: %d", r.status)
	}

	// material to the owner, with the typed params verbatim
	m := f.do("GET", "/v1/secrets/team_a_lake", f.alice, "")
	if m.status != 200 || m.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("material: %d", m.status)
	}
	params := m.json(t)["params"].(map[string]any)
	if params["secret"].(map[string]any)["value"] != "hunter2" || params["region"] != "eu-west-1" {
		t.Fatalf("params: %v", params)
	}

	// carol sees nothing: an invisible secret is the same 404 as a missing one
	for _, path := range []string{"/v1/secrets/team_a_lake", "/v1/secrets/nope"} {
		if r := f.do("GET", path, f.carol, ""); r.status != 404 || r.problemType(t) != "not_found" {
			t.Fatalf("%s for carol: %d", path, r.status)
		}
	}
	var list []map[string]any
	_ = json.Unmarshal(f.do("GET", "/v1/secrets", f.carol, "").body, &list)
	if len(list) != 0 {
		t.Fatalf("carol's list: %v", list)
	}
	// and may not take the name either (nor learn it exists)
	if r := f.do("PUT", "/v1/secrets/team_a_lake", f.carol, s3Secret); r.status != 403 {
		t.Fatalf("carol replace: %d", r.status)
	}

	// grants: the owner gives carol use; carol sees it, may read it, may not annotate
	if r := f.do("PUT", "/v1/secrets/team_a_lake/grants/g1", f.alice,
		`{"principal":"subject:`+f.idp.URL+`|carol-id","verbs":["use"]}`); r.status != 200 {
		t.Fatalf("grant: %d %s", r.status, r.body)
	}
	_ = json.Unmarshal(f.do("GET", "/v1/secrets?type=S3", f.carol, "").body, &list)
	if len(list) != 1 || list[0]["permissions"].([]any)[0] != "use" || len(list[0]["permissions"].([]any)) != 1 {
		t.Fatalf("carol's list after the grant: %v", list)
	}
	if r := f.do("GET", "/v1/secrets/team_a_lake", f.carol, ""); r.status != 200 {
		t.Fatalf("carol use: %d", r.status)
	}
	if r := f.do("PATCH", "/v1/secrets/team_a_lake", f.carol, `{"comment":"mine"}`); r.status != 403 {
		t.Fatalf("carol annotate: %d", r.status)
	}
	if r := f.do("GET", "/v1/secrets/team_a_lake/grants", f.carol, ""); r.status != 403 {
		t.Fatalf("carol grants: %d", r.status)
	}
	if r := f.do("PUT", "/v1/secrets/team_a_lake/grants/g2", f.alice, `{"principal":"role:x","verbs":["fly"]}`); r.status != 422 {
		t.Fatalf("unknown verb: %d", r.status)
	}
	if r := f.do("PUT", "/v1/secrets/team_a_lake/grants/g2", f.alice, `{"principal":"x","verbs":["use"]}`); r.status != 422 {
		t.Fatalf("bad principal: %d", r.status)
	}

	// annotate, replace with preconditions
	if r := f.do("PATCH", "/v1/secrets/team_a_lake", f.alice, `{"comment":"the lake"}`); r.status != 200 ||
		r.json(t)["comment"] != "the lake" {
		t.Fatalf("annotate: %d %s", r.status, r.body)
	}
	version := f.do("GET", "/v1/secrets/team_a_lake", f.alice, "").header.Get("ETag")
	if r := f.do("PUT", "/v1/secrets/team_a_lake", f.alice, s3Secret, "If-Match", `"1"`); r.status != 412 {
		t.Fatalf("stale If-Match: %d", r.status)
	}
	r = f.do("PUT", "/v1/secrets/team_a_lake", f.alice, s3Secret, "If-Match", version)
	if r.status != 200 || r.json(t)["comment"] != "the lake" {
		t.Fatalf("replace keeps the comment it was not given: %d %s", r.status, r.body)
	}

	// the admin sees and may delete everything; carol's grant is gone with the secret
	if r := f.do("DELETE", "/v1/secrets/team_a_lake", f.carol, ""); r.status != 403 {
		t.Fatalf("carol delete: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/secrets/team_a_lake", f.admin, ""); r.status != 204 {
		t.Fatalf("admin delete: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/secrets/team_a_lake", f.admin, ""); r.status != 404 {
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
		t.Fatalf("etl replace (OR REPLACE, as owner): %d", r.status)
	}
	if owner := f.do("GET", "/v1/secrets/anything", f.etl, "").json(t)["owner"]; owner != "subject:"+f.idp.URL+"|sa-etl" {
		t.Fatalf("a service owns by its subject: %v", owner)
	}
}

// the review's findings, pinned

// two people whose tokens both carry the public client's client_id (RFC 9068) are two owners
func TestPeopleNeverShareOwnership(t *testing.T) {
	f := newFixture(t, "")
	dave := f.idp.Token(t, testidp.Claims{"sub": "dave", "aud": "duckdb-secrets", "azp": "duckdb",
		"realm_access": map[string]any{"roles": []any{"analysts"}}})
	erin := f.idp.Token(t, testidp.Claims{"sub": "erin", "aud": "duckdb-secrets", "azp": "duckdb"})
	if r := f.do("PUT", "/v1/secrets/team_a_dave", dave, s3Secret); r.status != 201 {
		t.Fatalf("dave create: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/secrets/team_a_dave", erin, ""); r.status != 404 {
		t.Fatalf("erin must not see dave's secret: %d", r.status)
	}
}

// `grant` alone never becomes `use`: a grant passes on at most what its grantor holds
func TestGrantCannotEscalate(t *testing.T) {
	f := newFixture(t, "")
	carol := "subject:" + f.idp.URL + "|carol-id"
	f.do("PUT", "/v1/secrets/team_a_x", f.alice, s3Secret)
	if r := f.do("PUT", "/v1/secrets/team_a_x/grants/c", f.alice, `{"principal":"`+carol+`","verbs":["grant"]}`); r.status != 200 {
		t.Fatalf("grant: %d", r.status)
	}
	r := f.do("PUT", "/v1/secrets/team_a_x/grants/self", f.carol, `{"principal":"`+carol+`","verbs":["use"]}`)
	if r.status != 403 || r.problemType(t) != "no_verb" {
		t.Fatalf("carol granting herself use: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/secrets/team_a_x", f.carol, ""); r.status != 403 {
		t.Fatalf("carol still may not use: %d", r.status)
	}
	// what she holds she may pass on
	if r := f.do("PUT", "/v1/secrets/team_a_x/grants/d", f.carol, `{"principal":"role:x","verbs":["grant"]}`); r.status != 200 {
		t.Fatalf("passing on grant: %d", r.status)
	}
	// delete a grant; a missing one is not found
	if r := f.do("DELETE", "/v1/secrets/team_a_x/grants/d", f.alice, ""); r.status != 204 {
		t.Fatalf("delete grant: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/secrets/team_a_x/grants/d", f.alice, ""); r.status != 404 {
		t.Fatalf("delete a missing grant: %d", r.status)
	}
	if r := f.do("PUT", "/v1/secrets/team_a_x/grants/e", f.alice, `{"principal":"role:x","verbs":["delegate"]}`); r.status != 200 {
		t.Fatalf("delegate is grantable: %d", r.status)
	}
}

func TestPreconditionsAndBodies(t *testing.T) {
	f := newFixture(t, "")
	if r := f.do("PUT", "/v1/secrets/team_a_p", f.alice, s3Secret, "If-Match", `"1"`); r.status != 412 {
		t.Fatalf("If-Match on a missing secret: %d", r.status)
	}
	f.do("PUT", "/v1/secrets/team_a_p", f.alice, s3Secret)
	if r := f.do("PUT", "/v1/secrets/team_a_p", f.alice, s3Secret, "If-None-Match", `"1"`); r.status != 412 {
		t.Fatalf("If-None-Match with the current ETag: %d", r.status)
	}
	if r := f.do("PUT", "/v1/secrets/team_a_p", f.alice, s3Secret, "If-None-Match", `"7"`); r.status != 200 {
		t.Fatalf("If-None-Match with another ETag: %d", r.status)
	}
	if r := f.do("PUT", "/v1/secrets/team_a_p", f.alice, s3Secret, "If-Match", "*"); r.status != 200 {
		t.Fatalf("If-Match: * on an existing secret: %d", r.status)
	}
	// a non-owner holding update may replace
	f.do("PUT", "/v1/secrets/team_a_p/grants/u", f.alice, `{"principal":"subject:`+f.idp.URL+`|carol-id","verbs":["update"]}`)
	if r := f.do("PUT", "/v1/secrets/team_a_p", f.carol, s3Secret); r.status != 200 {
		t.Fatalf("carol with update: %d %s", r.status, r.body)
	}
	for name, body := range map[string]string{
		"a null param":       `{"type":"s3","params":{"a":null}}`,
		"a null typed value": `{"type":"s3","params":{"a":{"type":"INTEGER","value":null}}}`,
		"trailing data":      `{"type":"s3"} garbage`,
		"a second document":  `{"type":"s3"}{"type":"s3"}`,
	} {
		if r := f.do("PUT", "/v1/secrets/team_a_q", f.alice, body); r.status != 422 {
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
	// unknown routes and methods answer problem documents
	for _, probe := range [][2]string{{"GET", "/v1/nothing"}, {"POST", "/v1/secrets/x"}} {
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
