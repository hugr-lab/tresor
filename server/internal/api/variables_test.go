package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// variables (specs/018): the secrets' rules in their own namespace - advertised, administered, used through grants
func TestVariables(t *testing.T) {
	f := newFixture(t, "")
	var disco map[string]any
	_ = json.Unmarshal(f.do("GET", "/.well-known/duckdb-secrets", "", "").body, &disco)
	if caps := disco["capabilities"].(map[string]any); caps["variables"] != true {
		t.Fatalf("capabilities: %v", caps)
	}
	if r := f.do("PUT", "/v1/variables/lake", f.alice, `{"value":"s3://x"}`); r.status != 403 {
		t.Fatalf("a user creates: %d %s", r.status, r.body)
	}
	if r := f.do("PUT", "/v1/variables/lake", f.admin, `{"value":"s3://corp-lake","comment":"the lake"}`); r.status != 201 {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	if r := f.do("PUT", "/v1/variables/lake", f.admin, `{"value":"s3://other"}`, "If-None-Match", "*"); r.status != 412 {
		t.Fatalf("CREATE over an existing one: %d", r.status)
	}
	// a secret and a variable of one name are two things
	if r := f.do("GET", "/v1/secrets/lake", f.admin, ""); r.status != 404 {
		t.Fatalf("the secrets' namespace: %d", r.status)
	}
	// an administrator manages, and uses only what its roles are granted - as for a secret
	if r := f.do("GET", "/v1/variables/lake", f.admin, ""); r.status != 403 {
		t.Fatalf("an admin reads without a grant: %d", r.status)
	}
	if r := f.do("GET", "/v1/variables/lake", f.alice, ""); r.status != 404 {
		t.Fatalf("invisible before the grant: %d", r.status)
	}
	if r := f.do("PUT", "/v1/variables/lake/grants/g1", f.admin, `{"principal":"role:analysts","verbs":["use"]}`); r.status != 200 {
		t.Fatalf("grant: %d %s", r.status, r.body)
	}
	r := f.do("GET", "/v1/variables/lake", f.alice, "")
	var got map[string]any
	_ = json.Unmarshal(r.body, &got)
	if r.status != 200 || got["value"] != "s3://corp-lake" || got["sensitive"] != false || got["comment"] != "the lake" {
		t.Fatalf("read: %d %s", r.status, r.body)
	}
	list := f.do("GET", "/v1/variables", f.alice, "")
	if list.status != 200 || !strings.Contains(string(list.body), `"name":"lake"`) || strings.Contains(string(list.body), "s3://corp-lake") {
		t.Fatalf("the list (no values): %d %s", list.status, list.body)
	}
	if r := f.do("PATCH", "/v1/variables/lake", f.alice, `{"comment":"x"}`); r.status != 403 {
		t.Fatalf("a user annotates: %d", r.status)
	}
	if r := f.do("PATCH", "/v1/variables/lake", f.admin, `{"comment":"renamed"}`); r.status != 200 || !strings.Contains(string(r.body), "renamed") {
		t.Fatalf("annotate: %d %s", r.status, r.body)
	}
	if r := f.do("DELETE", "/v1/variables/lake/grants/g1", f.admin, ""); r.status != 204 {
		t.Fatalf("revoke: %d", r.status)
	}
	if r := f.do("GET", "/v1/variables/lake", f.alice, ""); r.status != 404 {
		t.Fatalf("after the revoke: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/variables/lake", f.admin, ""); r.status != 204 {
		t.Fatalf("drop: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/variables/lake", f.admin, ""); r.status != 404 {
		t.Fatalf("drop again: %d", r.status)
	}
}

func TestVariableBodies(t *testing.T) {
	f := newFixture(t, "")
	for label, c := range map[string]struct{ path, body string }{
		"no value":       {"/v1/variables/v", `{"comment":"x"}`},
		"a number":       {"/v1/variables/v", `{"value":1}`},
		"not json":       {"/v1/variables/v", `value`},
		"over 64 KiB":    {"/v1/variables/v", `{"value":"` + strings.Repeat("x", 64<<10+1) + `"}`},
		"an edge space":  {"/v1/variables/v%20", `{"value":"x"}`},
		"a control char": {"/v1/variables/a%01b", `{"value":"x"}`},
	} {
		if r := f.do("PUT", c.path, f.admin, c.body); r.status != 422 || r.problemType(t) != "invalid_secret" {
			t.Errorf("%s: %d %s", label, r.status, r.body)
		}
	}
	if r := f.do("PUT", "/v1/variables/v", f.admin, `{"value":"`+strings.Repeat("é", 32<<10)+`"}`); r.status != 201 {
		t.Errorf("64 KiB exactly: %d %s", r.status, r.body)
	}
}
