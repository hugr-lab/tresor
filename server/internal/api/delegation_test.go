package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// grantFor exchanges `user`'s token for a grant held by the actor `actorToken`; the id, or "" on refusal.
func (f *fixture) grantFor(actorToken, userToken string) (string, reply) {
	f.t.Helper()
	r := f.do("POST", "/v1/delegations", actorToken, `{"subject_token":"`+userToken+`","ttl":3600}`)
	if r.status != 201 {
		return "", r
	}
	return r.json(f.t)["id"].(string), r
}

func TestDelegation(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node")
	adminNode := f.idp.Service(t, "duckdb-secrets", "admin-node")
	rogue := f.idp.Service(t, "duckdb-secrets", "rogue")

	// the owner (etl) creates a secret and delegates it to the node for analysts, shared
	if r := f.do("PUT", "/v1/secrets/crm_prod", f.etl, s3Secret); r.status != 201 {
		t.Fatalf("create: %d", r.status)
	}
	if r := f.do("POST", "/v1/secrets/crm_prod/delegations", f.alice, `{"actors":["client:node"],"subjects":["role:analysts"],"mode":"shared"}`); r.status != 404 {
		t.Fatalf("a rule by someone who cannot see the secret: %d", r.status)
	}
	for name, body := range map[string]string{
		"user mode":       `{"actors":["client:node"],"subjects":["role:analysts"],"mode":"user"}`,
		"no actors":       `{"actors":[],"subjects":["role:analysts"],"mode":"shared"}`,
		"a person actor":  `{"actors":["role:x"],"subjects":["role:analysts"],"mode":"shared"}`,
		"a bad subject":   `{"actors":["client:node"],"subjects":["analysts"],"mode":"shared"}`,
		"an unknown mode": `{"actors":["client:node"],"subjects":["role:analysts"],"mode":"always"}`,
	} {
		if r := f.do("POST", "/v1/secrets/crm_prod/delegations", f.etl, body); r.status != 422 {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	r := f.do("POST", "/v1/secrets/crm_prod/delegations", f.etl, `{"actors":["client:node"],"subjects":["role:analysts"],"mode":"shared","ttl":600}`)
	if r.status != 201 {
		t.Fatalf("add rule: %d %s", r.status, r.body)
	}
	ruleID := r.json(t)["id"].(string)
	var rules []map[string]any
	_ = json.Unmarshal(f.do("GET", "/v1/secrets/crm_prod/delegations", f.etl, "").body, &rules)
	if len(rules) != 1 || rules[0]["id"] != ruleID || rules[0]["mode"] != "shared" {
		t.Fatalf("rules: %v", rules)
	}

	// the exchange: only a service the policy lets act for users
	if _, r := f.grantFor(f.alice, f.alice); r.status != 403 || r.problemType(t) != "actor_not_allowed" {
		t.Fatalf("a person as actor: %d", r.status)
	}
	if _, r := f.grantFor(rogue, f.alice); r.status != 403 || r.problemType(t) != "actor_not_allowed" {
		t.Fatalf("an actor not in the policy: %d", r.status)
	}
	if _, r := f.grantFor(node, "not-a-token"); r.status != 401 {
		t.Fatalf("a bad subject token: %d", r.status)
	}
	aliceGrant, r := f.grantFor(node, f.alice)
	if aliceGrant == "" {
		t.Fatalf("exchange: %d %s", r.status, r.body)
	}
	if r.json(t)["actor"] != "client:node" || r.json(t)["subject"] != "alice-id" {
		t.Fatalf("grant: %s", r.body)
	}
	carolGrant, _ := f.grantFor(node, f.carol)

	// material through the grant: alice holds no `use`, the shared rule is what lets the node use it
	if r := f.do("GET", "/v1/secrets/crm_prod", f.alice, ""); r.status != 404 {
		t.Fatalf("alice alone: %d", r.status)
	}
	m := f.do("GET", "/v1/secrets/crm_prod", node, "", "Delegation", aliceGrant)
	if m.status != 200 || m.json(t)["params"] == nil {
		t.Fatalf("delegated material: %d %s", m.status, m.body)
	}
	// ... but not for carol, whom no rule names
	if r := f.do("GET", "/v1/secrets/crm_prod", node, "", "Delegation", carolGrant); r.status != 404 {
		t.Fatalf("carol through the node: %d", r.status)
	}
	// the node alone has no business with it
	if r := f.do("GET", "/v1/secrets/crm_prod", node, ""); r.status != 404 {
		t.Fatalf("the node on its own: %d", r.status)
	}
	// a grant presented by another actor is no grant
	if r := f.do("GET", "/v1/secrets/crm_prod", adminNode, "", "Delegation", aliceGrant); r.status != 401 {
		t.Fatalf("a stolen grant: %d", r.status)
	}

	// whoami and the listing under the grant: the user, with the actor named
	w := f.do("GET", "/v1/whoami", node, "", "Delegation", aliceGrant).json(t)
	if w["subject"] != "alice-id" || w["actor"] != "client:node" {
		t.Fatalf("whoami: %v", w)
	}
	var list []map[string]any
	_ = json.Unmarshal(f.do("GET", "/v1/secrets", node, "", "Delegation", aliceGrant).body, &list)
	if len(list) != 1 || list[0]["name"] != "crm_prod" || list[0]["permissions"].([]any)[0] != "use" {
		t.Fatalf("listing: %v", list)
	}

	// a rule for another actor delegates nothing to this one
	f.do("PUT", "/v1/secrets/other", f.etl, s3Secret)
	f.do("POST", "/v1/secrets/other/delegations", f.etl, `{"actors":["client:admin-node"],"subjects":["role:analysts"],"mode":"shared"}`)
	if r := f.do("GET", "/v1/secrets/other", node, "", "Delegation", aliceGrant); r.status != 404 {
		t.Fatalf("a rule for another actor: %d", r.status)
	}

	// management through a grant: the user's verbs, only those the actor may exercise
	f.do("PUT", "/v1/secrets/team_a_mine", f.alice, s3Secret)
	if r := f.do("PATCH", "/v1/secrets/team_a_mine", node, `{"comment":"x"}`, "Delegation", aliceGrant); r.status != 403 || r.problemType(t) != "actor_not_allowed" {
		t.Fatalf("annotate via a use-only actor: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/secrets/team_a_mine", node, "", "Delegation", aliceGrant); r.status != 403 || r.problemType(t) != "not_delegable" {
		t.Fatalf("the user's own secret without a rule: %d %s", r.status, r.body)
	}
	adminGrant, _ := f.grantFor(adminNode, f.alice)
	if r := f.do("PATCH", "/v1/secrets/team_a_mine", adminNode, `{"comment":"x"}`, "Delegation", adminGrant); r.status != 200 {
		t.Fatalf("annotate via an actor allowed to: %d %s", r.status, r.body)
	}
	if r := f.do("PUT", "/v1/secrets/team_a_new", node, s3Secret, "Delegation", aliceGrant); r.status != 403 {
		t.Fatalf("create through a grant (a management verb): %d", r.status)
	}
	// a grant cannot mint grants
	if r := f.do("POST", "/v1/delegations", node, `{"subject_token":"`+f.carol+`"}`, "Delegation", aliceGrant); r.status != 403 {
		t.Fatalf("an exchange under a grant: %d", r.status)
	}

	// revoke: by its actor; afterwards the grant is gone
	if r := f.do("DELETE", "/v1/delegations/"+aliceGrant, adminNode, ""); r.status != 404 {
		t.Fatalf("revoke by another actor: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/delegations/"+aliceGrant, node, ""); r.status != 204 {
		t.Fatalf("revoke: %d", r.status)
	}
	if r := f.do("GET", "/v1/whoami", node, "", "Delegation", aliceGrant); r.status != 401 {
		t.Fatalf("a revoked grant: %d", r.status)
	}

	// remove the rule: the secret is no longer delegated
	if r := f.do("DELETE", "/v1/secrets/crm_prod/delegations/"+ruleID, f.etl, ""); r.status != 204 {
		t.Fatalf("remove rule: %d", r.status)
	}
	fresh, _ := f.grantFor(node, f.alice)
	if r := f.do("GET", "/v1/secrets/crm_prod", node, "", "Delegation", fresh); r.status != 404 {
		t.Fatalf("after the rule went: %d", r.status)
	}
	if strings.Contains(f.logs.String(), fresh) || strings.Contains(f.logs.String(), aliceGrant) {
		t.Fatal("a grant id reached the log")
	}
}

func TestGrantExpiry(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node")
	id, r := f.grantFor(node, f.alice)
	if id == "" {
		t.Fatalf("exchange: %d", r.status)
	}
	// the ttl is capped at 8 hours
	big := f.do("POST", "/v1/delegations", node, `{"subject_token":"`+f.alice+`","ttl":999999}`).json(t)
	if !strings.HasPrefix(big["expires_at"].(string), "20") {
		t.Fatalf("expires: %v", big)
	}
}
