package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
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

// the review's findings, pinned

// a rule's use never becomes a standing grant: not for the user, not for the server itself
func TestRuleUseIsNotGrantable(t *testing.T) {
	f := newFixture(t, "")
	mgr := f.idp.Service(t, "duckdb-secrets", "mgr-node")
	carol := "subject:" + f.idp.URL + "|carol-id"
	f.do("PUT", "/v1/secrets/s", f.etl, s3Secret)
	f.do("PUT", "/v1/secrets/s/grants/c", f.etl, `{"principal":"`+carol+`","verbs":["grant"]}`)
	f.do("POST", "/v1/secrets/s/delegations", f.etl, `{"actors":["client:mgr-node"],"subjects":["`+carol+`"],"mode":"shared"}`)
	g, _ := f.grantFor(mgr, f.carol)
	if r := f.do("GET", "/v1/secrets/s", mgr, "", "Delegation", g); r.status != 200 {
		t.Fatalf("the rule works: %d", r.status)
	}
	for _, principal := range []string{carol, "client:mgr-node"} {
		r := f.do("PUT", "/v1/secrets/s/grants/x", mgr, `{"principal":"`+principal+`","verbs":["use"]}`, "Delegation", g)
		if r.status != 403 {
			t.Fatalf("granting a rule's use to %s: %d %s", principal, r.status, r.body)
		}
	}
	if r := f.do("GET", "/v1/secrets/s", f.carol, ""); r.status != 403 {
		t.Fatalf("carol alone: %d", r.status)
	}
	if r := f.do("GET", "/v1/secrets/s", mgr, ""); r.status != 404 {
		t.Fatalf("the node alone: %d", r.status)
	}
}

// delegate alone is not more than use: a rule's author must hold use
func TestDelegateAloneCannotDelegate(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node")
	carol := "subject:" + f.idp.URL + "|carol-id"
	f.do("PUT", "/v1/secrets/s", f.etl, s3Secret)
	f.do("PUT", "/v1/secrets/s/grants/c", f.etl, `{"principal":"`+carol+`","verbs":["delegate"]}`)
	r := f.do("POST", "/v1/secrets/s/delegations", f.carol, `{"actors":["client:node"],"subjects":["`+carol+`"],"mode":"shared"}`)
	if r.status != 403 {
		t.Fatalf("a rule by delegate alone: %d %s", r.status, r.body)
	}
	g, _ := f.grantFor(node, f.carol)
	if r := f.do("GET", "/v1/secrets/s", node, "", "Delegation", g); r.status == 200 {
		t.Fatal("material through a rule its author could not write")
	}
}

func TestExchangeRefusals(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node")
	pinned := f.idp.Service(t, "duckdb-secrets", "pinned")
	if _, r := f.grantFor(node, node); r.status != 422 {
		t.Fatalf("self-exchange: %d", r.status)
	}
	if _, r := f.grantFor(node, f.etl); r.status != 422 {
		t.Fatalf("a service as the subject: %d", r.status)
	}
	if _, r := f.grantFor(pinned, f.alice); r.status != 403 {
		t.Fatalf("an actor pinned to another issuer: %d", r.status)
	}
	// a huge ttl is capped, not wrapped into the past
	r := f.do("POST", "/v1/delegations", node, `{"subject_token":"`+f.alice+`","ttl":9223372036854775807}`)
	if r.status != 201 {
		t.Fatalf("huge ttl: %d", r.status)
	}
	expires, _ := time.Parse(time.RFC3339, r.json(t)["expires_at"].(string))
	if d := time.Until(expires); d < 7*time.Hour || d > 8*time.Hour+time.Minute {
		t.Fatalf("the cap: %v", d)
	}
}

func TestRevocation(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node")
	a1, _ := f.grantFor(node, f.alice)
	a2, _ := f.grantFor(node, f.alice)
	c1, _ := f.grantFor(node, f.carol)
	// a user ends every grant a server holds for them
	r := f.do("DELETE", "/v1/delegations", f.alice, "")
	if r.status != 200 || r.json(t)["revoked"] != float64(2) {
		t.Fatalf("self revoke: %d %s", r.status, r.body)
	}
	for _, g := range []string{a1, a2} {
		if r := f.do("GET", "/v1/whoami", node, "", "Delegation", g); r.status != 401 {
			t.Fatalf("revoked grant: %d", r.status)
		}
	}
	if r := f.do("GET", "/v1/whoami", node, "", "Delegation", c1); r.status != 200 {
		t.Fatalf("carol's grant is untouched: %d", r.status)
	}
	// an admin cuts a node off; a filter is required
	if r := f.do("DELETE", "/v1/delegations", f.admin, ""); r.status != 422 {
		t.Fatalf("an unfiltered admin revoke: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/delegations?actor=client:node", f.admin, ""); r.status != 200 || r.json(t)["revoked"] != float64(1) {
		t.Fatalf("admin by actor: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/whoami", node, "", "Delegation", c1); r.status != 401 {
		t.Fatalf("after the admin's revoke: %d", r.status)
	}
}

func TestUnderAGrant(t *testing.T) {
	f := newFixture(t, "")
	node := f.idp.Service(t, "duckdb-secrets", "node")
	f.do("PUT", "/v1/secrets/team_a_seen", f.alice, s3Secret)
	f.do("PUT", "/v1/secrets/lent", f.etl, s3Secret)
	f.do("POST", "/v1/secrets/lent/delegations", f.etl, `{"actors":["client:node"],"subjects":["role:analysts"],"mode":"shared","ttl":120}`)
	g, _ := f.grantFor(node, f.alice)
	// a secret the user sees but the node may not act on: listed with [] (never null)
	var list []map[string]any
	_ = json.Unmarshal(f.do("GET", "/v1/secrets", node, "", "Delegation", g).body, &list)
	for _, d := range list {
		if d["permissions"] == nil {
			t.Fatalf("permissions null: %v", d)
		}
	}
	// the rule's ttl bounds the material's life
	m := f.do("GET", "/v1/secrets/lent", node, "", "Delegation", g).json(t)
	expires, err := time.Parse(time.RFC3339, m["expires_at"].(string))
	if err != nil || time.Until(expires) > 2*time.Minute+5*time.Second {
		t.Fatalf("expires_at from the rule's ttl: %v", m["expires_at"])
	}
	// whoami: what the user may create through this node - nothing, the policy lists no create
	w := f.do("GET", "/v1/whoami", node, "", "Delegation", g).json(t)
	if w["permissions"].(map[string]any)["create"] != false {
		t.Fatalf("create under a use-only actor: %v", w)
	}
	// the owner sees the rules summarised
	if d := f.do("GET", "/v1/secrets/lent", f.etl, "").json(t)["delegation"]; d == nil {
		t.Fatal("the rules' summary for the owner")
	}
	// expiry: move the server's clock past the grant
	f.srv.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if r := f.do("GET", "/v1/whoami", node, "", "Delegation", g); r.status != 401 {
		t.Fatalf("an expired grant: %d", r.status)
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
