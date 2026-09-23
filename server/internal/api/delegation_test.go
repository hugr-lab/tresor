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
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	other := f.idp.Service(t, "duckdb-secrets", "other-node")
	rogue := f.idp.Service(t, "duckdb-secrets", "rogue", "nodes")

	// an admin creates what the node serves, and grants it to the node's role; another only to analysts
	f.do("PUT", "/v1/secrets/lake", f.etl, s3Secret)
	f.do("PUT", "/v1/secrets/lake/grants/nodes", f.etl, `{"principal":"role:nodes","verbs":["use"]}`)
	f.do("PUT", "/v1/secrets/analysts_only", f.etl, s3Secret)
	f.do("PUT", "/v1/secrets/analysts_only/grants/a", f.etl, `{"principal":"role:analysts","verbs":["use"]}`)

	// the node uses its own, as itself
	if r := f.do("GET", "/v1/secrets/lake", node, ""); r.status != 200 {
		t.Fatalf("the node's own: %d", r.status)
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

	// under a grant the node's own rights apply (specs/009): what the node was granted, for any of its users
	for name, g := range map[string]string{"alice": aliceGrant, "carol": carolGrant} {
		if m := f.do("GET", "/v1/secrets/lake", node, "", "Delegation", g); m.status != 200 || m.json(t)["params"] == nil {
			t.Fatalf("%s through the node: %d %s", name, m.status, m.body)
		}
	}
	// ... and nothing more: a secret alice uses herself is not the node's, not through her grant either
	if r := f.do("GET", "/v1/secrets/analysts_only", f.alice, ""); r.status != 200 {
		t.Fatalf("alice alone: %d", r.status)
	}
	if r := f.do("GET", "/v1/secrets/analysts_only", node, "", "Delegation", aliceGrant); r.status != 404 {
		t.Fatalf("alice's own through the node: %d", r.status)
	}
	// a grant presented by another actor is no grant
	if r := f.do("GET", "/v1/secrets/lake", other, "", "Delegation", aliceGrant); r.status != 401 {
		t.Fatalf("a stolen grant: %d", r.status)
	}

	// whoami and the listing under the grant: the user, with the actor named; the node's secrets
	w := f.do("GET", "/v1/whoami", node, "", "Delegation", aliceGrant).json(t)
	if w["subject"] != "alice-id" || w["actor"] != "client:node" || w["permissions"].(map[string]any)["create"] != false {
		t.Fatalf("whoami: %v", w)
	}
	var list []map[string]any
	_ = json.Unmarshal(f.do("GET", "/v1/secrets", node, "", "Delegation", aliceGrant).body, &list)
	if len(list) != 1 || list[0]["name"] != "lake" || list[0]["permissions"].([]any)[0] != "use" {
		t.Fatalf("listing: %v", list)
	}

	// nothing is managed through a server that may not pass it on - not even for an admin
	adminGrant, _ := f.grantFor(node, f.admin)
	for _, g := range []string{aliceGrant, adminGrant} {
		for _, probe := range [][3]string{
			{"PATCH", "/v1/secrets/lake", `{"comment":"x"}`},
			{"PUT", "/v1/secrets/lake", s3Secret},
			{"PUT", "/v1/secrets/new", s3Secret},
			{"PUT", "/v1/secrets/lake/grants/x", `{"principal":"role:x","verbs":["use"]}`},
			{"DELETE", "/v1/secrets/lake", ""},
		} {
			if r := f.do(probe[0], probe[1], node, probe[2], "Delegation", g); r.status != 403 ||
				r.problemType(t) != "actor_not_allowed" {
				t.Errorf("%s %s under a grant: %d %s", probe[0], probe[1], r.status, r.body)
			}
		}
	}
	// administration through a server that may pass it on (specs/009): only for a user who is an admin
	adminNode := f.idp.Service(t, "duckdb-secrets", "admin-node")
	viaAdmin, _ := f.grantFor(adminNode, f.admin)
	viaAlice, _ := f.grantFor(adminNode, f.alice)
	if w := f.do("GET", "/v1/whoami", adminNode, "", "Delegation", viaAdmin).json(t); w["permissions"].(map[string]any)["create"] != true {
		t.Fatalf("an admin through an admin node may create: %v", w)
	}
	if r := f.do("PUT", "/v1/secrets/made_via_node", adminNode, s3Secret, "Delegation", viaAdmin); r.status != 201 ||
		r.json(t)["owner"] != "subject:"+f.idp.URL+"|bob-id" {
		t.Fatalf("create through the node, owned by the admin: %d %s", r.status, r.body)
	}
	if r := f.do("PUT", "/v1/secrets/made_via_node/grants/n", adminNode, `{"principal":"role:nodes","verbs":["use"]}`,
		"Delegation", viaAdmin); r.status != 200 {
		t.Fatalf("grant through the node: %d %s", r.status, r.body)
	}
	if r := f.do("GET", "/v1/secrets/made_via_node", node, ""); r.status != 200 {
		t.Fatalf("the grant took: %d", r.status)
	}
	for _, probe := range [][3]string{
		{"PUT", "/v1/secrets/by_alice", s3Secret},
		{"PUT", "/v1/secrets/made_via_node/grants/x", `{"principal":"role:x","verbs":["use"]}`},
		{"DELETE", "/v1/secrets/made_via_node", ""},
	} {
		if r := f.do(probe[0], probe[1], adminNode, probe[2], "Delegation", viaAlice); r.status != 403 && r.status != 404 {
			t.Errorf("a user who is no admin, through an admin node, %s %s: %d %s", probe[0], probe[1], r.status, r.body)
		}
	}

	// a grant cannot mint grants
	if r := f.do("POST", "/v1/delegations", node, `{"subject_token":"`+f.carol+`"}`, "Delegation", aliceGrant); r.status != 403 {
		t.Fatalf("an exchange under a grant: %d", r.status)
	}

	// revoke: by its actor; afterwards the grant is gone
	if r := f.do("DELETE", "/v1/delegations/"+aliceGrant, other, ""); r.status != 404 {
		t.Fatalf("revoke by another actor: %d", r.status)
	}
	if r := f.do("DELETE", "/v1/delegations/"+aliceGrant, node, ""); r.status != 204 {
		t.Fatalf("revoke: %d", r.status)
	}
	if r := f.do("GET", "/v1/whoami", node, "", "Delegation", aliceGrant); r.status != 401 {
		t.Fatalf("a revoked grant: %d", r.status)
	}
	if strings.Contains(f.logs.String(), aliceGrant) || strings.Contains(f.logs.String(), carolGrant) {
		t.Fatal("a grant id reached the log")
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
	node := f.idp.Service(t, "duckdb-secrets", "node", "nodes")
	f.do("PUT", "/v1/secrets/lent", f.etl, s3Secret)
	f.do("PUT", "/v1/secrets/lent/grants/n", f.etl, `{"principal":"role:nodes","verbs":["use"]}`)
	g, _ := f.grantFor(node, f.alice)
	var list []map[string]any
	_ = json.Unmarshal(f.do("GET", "/v1/secrets", node, "", "Delegation", g).body, &list)
	for _, d := range list {
		if d["permissions"] == nil {
			t.Fatalf("permissions null: %v", d)
		}
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
