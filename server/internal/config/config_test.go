package config

import (
	"strings"
	"testing"
)

const good = `
listen: 127.0.0.1:8443
public_url: http://127.0.0.1:8443
issuers:
  - issuer: http://127.0.0.1:18080/realms/tresor/
    audience: duckdb-secrets
policy:
  admins: [role:secrets_admin]
  actors:
    - {principal: client:node, verbs: [use]}
`

func TestGood(t *testing.T) {
	cfg, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuers[0].Issuer != "http://127.0.0.1:18080/realms/tresor/" || IssuerKey(cfg.Issuers[0].Issuer) != "http://127.0.0.1:18080/realms/tresor" {
		t.Fatal("the issuer is kept verbatim (RFC 8414 compares exactly); only its lookup key is normalised")
	}
	if len(cfg.Issuers[0].Algorithms) != 2 {
		t.Fatal("algorithms default to RS256, ES256")
	}
}

func TestRefused(t *testing.T) {
	cases := map[string]string{
		"plain http off loopback": strings.Replace(good, "listen: 127.0.0.1:8443", "listen: 0.0.0.0:8443", 1),
		"public http off loopback": strings.Replace(good, "public_url: http://127.0.0.1:8443",
			"public_url: http://secrets.corp", 1),
		"an unknown key": good + "\nextra: 1\n",
		"a symmetric algorithm": strings.Replace(good, "audience: duckdb-secrets",
			"audience: duckdb-secrets\n    algorithms: [HS256]", 1),
		"no audience":             strings.Replace(good, "    audience: duckdb-secrets\n", "", 1),
		"a bad principal":         strings.Replace(good, "role:secrets_admin", "secrets_admin", 1),
		"a store without a key":   good + "store: {path: x.enc}\n",
		"an actor with no verbs":  strings.Replace(good, "verbs: [use]", "verbs: []", 1),
		"an actor's unknown verb": strings.Replace(good, "verbs: [use]", "verbs: [use, fly]", 1),
		"the old create policy":   good + "  create:\n    - {principal: role:analysts, names: [\"*\"]}\n",
		"no issuers":              "listen: 127.0.0.1:1\npublic_url: http://127.0.0.1:1\n",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCreateGone(t *testing.T) {
	_, err := Parse([]byte(good + "  create:\n    - {principal: role:analysts, names: [\"*\"]}\n"))
	if err == nil || !strings.Contains(err.Error(), "policy.create is gone") {
		t.Fatalf("a config with policy.create: %v", err)
	}
}

func TestExchangeClient(t *testing.T) {
	with := strings.Replace(good, "audience: duckdb-secrets",
		"audience: duckdb-secrets\n    exchange: {client_id: duckdb-secrets, client_secret_env: TRESOR_TEST_EX}", 1)
	t.Setenv("TRESOR_TEST_EX", "")
	if _, err := Parse([]byte(with)); err == nil || !strings.Contains(err.Error(), "TRESOR_TEST_EX is empty") {
		t.Fatalf("an empty secret env: %v", err)
	}
	t.Setenv("TRESOR_TEST_EX", "s3cr3t")
	cfg, err := Parse([]byte(with))
	if err != nil || cfg.Issuers[0].Exchange.ClientSecret != "s3cr3t" {
		t.Fatalf("the secret from the env: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(with, "client_id: duckdb-secrets, ", "", 1))); err == nil {
		t.Fatal("an exchange without client_id")
	}
	if _, err := Parse([]byte(strings.Replace(with, "client_secret_env: TRESOR_TEST_EX", "client_secret: x", 1))); err == nil {
		t.Fatal("a client secret in the file")
	}
}
