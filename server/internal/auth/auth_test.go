package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/hugr-lab/tresor/server/internal/config"
	"github.com/hugr-lab/tresor/server/internal/testidp"
)

func verifierFor(idp *testidp.IdP) *Verifier {
	return NewVerifier([]config.Issuer{{
		Issuer: idp.URL, Audience: "duckdb-secrets", RolesClaim: "realm_access.roles",
		GroupsClaim: "groups", Algorithms: []string{"RS256"},
	}})
}

func TestPersonAndService(t *testing.T) {
	idp := testidp.New(t)
	v := verifierFor(idp)

	person, err := v.Verify(context.Background(), idp.Person(t, "duckdb-secrets", "analysts"))
	if err != nil {
		t.Fatal(err)
	}
	if person.Service || person.Subject != "alice-id" {
		t.Fatalf("person: %+v", person)
	}
	if !person.Has("role:analysts") || !person.Has("subject:"+idp.URL+"|alice-id") {
		t.Fatalf("person principals: %v", person.Principals)
	}
	if person.Owner() != "subject:"+idp.URL+"|alice-id" {
		t.Fatalf("person owner: %s", person.Owner())
	}

	service, err := v.Verify(context.Background(), idp.Service(t, "duckdb-secrets", "etl", "etl"))
	if err != nil {
		t.Fatal(err)
	}
	if !service.Service || !service.Has("client:etl") || service.Owner() != "client:etl" {
		t.Fatalf("service: %+v", service)
	}
}

func TestClaimShapes(t *testing.T) {
	cfg := config.Issuer{RolesClaim: "roles", GroupsClaim: "groups"}
	// Entra: app roles in `roles`, an app token marked idtyp=app, the client in azp
	c := callerFrom(cfg, "https://login.example/tenant/v2.0/", "oid-1", time.Time{}, map[string]any{
		"roles": []any{"Secrets.Read"}, "idtyp": "app", "azp": "app-guid",
	})
	if !c.Service || !c.Has("client:app-guid") || !c.Has("role:Secrets.Read") || c.Issuer != "https://login.example/tenant/v2.0" {
		t.Fatalf("entra app: %+v", c)
	}
	// Keycloak groups are paths; a person has no client principal even with azp
	c = callerFrom(cfg, "https://kc/realms/r", "u1", time.Time{}, map[string]any{
		"groups": []any{"/sales", 7}, "azp": "duckdb",
	})
	if c.Service || !c.Has("group:sales") || len(c.Principals) != 2 {
		t.Fatalf("keycloak person: %+v", c)
	}
	// a roles claim of the wrong shape is nothing, not an error
	c = callerFrom(config.Issuer{RolesClaim: "realm_access.roles"}, "https://kc", "u", time.Time{}, map[string]any{
		"realm_access": "admin",
	})
	if len(c.Principals) != 1 {
		t.Fatalf("wrong shape: %v", c.Principals)
	}
}

func TestRefusals(t *testing.T) {
	idp := testidp.New(t)
	other := testidp.New(t)
	v := verifierFor(idp)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	base := testidp.Claims{"iss": idp.URL, "sub": "alice", "aud": "duckdb-secrets",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()}
	with := func(k string, val any) testidp.Claims {
		out := testidp.Claims{}
		for key, value := range base {
			out[key] = value
		}
		out[k] = val
		return out
	}
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+idp.URL+`","sub":"alice","aud":"duckdb-secrets","exp":9999999999}`)) + "."

	cases := map[string]string{
		"wrong audience":        idp.Token(t, with("aud", "account")),
		"expired":               idp.Token(t, with("exp", time.Now().Add(-time.Hour).Unix())),
		"unknown issuer":        other.Token(t, testidp.Claims{"sub": "alice", "aud": "duckdb-secrets"}),
		"another key":           testidp.Sign(t, otherKey, "k1", jose.RS256, base),
		"alg none":              none,
		"HS256 with a secret":   testidp.Sign(t, []byte("0123456789abcdef0123456789abcdef"), "k1", jose.HS256, base),
		"not a JWT":             "opaque-token",
		"a claimed iss, forged": testidp.Sign(t, otherKey, "k1", jose.RS256, with("iss", idp.URL)),
		"no subject":            idp.Token(t, testidp.Claims{"aud": "duckdb-secrets"}),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), token)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("expected a refusal, got %v", err)
			}
			if strings.Contains(err.Error(), token) && token != "" {
				t.Fatal("the refusal carries the token")
			}
		})
	}
}

func TestIssuerNotUpYet(t *testing.T) {
	v := NewVerifier([]config.Issuer{{Issuer: "http://127.0.0.1:1", Audience: "a", Algorithms: []string{"RS256"}}})
	idp := testidp.New(t)
	token := testidp.Sign(t, idp.Key, "k1", jose.RS256, testidp.Claims{"iss": "http://127.0.0.1:1", "sub": "x",
		"aud": "a", "exp": time.Now().Add(time.Minute).Unix()})
	_, err := v.Verify(context.Background(), token)
	if !errors.Is(err, ErrUnauthenticated) || !strings.Contains(err.Error(), "not reachable yet") {
		t.Fatalf("an unreachable issuer: %v", err)
	}
	if v.issuers["http://127.0.0.1:1"].verifier != nil {
		t.Fatal("a failed discovery must be retried, not cached")
	}
}
