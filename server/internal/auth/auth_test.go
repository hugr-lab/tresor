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

// keycloak is the rule the Keycloak realm needs: a client-credentials token carries the client_id
// session note; the client is azp
var keycloak = &config.ServiceRule{Claim: "client_id", ClientClaim: "azp"}

func verifierFor(idp *testidp.IdP) *Verifier {
	return NewVerifier([]config.Issuer{{
		Issuer: idp.Issuer, Audience: "duckdb-secrets", RolesClaim: "realm_access.roles",
		GroupsClaim: "groups", Algorithms: []string{"RS256"}, Service: keycloak,
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
	if !service.Service || !service.Has("client:etl") {
		t.Fatalf("service: %+v", service)
	}
	// ownership is identity: a service owns by its subject, never by a client name every token of the
	// client (and a same-named client of another issuer) shares
	if service.Owner() != "subject:"+idp.URL+"|sa-etl" {
		t.Fatalf("service owner: %s", service.Owner())
	}
}

// RFC 9068 puts client_id into every access token, a person's included: without a service rule no
// token is a service's, and with one only the rule decides
func TestServiceOnlyByRule(t *testing.T) {
	idp := testidp.New(t)
	person := idp.Token(t, testidp.Claims{"sub": "dave", "aud": "duckdb-secrets", "client_id": "duckdb", "azp": "duckdb"})
	plain := NewVerifier([]config.Issuer{{Issuer: idp.Issuer, Audience: "duckdb-secrets", Algorithms: []string{"RS256"}}})
	c, err := plain.Verify(context.Background(), person)
	if err != nil || c.Service || c.Has("client:duckdb") {
		t.Fatalf("no rule, no service: %+v %v", c, err)
	}
	entra := &config.ServiceRule{Claim: "idtyp", Equals: "app", ClientClaim: "azp"}
	byIdtyp := NewVerifier([]config.Issuer{{Issuer: idp.Issuer, Audience: "duckdb-secrets", Algorithms: []string{"RS256"}, Service: entra}})
	if c, _ := byIdtyp.Verify(context.Background(), person); c.Service {
		t.Fatal("a rule on idtyp=app does not fire on client_id")
	}
	app := idp.Token(t, testidp.Claims{"sub": "app-oid", "aud": "duckdb-secrets", "idtyp": "app", "azp": "etl-app"})
	if c, _ := byIdtyp.Verify(context.Background(), app); !c.Service || !c.Has("client:etl-app") {
		t.Fatalf("idtyp=app: %+v", c)
	}
	user := idp.Token(t, testidp.Claims{"sub": "u", "aud": "duckdb-secrets", "idtyp": "user", "azp": "x"})
	if c, _ := byIdtyp.Verify(context.Background(), user); c.Service {
		t.Fatal("equals is compared")
	}
}

// an issuer identifier ending in '/' (Auth0, Entra v1) is verified as written
func TestSlashedIssuer(t *testing.T) {
	idp := testidp.NewSlashed(t)
	v := verifierFor(idp)
	c, err := v.Verify(context.Background(), idp.Person(t, "duckdb-secrets", "analysts"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != idp.URL+"/" {
		t.Fatalf("issuer kept verbatim: %s", c.Issuer)
	}
}

func TestClaimShapes(t *testing.T) {
	cfg := config.Issuer{RolesClaim: "roles", GroupsClaim: "groups",
		Service: &config.ServiceRule{Claim: "idtyp", Equals: "app", ClientClaim: "azp"}}
	// Entra: app roles in `roles`, an app token marked idtyp=app, the client in azp
	c := callerFrom(cfg, "https://login.example/tenant/v2.0", "oid-1", time.Time{}, map[string]any{
		"roles": []any{"Secrets.Read"}, "idtyp": "app", "azp": "app-guid",
	})
	if !c.Service || !c.Has("client:app-guid") || !c.Has("role:Secrets.Read") {
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
	base := testidp.Claims{"iss": idp.Issuer, "sub": "alice", "aud": "duckdb-secrets",
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
		"a claimed iss, forged": testidp.Sign(t, otherKey, "k1", jose.RS256, with("iss", idp.Issuer)),
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
	is := v.issuers["http://127.0.0.1:1"]
	if is.verifier != nil || is.lastFailed == nil {
		t.Fatal("a failed discovery is remembered as failed, not as a verifier")
	}
	// within retryAfter the failure is answered from memory, without another outbound request
	failedAt := is.failedAt
	if _, err := v.Verify(context.Background(), token); !errors.Is(err, ErrUnauthenticated) || is.failedAt != failedAt {
		t.Fatal("a second token within retryAfter must not trigger another discovery")
	}
	// after it, discovery is tried again
	v.Now = func() time.Time { return time.Now().Add(retryAfter + time.Second) }
	_, _ = v.Verify(context.Background(), token)
	if is.failedAt == failedAt {
		t.Fatal("after retryAfter discovery is retried")
	}
}
