// Package config reads and validates the reference server's configuration (specs/003).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the whole server configuration.
type Config struct {
	Listen    string   `yaml:"listen"`
	PublicURL string   `yaml:"public_url"`
	TLS       TLS      `yaml:"tls"`
	Store     Store    `yaml:"store"`
	Issuers   []Issuer `yaml:"issuers"`
	Policy    Policy   `yaml:"policy"`
}

// TLS names the certificate the server serves with; empty means plain http (loopback only).
type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// Store says where the secrets are kept: memory when Path is empty, else an encrypted file.
type Store struct {
	Path   string `yaml:"path"`
	KeyEnv string `yaml:"key_env"`
}

// Issuer is one identity provider the server accepts tokens from.
type Issuer struct {
	Issuer       string   `yaml:"issuer"`
	Audience     string   `yaml:"audience"`
	ClientID     string   `yaml:"client_id"`
	Scopes       []string `yaml:"scopes"`
	HumanFlows   []string `yaml:"human_flows"`
	ServiceFlows []string `yaml:"service_flows"`
	RolesClaim   string   `yaml:"roles_claim"`
	GroupsClaim  string   `yaml:"groups_claim"`
	Algorithms   []string `yaml:"algorithms"`
	// Service says how this issuer's client-credentials tokens are told apart from people's. Without
	// it every caller of the issuer is a person: no claim is a service marker by convention (RFC 9068
	// puts client_id into every access token, a person's included).
	Service *ServiceRule `yaml:"service"`
	// Exchange is the service's own confidential client at this issuer (specs/010): with it the service
	// mints `token_exchange` secrets - a token for the caller - by RFC 8693 token exchange.
	Exchange *ExchangeClient `yaml:"exchange"`
}

// ExchangeClient names the service's client at an issuer; its secret comes from the environment, never
// from the file.
type ExchangeClient struct {
	ClientID        string `yaml:"client_id"`
	ClientSecretEnv string `yaml:"client_secret_env"`
	ClientSecret    string `yaml:"-"` // read from ClientSecretEnv at load
}

// ServiceRule marks a token as a service's: Claim is present (and equals Equals, when set); the
// client's name is ClientClaim (default azp).
type ServiceRule struct {
	Claim       string `yaml:"claim"`
	Equals      string `yaml:"equals"`
	ClientClaim string `yaml:"client_claim"`
}

// Policy is the service-level part of the permissions (specs/009): the admins, who alone manage secrets
// and grant their use, and the servers allowed to act for users.
type Policy struct {
	Admins []string `yaml:"admins"`
	// Actors are the servers allowed to act for users (delegation grants). Under a grant `use` is the actor's
	// own (what an admin granted the server); a management verb listed here passes through the server only for
	// a user who is an admin themselves - administration through a duckdb-acl node (specs/009).
	Actors []ActorRule `yaml:"actors"`
	// Create is gone (specs/009): kept only to refuse a config that still has it, with a word on why
	Create any `yaml:"create"`
}

// ActorRule lets a service (a client: principal) act for users with the verbs listed: `use` (its own grants),
// and the management verbs and `create` it may pass on for admins. Issuer, when set, pins the actor to the
// issuer its token must come from: a client: name is not issuer-qualified, and a same-named client of another
// configured issuer must not pass for it.
type ActorRule struct {
	Principal string   `yaml:"principal"`
	Issuer    string   `yaml:"issuer"`
	Verbs     []string `yaml:"verbs"`
}

// Load reads and validates a YAML file.
func Load(file string) (*Config, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse validates a YAML document; unknown keys are an error, not ignored.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &cfg, nil
}

var allowedAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true, "EdDSA": true,
}

// the per-secret verbs (specs/009): `use`, granted to roles and groups; the rest are the admins'
var knownVerbs = map[string]bool{
	"use": true, "update": true, "delete": true, "annotate": true, "grant": true,
}

// KnownVerb says whether v is one of the protocol's per-secret verbs.
func KnownVerb(v string) bool { return knownVerbs[v] }

func (c *Config) validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen %q: %w", c.Listen, err)
	}
	if (c.TLS.Cert == "") != (c.TLS.Key == "") {
		return errors.New("tls needs both cert and key")
	}
	if c.TLS.Cert == "" && !IsLoopback(host) {
		return fmt.Errorf("plain http is allowed only on a loopback listen address, not %q - configure tls", host)
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("public_url %q must be an absolute http(s) URL", c.PublicURL)
	}
	if u.Scheme == "http" && !IsLoopback(u.Hostname()) {
		return fmt.Errorf("public_url %q: http only for a loopback host", c.PublicURL)
	}
	if c.Store.Path != "" && c.Store.KeyEnv == "" {
		return errors.New("store.key_env is required with store.path: the store is always encrypted")
	}
	if c.Store.Path == "" && c.Store.KeyEnv != "" {
		return errors.New("store.key_env without store.path: the store would silently be memory only")
	}
	if len(c.Issuers) == 0 {
		return errors.New("at least one issuer is required")
	}
	seen := map[string]bool{}
	for i := range c.Issuers {
		is := &c.Issuers[i]
		// kept verbatim: an issuer identifier is compared exactly (RFC 8414), and some end in '/'
		// (Auth0, Entra v1); only the lookup key is normalised (IssuerKey)
		if is.Issuer == "" || is.Audience == "" {
			return fmt.Errorf("issuers[%d]: issuer and audience are required", i)
		}
		iu, err := url.Parse(is.Issuer)
		if err != nil || iu.Host == "" || (iu.Scheme != "https" && !(iu.Scheme == "http" && IsLoopback(iu.Hostname()))) {
			// its discovery and JWKS are fetched from here: over plain http anyone on the path could
			// substitute the signing keys
			return fmt.Errorf("issuer %q must be https (http only for a loopback host)", is.Issuer)
		}
		if seen[IssuerKey(is.Issuer)] {
			return fmt.Errorf("issuer %q listed twice", is.Issuer)
		}
		seen[IssuerKey(is.Issuer)] = true
		if len(is.HumanFlows) > 0 && is.ClientID == "" {
			return fmt.Errorf("issuer %q: human_flows need the public client_id people log in with", is.Issuer)
		}
		if is.Service != nil {
			if is.Service.Claim == "" {
				return fmt.Errorf("issuer %q: service.claim is required", is.Issuer)
			}
			if is.Service.ClientClaim == "" {
				is.Service.ClientClaim = "azp"
			}
		}
		if ex := is.Exchange; ex != nil {
			if ex.ClientID == "" || ex.ClientSecretEnv == "" {
				return fmt.Errorf("issuer %q: exchange needs client_id and client_secret_env", is.Issuer)
			}
			if ex.ClientSecret = os.Getenv(ex.ClientSecretEnv); ex.ClientSecret == "" {
				return fmt.Errorf("issuer %q: exchange: the environment variable %s is empty", is.Issuer, ex.ClientSecretEnv)
			}
		}
		if len(is.Algorithms) == 0 {
			is.Algorithms = []string{"RS256", "ES256"}
		}
		for _, alg := range is.Algorithms {
			if !allowedAlgorithms[alg] {
				return fmt.Errorf("issuer %q: algorithm %q is not allowed (asymmetric only)", is.Issuer, alg)
			}
		}
	}
	if c.Policy.Create != nil {
		return errors.New("policy.create is gone (tresor specs/009): only admins create secrets - list them in " +
			"policy.admins")
	}
	for _, p := range c.Policy.Admins {
		if err := checkPrincipal(p); err != nil {
			return fmt.Errorf("policy.admins: %w", err)
		}
	}
	for _, a := range c.Policy.Actors {
		if !strings.HasPrefix(a.Principal, "client:") || len(a.Principal) <= len("client:") {
			return fmt.Errorf("policy.actors: %q - an actor is a service, client:<id>", a.Principal)
		}
		if len(a.Verbs) == 0 {
			return fmt.Errorf("policy.actors: %s lists no verbs - leave it out instead", a.Principal)
		}
		for _, v := range a.Verbs {
			if !KnownVerb(v) && v != "create" {
				return fmt.Errorf("policy.actors: unknown verb %q", v)
			}
		}
	}
	return nil
}

func checkPrincipal(p string) error {
	for _, prefix := range []string{"role:", "group:", "subject:", "client:"} {
		if strings.HasPrefix(p, prefix) && len(p) > len(prefix) {
			return nil
		}
	}
	return fmt.Errorf("principal %q: role:, group:, subject: or client: expected", p)
}

// IssuerKey is how an issuer is looked up by a token's iss: without a trailing '/'.
func IssuerKey(issuer string) string { return strings.TrimRight(issuer, "/") }

// IsLoopback says whether host (a name or an IP) is this machine.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
