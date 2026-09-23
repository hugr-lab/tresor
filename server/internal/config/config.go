// Package config reads and validates the reference server's configuration (specs/003).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
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
}

// Policy is the service-level part of the permissions: admins and who may create what.
type Policy struct {
	Admins []string     `yaml:"admins"`
	Create []CreateRule `yaml:"create"`
}

// CreateRule lets a principal create secrets whose names match one of the patterns (path.Match).
type CreateRule struct {
	Principal string   `yaml:"principal"`
	Names     []string `yaml:"names"`
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

var knownVerbs = map[string]bool{
	"use": true, "update": true, "delete": true, "annotate": true, "grant": true, "delegate": true,
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
	if len(c.Issuers) == 0 {
		return errors.New("at least one issuer is required")
	}
	seen := map[string]bool{}
	for i := range c.Issuers {
		is := &c.Issuers[i]
		is.Issuer = strings.TrimRight(is.Issuer, "/")
		if is.Issuer == "" || is.Audience == "" {
			return fmt.Errorf("issuers[%d]: issuer and audience are required", i)
		}
		if seen[is.Issuer] {
			return fmt.Errorf("issuer %q listed twice", is.Issuer)
		}
		seen[is.Issuer] = true
		if len(is.Algorithms) == 0 {
			is.Algorithms = []string{"RS256", "ES256"}
		}
		for _, alg := range is.Algorithms {
			if !allowedAlgorithms[alg] {
				return fmt.Errorf("issuer %q: algorithm %q is not allowed (asymmetric only)", is.Issuer, alg)
			}
		}
	}
	for _, p := range c.Policy.Admins {
		if err := checkPrincipal(p); err != nil {
			return fmt.Errorf("policy.admins: %w", err)
		}
	}
	for _, r := range c.Policy.Create {
		if err := checkPrincipal(r.Principal); err != nil {
			return fmt.Errorf("policy.create: %w", err)
		}
		for _, n := range r.Names {
			if _, err := path.Match(n, ""); err != nil {
				return fmt.Errorf("policy.create: bad pattern %q", n)
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

// IsLoopback says whether host (a name or an IP) is this machine.
func IsLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
