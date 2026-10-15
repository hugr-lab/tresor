package api

// Generated parameters (specs/029): a parameter whose whole value (a JSON string, a VARCHAR) is
// `mint+<kind>://<…>` is generated on every read, for the effective caller - the direct caller, or under a
// delegation grant the grant's user, never the server. The secret is then dynamic; the served value is the
// generated one, its key is added to redact_keys, its expiry bounds expires_at. Kinds here:
//   - mint+exchange://<audience>[?scope=<scope>] - a token for the caller at the identity provider (RFC 8693);
//   - mint+claim://<claim> - a claim of the caller's verified token (its text), never the token.
// A literal beginning with `mint+` is stored with the `+` doubled: `mint++x` is served as `mint+x`.
// `provider: token_exchange` (specs/010) stays an alias: an exchange generator of the type's token param.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hugr-lab/tresor/server/internal/auth"
	"github.com/hugr-lab/tresor/server/internal/store"
)

const generatorPrefix = "mint+"

// generator is one generated parameter: a kind and what it needs.
type generator struct {
	kind     string // "exchange" | "claim"
	audience string // exchange
	scope    string // exchange, optional
	claim    string // claim
}

// parseValue reads a stored string value: a generator, or the literal it stands for. The error names no
// value: a value an administrator wrote may be a secret.
func parseValue(value string) (*generator, string, error) {
	if !strings.HasPrefix(value, generatorPrefix) {
		return nil, value, nil
	}
	rest := value[len(generatorPrefix):]
	if strings.HasPrefix(rest, "+") { // the escape: one `+` dropped
		return nil, generatorPrefix + rest[1:], nil
	}
	kind, body, ok := strings.Cut(rest, "://")
	if !ok {
		return nil, "", errors.New("begins with mint+ but is no mint+<kind>://… generator (a literal is written mint++…)")
	}
	switch kind {
	case "exchange":
		rawAudience, query, _ := strings.Cut(body, "?")
		audience, err := url.PathUnescape(rawAudience)
		if err != nil || audience == "" {
			return nil, "", errors.New("is a mint+exchange:// generator with no audience")
		}
		values, err := url.ParseQuery(query)
		if err != nil {
			return nil, "", errors.New("is a mint+exchange:// generator with a malformed query")
		}
		for key, v := range values {
			if key != "scope" || len(v) != 1 {
				return nil, "", errors.New("is a mint+exchange:// generator: its query is ?scope=<scope> only")
			}
		}
		return &generator{kind: kind, audience: audience, scope: values.Get("scope")}, "", nil
	case "claim":
		if body == "" {
			return nil, "", errors.New("is a mint+claim:// generator with no claim name")
		}
		return &generator{kind: kind, claim: body}, "", nil
	case "login", "rule":
		return nil, "", fmt.Errorf("is a mint+%s:// generator, which this service does not implement", kind)
	default:
		return nil, "", errors.New("is a generator of an unknown kind (mint+exchange://, mint+claim://)")
	}
}

// stringParam is a parameter's value when it is a JSON string (a VARCHAR); a typed value is always literal.
func stringParam(raw json.RawMessage) (string, bool) {
	var str string
	return str, json.Unmarshal(raw, &str) == nil
}

// generatorsOf are a secret's generated parameters, by key: its mint+ values, and the token_exchange alias.
func generatorsOf(typ, provider string, params map[string]json.RawMessage) (map[string]*generator, error) {
	gens := map[string]*generator{}
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys) // the same error for the same secret
	for _, key := range keys {
		str, ok := stringParam(params[key])
		if !ok {
			continue
		}
		gen, _, err := parseValue(str)
		if err != nil {
			return nil, fmt.Errorf("parameter %q %v", key, err)
		}
		if gen != nil {
			gens[key] = gen
		}
	}
	if provider == tokenExchangeProvider {
		if param, ok := tokenParam[strings.ToLower(typ)]; ok {
			audience, scope := mintTarget(params)
			gens[param] = &generator{kind: "exchange", audience: audience, scope: scope}
		}
	}
	return gens, nil
}

// isDynamic: a secret with a generated parameter (one that cannot be read as stored counts too: its read fails).
func isDynamic(sec *store.Secret) bool {
	gens, err := generatorsOf(sec.Type, sec.Provider, sec.Params)
	return err != nil || len(gens) > 0
}

// validGenerators checks a secret's generators at PUT: well formed, and no exchange for this service's own
// audience (a user's token for this service, in a secret sent to another server, could be replayed here).
func (s *Server) validGenerators(typ, provider string, params map[string]json.RawMessage) error {
	gens, err := generatorsOf(typ, provider, params)
	if err != nil {
		return err
	}
	for key, gen := range gens {
		if gen.kind != "exchange" {
			continue
		}
		for _, is := range s.cfg.Issuers {
			if gen.audience == is.Audience {
				return fmt.Errorf("parameter %q exchanges for this service's own audience, never allowed", key)
			}
		}
	}
	return nil
}

// material is a secret's params as the caller receives them: literals unescaped, generated values made for
// the effective caller; the redact keys with every generated key; the earliest expiry of what was generated
// (zero: none named).
func (s *Server) material(r *http.Request, c *auth.Caller, sec *store.Secret) (map[string]json.RawMessage,
	[]string, time.Time, *mintProblem) {
	redact := slices.Clone(sec.RedactKeys)
	if redact == nil {
		redact = []string{}
	}
	gens, err := generatorsOf(sec.Type, sec.Provider, sec.Params)
	if err != nil {
		// stored before generators were checked: never served as it is
		return nil, nil, time.Time{}, &mintProblem{http.StatusInternalServerError, "service_error",
			"the secret cannot be served: " + err.Error()}
	}
	out := make(map[string]json.RawMessage, len(sec.Params)+1)
	for key, raw := range sec.Params {
		if str, ok := stringParam(raw); ok && strings.HasPrefix(str, generatorPrefix) {
			if _, literal, _ := parseValue(str); gens[key] == nil {
				raw, _ = json.Marshal(literal)
			}
		}
		out[key] = raw
	}
	var expires time.Time
	keys := make([]string, 0, len(gens))
	for key := range gens {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, expiry, problem := s.generate(r, c, gens[key])
		if problem != nil {
			return nil, nil, time.Time{}, problem
		}
		if value == "" { // never an empty value in place of what could not be made
			return nil, nil, time.Time{}, refusedMint("parameter " + strconv.Quote(key) + " was generated empty")
		}
		out[key], _ = json.Marshal(value)
		if !slices.Contains(redact, key) {
			redact = append(redact, key)
		}
		if !expiry.IsZero() && (expires.IsZero() || expiry.Before(expires)) {
			expires = expiry
		}
	}
	return out, redact, expires, nil
}

// generate makes one value for the effective caller.
func (s *Server) generate(r *http.Request, c *auth.Caller, gen *generator) (string, time.Time, *mintProblem) {
	switch gen.kind {
	case "exchange":
		token, problem := s.mintedToken(r, c, gen.audience, gen.scope)
		if problem != nil {
			return "", time.Time{}, problem
		}
		return token.Access, token.Expiry, nil
	case "claim":
		value, ok := claimText(c.Claims, gen.claim)
		if !ok {
			return "", time.Time{}, refusedMint("the caller's token carries no text claim " + strconv.Quote(gen.claim))
		}
		// as long as the token it came from (under a grant: the grant)
		return value, c.ExpiresAt, nil
	}
	return "", time.Time{}, refusedMint("an unknown generator")
}

// claimText is a top-level claim as text: a string as it is, a number or a boolean as its JSON text; a list,
// an object, null, an empty string or no claim at all is none.
func claimText(claims map[string]any, name string) (string, bool) {
	switch v := claims[name].(type) {
	case string:
		return v, v != ""
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case json.Number:
		return v.String(), true
	case bool:
		return strconv.FormatBool(v), true
	}
	return "", false
}
