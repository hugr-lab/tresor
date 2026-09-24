// Package mint obtains tokens for a caller at its identity provider (specs/010): RFC 8693 token exchange of
// the caller's token for a downstream audience, and refreshes. It never logs or returns a token in an error.
package mint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// sharedHTTP is every mint's client: one connection pool, bounded requests.
var sharedHTTP = &http.Client{Timeout: timeout}

const (
	accessTokenType  = "urn:ietf:params:oauth:token-type:access_token"
	refreshTokenType = "urn:ietf:params:oauth:token-type:refresh_token"
	timeout          = 15 * time.Second
)

// Client is the service's own confidential client at one issuer's token endpoint.
type Client struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	HTTP         *http.Client // nil: a client bounded by the timeout
	Now          func() time.Time
}

// Token is a minted access token, and the refresh token that renews it when one was asked for.
type Token struct {
	Access  string
	Refresh string
	Expiry  time.Time // zero: the IdP named none
}

// Error is the IdP's refusal: its code (invalid_grant: the user's session is over) and a description with
// no token in it.
type Error struct {
	Code        string
	Description string
	Status      int // the HTTP status; 0 when the IdP did not answer (Code "unreachable")
}

// Transient: the IdP did not answer, or failed (5xx) - worth another try, unlike a refusal.
func (e *Error) Transient() bool { return e.Status == 0 || e.Status >= 500 }

func (e *Error) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// IsInvalidGrant: the refresh token (or the subject token) is dead - the user's IdP session ended.
func IsInvalidGrant(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == "invalid_grant"
}

// IsUnsupported: the IdP does not issue refresh tokens by exchange ("requested_token_type unsupported").
func IsUnsupported(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == "invalid_request" && strings.Contains(e.Description, "requested_token_type")
}

// Exchange trades `subject` (an access token issued for this service) for one meant for `audience`; with
// `withRefresh` a refresh token too (Keycloak issues one only when asked with requested_token_type).
func (c *Client) Exchange(ctx context.Context, subject, audience, scope string, withRefresh bool) (*Token, error) {
	if subject == "" || audience == "" {
		return nil, &Error{Code: "invalid_request", Description: "a subject token and an audience are required"}
	}
	requested := accessTokenType
	if withRefresh {
		requested = refreshTokenType
	}
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {subject},
		"subject_token_type":   {accessTokenType},
		"requested_token_type": {requested},
		"audience":             {audience},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	return c.post(ctx, form, subject, withRefresh)
}

// Refresh renews a token from its refresh token; a rotated refresh token comes back, or the old one stays.
func (c *Client) Refresh(ctx context.Context, refresh string) (*Token, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	token, err := c.post(ctx, form, refresh, true)
	if err == nil && token.Refresh == "" {
		token.Refresh = refresh // RFC 6749 §6: the IdP may keep the old one
	}
	return token, err
}

func (c *Client) post(ctx context.Context, form url.Values, presented string, keepRefresh bool) (*Token, error) {
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret) // client_secret_post, as every tresor flow
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = sharedHTTP
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("the token endpoint: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := httpClient.Do(req)
	if err != nil {
		// the transport's error could name the URL only: a fixed text
		return nil, &Error{Code: "unreachable", Description: "the identity provider is not reachable"}
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var answer struct {
		AccessToken     string `json:"access_token"`
		RefreshToken    string `json:"refresh_token"`
		ExpiresIn       int64  `json:"expires_in"`
		IssuedTokenType string `json:"issued_token_type"`
		TokenType       string `json:"token_type"`
		Error           string `json:"error"`
		ErrorDesc       string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &answer)
	if res.StatusCode/100 != 2 {
		code := answer.Error
		if code == "" {
			code = fmt.Sprintf("http_%d", res.StatusCode)
		}
		// redacted before it is cut: a cut must not leave part of the token behind
		return nil, &Error{Code: bounded(code, 64), Description: bounded(redact(answer.ErrorDesc, presented), 300),
			Status: res.StatusCode}
	}
	// only an access token is taken for one: RFC 8693's strict shape (a refresh token in access_token,
	// token_type N_A), or any other issued type, is refused
	typeOK := answer.IssuedTokenType == "" || answer.IssuedTokenType == accessTokenType ||
		(keepRefresh && answer.IssuedTokenType == refreshTokenType && answer.RefreshToken != "" &&
			answer.RefreshToken != answer.AccessToken)
	if answer.AccessToken == "" || !typeOK || strings.EqualFold(answer.TokenType, "N_A") {
		return nil, &Error{Code: "invalid_token_type", Description: "the identity provider answered with no access token",
			Status: res.StatusCode}
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	token := &Token{Access: answer.AccessToken}
	if keepRefresh {
		token.Refresh = answer.RefreshToken
	}
	if answer.ExpiresIn > 0 {
		if answer.ExpiresIn > 366*24*3600 {
			answer.ExpiresIn = 366 * 24 * 3600
		}
		token.Expiry = now().Add(time.Duration(answer.ExpiresIn) * time.Second)
	}
	return token, nil
}

// bounded keeps an IdP's text printable and short.
func bounded(text string, max int) string {
	var out strings.Builder
	for _, r := range text {
		if out.Len() >= max {
			break
		}
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		out.WriteRune(r)
	}
	return out.String()
}

// redact keeps a credential the caller presented out of an error, even when the IdP quotes it back.
func redact(text, presented string) string {
	if len(presented) < 8 { // no credential is this short; a short value would cut ordinary words apart
		return text
	}
	return strings.ReplaceAll(text, presented, "<redacted>")
}

// Audiences reads a JWT's `aud` without verifying it (the token came from the IdP over its own channel) - to
// check where a minted token is meant to go; isJWT false for an opaque token.
func Audiences(token string) (auds []string, isJWT bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims struct {
		Aud any `json:"aud"`
	}
	if json.Unmarshal(data, &claims) != nil {
		return nil, false
	}
	switch aud := claims.Aud.(type) {
	case string:
		return []string{aud}, true
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				auds = append(auds, s)
			}
		}
	}
	return auds, true
}
