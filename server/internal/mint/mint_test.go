package mint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serve(t *testing.T, status int, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &Client{TokenURL: srv.URL, ClientID: "c", ClientSecret: "s"}
}

func TestShapes(t *testing.T) {
	ctx := context.Background()
	ok := serve(t, 200, `{"access_token":"a","refresh_token":"r","expires_in":60,"issued_token_type":"urn:ietf:params:oauth:token-type:refresh_token"}`)
	if tok, err := ok.Exchange(ctx, "subj", "aud", "", true); err != nil || tok.Access != "a" || tok.Refresh != "r" || tok.Expiry.IsZero() {
		t.Fatalf("Keycloak's shape: %v %v", tok, err)
	}
	if tok, err := ok.Exchange(ctx, "subj", "aud", "", false); err == nil {
		t.Fatalf("a refresh-typed answer not asked for: %v", tok)
	}
	for name, body := range map[string]string{
		"RFC 8693's strict shape": `{"access_token":"rt","issued_token_type":"urn:ietf:params:oauth:token-type:refresh_token","token_type":"N_A"}`,
		"a refresh token twice":   `{"access_token":"rt","refresh_token":"rt","issued_token_type":"urn:ietf:params:oauth:token-type:refresh_token"}`,
		"N_A":                     `{"access_token":"x","token_type":"N_A"}`,
		"an id token":             `{"access_token":"x","issued_token_type":"urn:ietf:params:oauth:token-type:id_token"}`,
		"no token":                `{}`,
	} {
		if tok, err := serve(t, 200, body).Exchange(ctx, "subj", "aud", "", true); err == nil {
			t.Errorf("%s: taken as an access token: %v", name, tok)
		}
	}
}

func TestRefusalsNameNoToken(t *testing.T) {
	ctx := context.Background()
	quoting := serve(t, 400, `{"error":"invalid_grant","error_description":"token secret-subject-token is not active"}`)
	_, err := quoting.Exchange(ctx, "secret-subject-token", "aud", "", false)
	if !IsInvalidGrant(err) || strings.Contains(err.Error(), "secret-subject-token") {
		t.Fatalf("exchange refusal: %v", err)
	}
	_, err = serve(t, 400, `{"error":"invalid_grant","error_description":"secret-refresh is dead"}`).Refresh(ctx, "secret-refresh")
	if !IsInvalidGrant(err) || strings.Contains(err.Error(), "secret-refresh") {
		t.Fatalf("refresh refusal: %v", err)
	}
	_, err = serve(t, 400, `{"error":"invalid_request","error_description":"requested_token_type unsupported"}`).Exchange(ctx, "s", "a", "", true)
	if !IsUnsupported(err) {
		t.Fatalf("unsupported: %v", err)
	}
	if _, err := (&Client{TokenURL: "http://127.0.0.1:1/token"}).Exchange(ctx, "s", "a", "", false); err == nil ||
		strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("unreachable, and the error names nothing: %v", err)
	}
}
