package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeDiscoveryURLRequiresWellKnownEndpoint(t *testing.T) {
	t.Parallel()

	if _, err := normalizeDiscoveryURL("https://issuer.example"); err == nil {
		t.Fatalf("expected missing .well-known endpoint to fail")
	}
}

func TestNormalizeDiscoveryURLKeepsWellKnownEndpoint(t *testing.T) {
	t.Parallel()

	got, err := normalizeDiscoveryURL("https://issuer.example/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if got != "https://issuer.example/.well-known/openid-configuration" {
		t.Fatalf("unexpected normalized URL: %q", got)
	}
}

func TestNormalizeDiscoveryURLRejectsInvalidURL(t *testing.T) {
	t.Parallel()

	if _, err := normalizeDiscoveryURL("issuer.example"); err == nil {
		t.Fatalf("expected invalid URL to fail")
	}
}

func TestNormalizeIntrospectionURLRejectsInvalidURL(t *testing.T) {
	t.Parallel()

	if _, err := normalizeIntrospectionURL("issuer.example/introspect"); err == nil {
		t.Fatalf("expected invalid URL to fail")
	}
}

func TestIntrospectAccessTokenWithClientSecretBasic(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			t.Fatalf("expected basic auth")
		}
		if username != "client" || password != "secret" {
			t.Fatalf("unexpected basic auth credentials: %q/%q", username, password)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form failed: %v", err)
		}
		if token := r.FormValue("token"); token != "token-123" {
			t.Fatalf("unexpected token value: %q", token)
		}
		if gotClientID := r.FormValue("client_id"); gotClientID != "" {
			t.Fatalf("did not expect client_id in form for basic auth, got %q", gotClientID)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"client_id":"client"}`))
	}))
	defer server.Close()

	provider := &oidcProvider{
		config: OIDCConfig{
			ClientID:     "client",
			ClientSecret: "secret",
		},
		introspectionURL:        server.URL,
		introspectionAuthMethod: OIDCIntrospectionAuthClientSecretBasic,
	}

	if err := provider.introspectAccessToken(t.Context(), "token-123"); err != nil {
		t.Fatalf("expected introspection to pass, got %v", err)
	}
}

func TestIntrospectAccessTokenWithClientSecretPost(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); ok {
			t.Fatalf("did not expect basic auth for client_secret_post")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form failed: %v", err)
		}
		if gotClientID := r.FormValue("client_id"); gotClientID != "client" {
			t.Fatalf("unexpected client_id in form: %q", gotClientID)
		}
		if gotSecret := r.FormValue("client_secret"); gotSecret != "secret" {
			t.Fatalf("unexpected client_secret in form: %q", gotSecret)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true}`))
	}))
	defer server.Close()

	provider := &oidcProvider{
		config: OIDCConfig{
			ClientID:     "client",
			ClientSecret: "secret",
		},
		introspectionURL:        server.URL,
		introspectionAuthMethod: OIDCIntrospectionAuthClientSecretPost,
	}

	if err := provider.introspectAccessToken(t.Context(), "token-123"); err != nil {
		t.Fatalf("expected introspection to pass, got %v", err)
	}
}

func TestIntrospectAccessTokenRejectsInactiveToken(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	defer server.Close()

	provider := &oidcProvider{
		config: OIDCConfig{
			ClientID:     "client",
			ClientSecret: "secret",
		},
		introspectionURL:        server.URL,
		introspectionAuthMethod: OIDCIntrospectionAuthClientSecretBasic,
	}

	err := provider.introspectAccessToken(t.Context(), "token-123")
	if !errors.Is(err, ErrOIDCAccessTokenInactive) {
		t.Fatalf("expected inactive-token error, got %v", err)
	}
}

func TestIntrospectAccessTokenRejectsClientIDMismatch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"active":true,"client_id":"other-client"}`))
	}))
	defer server.Close()

	provider := &oidcProvider{
		config: OIDCConfig{
			ClientID:     "client",
			ClientSecret: "secret",
		},
		introspectionURL:        server.URL,
		introspectionAuthMethod: OIDCIntrospectionAuthClientSecretBasic,
	}

	err := provider.introspectAccessToken(t.Context(), "token-123")
	if !errors.Is(err, ErrOIDCAccessTokenInvalid) {
		t.Fatalf("expected client-id-mismatch error, got %v", err)
	}
}
