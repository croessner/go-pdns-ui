package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestResolveIntrospectionURLPrefersConfig(t *testing.T) {
	t.Parallel()

	introspectionURL, source, err := resolveIntrospectionURL("https://config.example/introspect", "https://discovery.example/introspect")
	if err != nil {
		t.Fatalf("expected config URL to resolve, got %v", err)
	}
	if introspectionURL != "https://config.example/introspect" {
		t.Fatalf("unexpected introspection URL: %q", introspectionURL)
	}
	if source != "config" {
		t.Fatalf("unexpected source: %q", source)
	}
}

func TestResolveIntrospectionURLFallsBackToDiscovery(t *testing.T) {
	t.Parallel()

	introspectionURL, source, err := resolveIntrospectionURL("", "https://discovery.example/introspect")
	if err != nil {
		t.Fatalf("expected discovery URL to resolve, got %v", err)
	}
	if introspectionURL != "https://discovery.example/introspect" {
		t.Fatalf("unexpected introspection URL: %q", introspectionURL)
	}
	if source != "discovery" {
		t.Fatalf("unexpected source: %q", source)
	}
}

func TestResolveIntrospectionURLFailsWhenMissingEverywhere(t *testing.T) {
	t.Parallel()

	if _, _, err := resolveIntrospectionURL("", ""); err == nil {
		t.Fatalf("expected missing introspection endpoint to fail")
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

func TestOIDCLogoutURLIncludesIDTokenHint(t *testing.T) {
	t.Parallel()

	provider := &oidcProvider{
		config:        OIDCConfig{ClientID: "client"},
		endSessionURL: "https://issuer.example/logout",
	}

	logoutURL, ok := provider.logoutURL("https://app.example/login", "id-token-123")
	if !ok {
		t.Fatalf("expected logout URL to be available")
	}

	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("parse logout URL failed: %v", err)
	}
	query := parsedURL.Query()
	if got := query.Get("post_logout_redirect_uri"); got != "https://app.example/login" {
		t.Fatalf("unexpected post logout redirect URL: %q", got)
	}
	if got := query.Get("id_token_hint"); got != "id-token-123" {
		t.Fatalf("unexpected id_token_hint: %q", got)
	}
	if got := query.Get("client_id"); got != "" {
		t.Fatalf("did not expect client_id when id_token_hint is present, got %q", got)
	}
}

func TestOIDCLogoutURLFallsBackToClientIDWithoutIDTokenHint(t *testing.T) {
	t.Parallel()

	provider := &oidcProvider{
		config:        OIDCConfig{ClientID: "client"},
		endSessionURL: "https://issuer.example/logout",
	}

	logoutURL, ok := provider.logoutURL("https://app.example/login", "")
	if !ok {
		t.Fatalf("expected logout URL to be available")
	}

	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("parse logout URL failed: %v", err)
	}
	query := parsedURL.Query()
	if got := query.Get("client_id"); got != "client" {
		t.Fatalf("unexpected client_id: %q", got)
	}
}
