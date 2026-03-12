package auth

import "testing"

func TestOIDCConfigEnabledRequiresDiscoveryURL(t *testing.T) {
	t.Parallel()

	config := OIDCConfig{
		DiscoveryURL:     "https://issuer.example/.well-known/openid-configuration",
		IntrospectionURL: "https://issuer.example/introspect",
		ClientID:         "client",
		RedirectURL:      "http://localhost:8080/auth/oidc/callback",
	}

	if !config.Enabled() {
		t.Fatalf("expected config to be enabled when discovery URL is set")
	}
}

func TestOIDCConfigDisabledWithoutDiscoveryURL(t *testing.T) {
	t.Parallel()

	config := OIDCConfig{
		IssuerURL:        "https://issuer.example",
		IntrospectionURL: "https://issuer.example/introspect",
		ClientID:         "client",
		RedirectURL:      "http://localhost:8080/auth/oidc/callback",
	}
	if config.Enabled() {
		t.Fatalf("expected config to be disabled without discovery URL")
	}
}

func TestLoadOIDCConfigFromEnvIncludesIssuerURL(t *testing.T) {
	t.Setenv("GO_PDNS_UI_OIDC_DISCOVERY_URL", "https://discovery.example/.well-known/openid-configuration")
	t.Setenv("GO_PDNS_UI_OIDC_ISSUER_URL", "https://issuer.example")
	t.Setenv("GO_PDNS_UI_OIDC_INTROSPECTION_URL", "https://issuer.example/oauth2/introspect")
	t.Setenv("GO_PDNS_UI_OIDC_INTROSPECTION_AUTH_METHOD", "client_secret_post")
	t.Setenv("GO_PDNS_UI_OIDC_INSECURE_SKIP_VERIFY", "true")
	t.Setenv("GO_PDNS_UI_OIDC_CLIENT_ID", "client")
	t.Setenv("GO_PDNS_UI_OIDC_CLIENT_SECRET", "secret")
	t.Setenv("GO_PDNS_UI_OIDC_REDIRECT_URL", "http://localhost:8080/auth/oidc/callback")

	config := LoadOIDCConfigFromEnv()

	if config.DiscoveryURL != "https://discovery.example/.well-known/openid-configuration" {
		t.Fatalf("unexpected discovery URL: %q", config.DiscoveryURL)
	}
	if config.IssuerURL != "https://issuer.example" {
		t.Fatalf("unexpected issuer URL: %q", config.IssuerURL)
	}
	if config.IntrospectionURL != "https://issuer.example/oauth2/introspect" {
		t.Fatalf("unexpected introspection URL: %q", config.IntrospectionURL)
	}
	if config.IntrospectionAuth != "client_secret_post" {
		t.Fatalf("unexpected introspection auth method: %q", config.IntrospectionAuth)
	}
	if !config.InsecureSkipVerify {
		t.Fatalf("expected insecure skip verify to be enabled")
	}
}

func TestOIDCConfigValidateRejectsInvalidIntrospectionMethod(t *testing.T) {
	t.Parallel()

	config := OIDCConfig{
		IntrospectionAuth: "private_key_jwt",
		ClientSecret:      "secret",
	}
	if err := config.validate(); err == nil {
		t.Fatalf("expected config validation to fail for invalid introspection method")
	}
}
