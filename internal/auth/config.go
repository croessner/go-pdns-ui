package auth

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

type OIDCConfig struct {
	DiscoveryURL       string
	IssuerURL          string
	IntrospectionURL   string
	IntrospectionAuth  string
	InsecureSkipVerify bool
	ClientID           string
	ClientSecret       string
	RedirectURL        string
	Scopes             []string
	AdminGroup         string
	UserGroup          string
}

func (c OIDCConfig) Enabled() bool {
	return c.DiscoveryURL != "" && c.ClientID != "" && c.RedirectURL != "" && c.IntrospectionURL != ""
}

func LoadOIDCConfigFromEnv() OIDCConfig {
	scopes := splitScopes(getenvOrDefault("GO_PDNS_UI_OIDC_SCOPES", "openid profile email groups"))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "groups"}
	}

	return OIDCConfig{
		DiscoveryURL:       strings.TrimSpace(os.Getenv("GO_PDNS_UI_OIDC_DISCOVERY_URL")),
		IssuerURL:          strings.TrimSpace(os.Getenv("GO_PDNS_UI_OIDC_ISSUER_URL")),
		IntrospectionURL:   strings.TrimSpace(os.Getenv("GO_PDNS_UI_OIDC_INTROSPECTION_URL")),
		IntrospectionAuth:  getenvOrDefault("GO_PDNS_UI_OIDC_INTROSPECTION_AUTH_METHOD", OIDCIntrospectionAuthClientSecretBasic),
		InsecureSkipVerify: getenvBool("GO_PDNS_UI_OIDC_INSECURE_SKIP_VERIFY"),
		ClientID:           strings.TrimSpace(os.Getenv("GO_PDNS_UI_OIDC_CLIENT_ID")),
		ClientSecret:       strings.TrimSpace(os.Getenv("GO_PDNS_UI_OIDC_CLIENT_SECRET")),
		RedirectURL:        strings.TrimSpace(os.Getenv("GO_PDNS_UI_OIDC_REDIRECT_URL")),
		Scopes:             scopes,
		AdminGroup:         getenvOrDefault("GO_PDNS_UI_OIDC_ADMIN_GROUP", "admin"),
		UserGroup:          getenvOrDefault("GO_PDNS_UI_OIDC_USER_GROUP", "user"),
	}
}

func (c OIDCConfig) effectiveIntrospectionAuthMethod() string {
	method := strings.ToLower(strings.TrimSpace(c.IntrospectionAuth))
	if method == "" {
		return OIDCIntrospectionAuthClientSecretBasic
	}
	return method
}

func (c OIDCConfig) validate() error {
	method := c.effectiveIntrospectionAuthMethod()
	switch method {
	case OIDCIntrospectionAuthClientSecretBasic, OIDCIntrospectionAuthClientSecretPost:
	default:
		return errors.New("invalid oidc introspection auth method")
	}

	if c.ClientSecret == "" {
		return errors.New("oidc client secret is required for token introspection")
	}

	return nil
}

func splitScopes(value string) []string {
	fields := strings.Fields(strings.ReplaceAll(value, ",", " "))
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		trimmed := strings.TrimSpace(field)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func getenvOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getenvBool(key string) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return false
	}

	parsedValue, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}

	return parsedValue
}
