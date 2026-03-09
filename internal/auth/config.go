package auth

import (
	"os"
	"strings"
)

type OIDCConfig struct {
	DiscoveryURL string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AdminGroup   string
	UserGroup    string
}

func (c OIDCConfig) Enabled() bool {
	return c.DiscoveryURL != "" && c.ClientID != "" && c.RedirectURL != ""
}

func LoadOIDCConfigFromEnv() OIDCConfig {
	scopes := splitScopes(getenvOrDefault("GO_PDNS_UI_OIDC_SCOPES", "openid profile email groups"))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "groups"}
	}

	return OIDCConfig{
		DiscoveryURL: strings.TrimSpace(os.Getenv("GO_PDNS_UI_OIDC_DISCOVERY_URL")),
		ClientID:     strings.TrimSpace(os.Getenv("GO_PDNS_UI_OIDC_CLIENT_ID")),
		ClientSecret: strings.TrimSpace(os.Getenv("GO_PDNS_UI_OIDC_CLIENT_SECRET")),
		RedirectURL:  strings.TrimSpace(os.Getenv("GO_PDNS_UI_OIDC_REDIRECT_URL")),
		Scopes:       scopes,
		AdminGroup:   getenvOrDefault("GO_PDNS_UI_OIDC_ADMIN_GROUP", "admin"),
		UserGroup:    getenvOrDefault("GO_PDNS_UI_OIDC_USER_GROUP", "user"),
	}
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
