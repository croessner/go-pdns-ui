package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrOIDCNotConfigured  = errors.New("oidc is not configured")
	ErrOIDCStateInvalid   = errors.New("invalid oidc state")
	ErrOIDCNonceInvalid   = errors.New("invalid oidc nonce")
	ErrOIDCGroupsRejected = errors.New("oidc groups do not map to any role")
)

type oidcProvider struct {
	config   OIDCConfig
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

type oidcFlow struct {
	Verifier string
	Nonce    string
	Expires  time.Time
}

type oidcClaims struct {
	Subject           string      `json:"sub"`
	Name              string      `json:"name"`
	PreferredUsername string      `json:"preferred_username"`
	Email             string      `json:"email"`
	Groups            interface{} `json:"groups"`
	Nonce             string      `json:"nonce"`
}

func newOIDCProvider(ctx context.Context, config OIDCConfig) (*oidcProvider, error) {
	if !config.Enabled() {
		return nil, nil
	}

	provider, err := oidc.NewProvider(ctx, config.DiscoveryURL)
	if err != nil {
		return nil, fmt.Errorf("initialize oidc provider: %w", err)
	}

	oauthConfig := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.Scopes,
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	return &oidcProvider{
		config:   config,
		oauth2:   oauthConfig,
		verifier: verifier,
	}, nil
}

func (p *oidcProvider) authCodeURL(state, nonce, codeChallenge string) string {
	return p.oauth2.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (p *oidcProvider) exchange(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	token, err := p.oauth2.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidc token exchange failed: %w", err)
	}
	return token, nil
}

func (p *oidcProvider) verifyIDToken(ctx context.Context, rawIDToken string) (*oidcClaims, error) {
	verifiedToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id token: %w", err)
	}

	claims := &oidcClaims{}
	if err := verifiedToken.Claims(claims); err != nil {
		return nil, fmt.Errorf("decode id token claims: %w", err)
	}

	return claims, nil
}

func buildPKCEChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func mapGroupsToRole(groups []string, adminGroup, userGroup string) (Role, error) {
	adminGroup = strings.TrimSpace(adminGroup)
	userGroup = strings.TrimSpace(userGroup)

	normalized := make([]string, 0, len(groups))
	for _, group := range groups {
		g := strings.TrimSpace(strings.ToLower(group))
		if g != "" {
			normalized = append(normalized, g)
		}
	}

	if len(normalized) == 0 {
		return RoleUser, nil
	}

	if adminGroup != "" && slices.Contains(normalized, strings.ToLower(adminGroup)) {
		return RoleAdmin, nil
	}

	if userGroup != "" && slices.Contains(normalized, strings.ToLower(userGroup)) {
		return RoleUser, nil
	}

	return "", ErrOIDCGroupsRejected
}

func parseGroups(raw interface{}) []string {
	switch value := raw.(type) {
	case []interface{}:
		result := make([]string, 0, len(value))
		for _, entry := range value {
			if group, ok := entry.(string); ok {
				group = strings.TrimSpace(group)
				if group != "" {
					result = append(result, group)
				}
			}
		}
		return result
	case []string:
		result := make([]string, 0, len(value))
		for _, group := range value {
			group = strings.TrimSpace(group)
			if group != "" {
				result = append(result, group)
			}
		}
		return result
	case string:
		return splitScopes(value)
	default:
		return nil
	}
}
