package auth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrOIDCNotConfigured       = errors.New("oidc is not configured")
	ErrOIDCStateInvalid        = errors.New("invalid oidc state")
	ErrOIDCNonceInvalid        = errors.New("invalid oidc nonce")
	ErrOIDCAccessTokenInactive = errors.New("oidc access token is not active")
	ErrOIDCAccessTokenInvalid  = errors.New("oidc access token is not valid for this application")
	ErrOIDCGroupsRejected      = errors.New("oidc groups do not map to any role")
)

const (
	OIDCIntrospectionAuthClientSecretBasic = "client_secret_basic"
	OIDCIntrospectionAuthClientSecretPost  = "client_secret_post"
)

type oidcProvider struct {
	config                  OIDCConfig
	oauth2                  oauth2.Config
	verifier                *oidc.IDTokenVerifier
	httpClient              *http.Client
	introspectionURL        string
	endSessionURL           string
	introspectionAuthMethod string
	logger                  *slog.Logger
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

type oidcIntrospectionResponse struct {
	Active   bool   `json:"active"`
	ClientID string `json:"client_id"`
}

type oidcDiscoveryDocument struct {
	oidc.ProviderConfig
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

func newOIDCProvider(ctx context.Context, config OIDCConfig, logger *slog.Logger) (*oidcProvider, error) {
	if !config.Enabled() {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("initialize oidc provider: %w", err)
	}

	discoveryURL, err := normalizeDiscoveryURL(config.DiscoveryURL)
	if err != nil {
		return nil, fmt.Errorf("initialize oidc provider: %w", err)
	}

	httpClient := newOIDCHTTPClient(config.InsecureSkipVerify)
	provider, discoveredIntrospectionURL, discoveredEndSessionURL, err := loadProviderFromDiscovery(ctx, discoveryURL, config.IssuerURL, httpClient, logger)
	if err != nil {
		return nil, fmt.Errorf("initialize oidc provider: %w", err)
	}
	introspectionURL, introspectionSource, err := resolveIntrospectionURL(config.IntrospectionURL, discoveredIntrospectionURL)
	if err != nil {
		return nil, fmt.Errorf("initialize oidc provider: %w", err)
	}
	endSessionURL, err := normalizeOptionalURL(discoveredEndSessionURL, "end-session URL")
	if err != nil {
		return nil, fmt.Errorf("initialize oidc provider: %w", err)
	}
	logger.Info(
		"oidc_endpoints_resolved",
		"introspection_source", introspectionSource,
		"introspection_url", introspectionURL,
		"end_session_url", endSessionURL,
	)

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
		config:                  config,
		oauth2:                  oauthConfig,
		verifier:                verifier,
		httpClient:              httpClient,
		introspectionURL:        introspectionURL,
		endSessionURL:           endSessionURL,
		introspectionAuthMethod: config.effectiveIntrospectionAuthMethod(),
		logger:                  logger,
	}, nil
}

func normalizeDiscoveryURL(rawURL string) (string, error) {
	const wellKnownSuffix = "/.well-known/openid-configuration"

	parsedURL, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("parse discovery URL: %w", err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return "", errors.New("discovery URL must include scheme and host")
	}
	if !strings.HasSuffix(parsedURL.Path, wellKnownSuffix) {
		return "", errors.New("discovery URL must end with /.well-known/openid-configuration")
	}

	return parsedURL.String(), nil
}

func normalizeIntrospectionURL(rawURL string) (string, error) {
	endpointURL, err := normalizeOptionalURL(rawURL, "introspection URL")
	if err != nil {
		return "", err
	}
	if endpointURL == "" {
		return "", errors.New("introspection URL must include scheme and host")
	}
	return endpointURL, nil
}

func resolveIntrospectionURL(configURL, discoveredURL string) (string, string, error) {
	if strings.TrimSpace(configURL) != "" {
		introspectionURL, err := normalizeIntrospectionURL(configURL)
		if err != nil {
			return "", "", err
		}
		return introspectionURL, "config", nil
	}

	if strings.TrimSpace(discoveredURL) != "" {
		introspectionURL, err := normalizeIntrospectionURL(discoveredURL)
		if err != nil {
			return "", "", err
		}
		return introspectionURL, "discovery", nil
	}

	return "", "", errors.New("oidc introspection endpoint missing in config and discovery metadata")
}

func normalizeOptionalURL(rawURL, endpointName string) (string, error) {
	trimmedURL := strings.TrimSpace(rawURL)
	if trimmedURL == "" {
		return "", nil
	}

	parsedURL, err := url.Parse(trimmedURL)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", endpointName, err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return "", fmt.Errorf("%s must include scheme and host", endpointName)
	}

	return parsedURL.String(), nil
}

func loadProviderFromDiscovery(ctx context.Context, discoveryURL, issuerOverride string, httpClient *http.Client, logger *slog.Logger) (*oidc.Provider, string, string, error) {
	client := http.DefaultClient
	providerCtx := ctx
	if httpClient != nil {
		client = httpClient
		providerCtx = oidc.ClientContext(ctx, httpClient)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("build oidc discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	started := time.Now()
	resp, err := client.Do(req)
	durationMs := time.Since(started).Milliseconds()
	if err != nil {
		logger.Error("oidc_discovery_request_failed", "discovery_url", discoveryURL, "duration_ms", durationMs, "error", err)
		return nil, "", "", fmt.Errorf("oidc discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("oidc_discovery_read_failed", "discovery_url", discoveryURL, "duration_ms", durationMs, "error", err)
		return nil, "", "", fmt.Errorf("read oidc discovery response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		logger.Error("oidc_discovery_http_error", "discovery_url", discoveryURL, "status", resp.StatusCode, "duration_ms", durationMs, "body", msg)
		return nil, "", "", fmt.Errorf("oidc discovery failed with status %d", resp.StatusCode)
	}

	var discoveryDocument oidcDiscoveryDocument
	if err := json.Unmarshal(body, &discoveryDocument); err != nil {
		logger.Error("oidc_discovery_decode_failed", "discovery_url", discoveryURL, "duration_ms", durationMs, "error", err)
		return nil, "", "", fmt.Errorf("decode oidc discovery response: %w", err)
	}
	providerConfig := discoveryDocument.ProviderConfig

	if strings.TrimSpace(providerConfig.IssuerURL) == "" || strings.TrimSpace(providerConfig.AuthURL) == "" ||
		strings.TrimSpace(providerConfig.TokenURL) == "" || strings.TrimSpace(providerConfig.JWKSURL) == "" {
		return nil, "", "", errors.New("oidc discovery response is missing required endpoints")
	}

	override := strings.TrimSpace(issuerOverride)
	if override != "" {
		discoveryIssuer := strings.TrimSpace(providerConfig.IssuerURL)
		if strings.EqualFold(discoveryIssuer, override) {
			logger.Info(
				"oidc_issuer_override_matches_discovery",
				"discovery_issuer", providerConfig.IssuerURL,
				"issuer_override", override,
			)
		} else {
			logger.Warn(
				"oidc_issuer_override_configured",
				"discovery_issuer", providerConfig.IssuerURL,
				"issuer_override", override,
			)
		}
		providerConfig.IssuerURL = override
	}

	logger.Info(
		"oidc_discovery_loaded",
		"discovery_url", discoveryURL,
		"issuer", providerConfig.IssuerURL,
		"introspection_endpoint", strings.TrimSpace(discoveryDocument.IntrospectionEndpoint),
		"end_session_endpoint", strings.TrimSpace(discoveryDocument.EndSessionEndpoint),
		"duration_ms", durationMs,
	)

	return providerConfig.NewProvider(providerCtx), discoveryDocument.IntrospectionEndpoint, discoveryDocument.EndSessionEndpoint, nil
}

func newOIDCHTTPClient(insecureSkipVerify bool) *http.Client {
	if !insecureSkipVerify {
		return nil
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok || transport == nil {
		return nil
	}

	clone := transport.Clone()
	if clone.TLSClientConfig != nil {
		clone.TLSClientConfig = clone.TLSClientConfig.Clone()
	} else {
		clone.TLSClientConfig = &tls.Config{}
	}
	clone.TLSClientConfig.InsecureSkipVerify = true

	return &http.Client{
		Transport: clone,
	}
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
	if p.httpClient != nil {
		ctx = oidc.ClientContext(ctx, p.httpClient)
	}

	token, err := p.oauth2.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidc token exchange failed: %w", err)
	}
	return token, nil
}

func (p *oidcProvider) verifyIDToken(ctx context.Context, rawIDToken string) (*oidcClaims, error) {
	if p.httpClient != nil {
		ctx = oidc.ClientContext(ctx, p.httpClient)
	}

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

func (p *oidcProvider) introspectAccessToken(ctx context.Context, accessToken string) error {
	logger := p.logger
	if logger == nil {
		logger = slog.Default()
	}

	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return ErrOIDCAccessTokenInactive
	}

	form := url.Values{}
	form.Set("token", accessToken)
	form.Set("token_type_hint", "access_token")

	switch p.introspectionAuthMethod {
	case OIDCIntrospectionAuthClientSecretPost:
		form.Set("client_id", p.config.ClientID)
		form.Set("client_secret", p.config.ClientSecret)
	case OIDCIntrospectionAuthClientSecretBasic:
	default:
		return fmt.Errorf("unsupported oidc introspection auth method %q", p.introspectionAuthMethod)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.introspectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build oidc introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.introspectionAuthMethod == OIDCIntrospectionAuthClientSecretBasic {
		req.SetBasicAuth(p.config.ClientID, p.config.ClientSecret)
	}

	client := http.DefaultClient
	if p.httpClient != nil {
		client = p.httpClient
	}

	started := time.Now()
	resp, err := client.Do(req)
	durationMS := time.Since(started).Milliseconds()
	if err != nil {
		logger.Error("oidc_introspection_request_failed", "duration_ms", durationMS, "error", err)
		return fmt.Errorf("oidc introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("oidc_introspection_read_failed", "status", resp.StatusCode, "duration_ms", durationMS, "error", err)
		return fmt.Errorf("read oidc introspection response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		logger.Warn("oidc_introspection_http_error", "status", resp.StatusCode, "duration_ms", durationMS, "body", msg)
		return fmt.Errorf("oidc introspection failed with status %d", resp.StatusCode)
	}

	var introspection oidcIntrospectionResponse
	if err := json.Unmarshal(body, &introspection); err != nil {
		logger.Error("oidc_introspection_decode_failed", "duration_ms", durationMS, "error", err)
		return fmt.Errorf("decode oidc introspection response: %w", err)
	}

	if !introspection.Active {
		logger.Warn("oidc_introspection_inactive_token", "duration_ms", durationMS)
		return ErrOIDCAccessTokenInactive
	}

	if introspection.ClientID != "" && introspection.ClientID != p.config.ClientID {
		logger.Warn(
			"oidc_introspection_client_id_mismatch",
			"duration_ms", durationMS,
			"expected_client_id", p.config.ClientID,
			"token_client_id", introspection.ClientID,
		)
		return ErrOIDCAccessTokenInvalid
	}

	logger.Info("oidc_introspection_succeeded", "duration_ms", durationMS)
	return nil
}

func (p *oidcProvider) logoutURL(postLogoutRedirectURL, idTokenHint string) (string, bool) {
	endSessionURL := strings.TrimSpace(p.endSessionURL)
	if endSessionURL == "" {
		return "", false
	}

	parsedURL, err := url.Parse(endSessionURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		if p.logger != nil {
			p.logger.Warn("oidc_end_session_endpoint_invalid", "end_session_url", endSessionURL, "error", err)
		}
		return "", false
	}

	query := parsedURL.Query()
	if redirectURL := strings.TrimSpace(postLogoutRedirectURL); redirectURL != "" {
		query.Set("post_logout_redirect_uri", redirectURL)
	}
	if hint := strings.TrimSpace(idTokenHint); hint != "" {
		query.Set("id_token_hint", hint)
	} else if clientID := strings.TrimSpace(p.config.ClientID); clientID != "" {
		query.Set("client_id", clientID)
	}

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), true
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
		return RoleViewer, nil
	}

	role := Role("")
	if userGroup != "" && slices.Contains(normalized, strings.ToLower(userGroup)) {
		role = higherRole(role, RoleUser)
	}
	if adminGroup != "" && slices.Contains(normalized, strings.ToLower(adminGroup)) {
		role = higherRole(role, RoleAdmin)
	}
	if role != "" {
		return role, nil
	}

	return RoleViewer, nil
}

func higherRole(left, right Role) Role {
	if roleRank(right) > roleRank(left) {
		return right
	}
	return left
}

func roleRank(role Role) int {
	switch role {
	case RoleAdmin:
		return 2
	case RoleUser:
		return 1
	case RoleViewer:
		return 0
	default:
		return 0
	}
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
