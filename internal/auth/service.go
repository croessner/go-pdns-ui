package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidSession     = errors.New("invalid session")
	ErrInvalidOIDCCode    = errors.New("invalid oidc callback payload")
)

type Service interface {
	LoginWithPassword(username, password string) (Session, error)
	OIDCEnabled() bool
	ShowDefaultCredentialsHint() bool
	BeginOIDCAuth() (string, error)
	CompleteOIDCAuth(ctx context.Context, state, code string) (Session, error)
	GetSession(sessionID string) (Session, bool)
	ValidateSession(sessionID string) bool
	RevokeSession(sessionID string)
}

type InMemoryService struct {
	mu sync.RWMutex

	username string
	password string
	oidc     *oidcProvider
	logger   *slog.Logger
	// showDefaultCredentialsHint indicates that local auth uses the startup fallback defaults.
	showDefaultCredentialsHint bool

	sessions map[string]Session
	flows    map[string]oidcFlow
}

func NewInMemoryService(ctx context.Context, username, password string, oidcConfig OIDCConfig) (*InMemoryService, error) {
	return NewInMemoryServiceWithLogger(ctx, username, password, oidcConfig, nil)
}

func NewInMemoryServiceWithLogger(ctx context.Context, username, password string, oidcConfig OIDCConfig, logger *slog.Logger) (*InMemoryService, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "auth")

	oidcProvider, err := newOIDCProvider(ctx, oidcConfig, logger)
	if err != nil {
		return nil, err
	}

	service := &InMemoryService{
		username: strings.TrimSpace(username),
		password: password,
		oidc:     oidcProvider,
		logger:   logger,
		// Constructor with explicit credentials should not advertise defaults.
		showDefaultCredentialsHint: false,
		sessions:                   make(map[string]Session),
		flows:                      make(map[string]oidcFlow),
	}

	service.logger.Info(
		"auth_service_initialized",
		"oidc_enabled", service.oidc != nil,
		"oidc_introspection_auth_method", oidcConfig.effectiveIntrospectionAuthMethod(),
	)

	return service, nil
}

func NewInMemoryServiceFromEnv(ctx context.Context) (*InMemoryService, error) {
	return NewInMemoryServiceFromEnvWithLogger(ctx, nil)
}

func NewInMemoryServiceFromEnvWithLogger(ctx context.Context, logger *slog.Logger) (*InMemoryService, error) {
	_, usernameIsSet := os.LookupEnv("GO_PDNS_UI_USERNAME")
	_, passwordIsSet := os.LookupEnv("GO_PDNS_UI_PASSWORD")
	username := getenvOrDefault("GO_PDNS_UI_USERNAME", "admin")
	password := getenvOrDefault("GO_PDNS_UI_PASSWORD", "admin")
	oidcConfig := LoadOIDCConfigFromEnv()

	service, err := NewInMemoryServiceWithLogger(ctx, username, password, oidcConfig, logger)
	if err != nil {
		return nil, err
	}
	// Only display the hint if both credentials come from fallback defaults.
	service.showDefaultCredentialsHint = !usernameIsSet && !passwordIsSet

	return service, nil
}

func (s *InMemoryService) LoginWithPassword(username, password string) (Session, error) {
	if strings.TrimSpace(username) != s.username || password != s.password {
		s.logger.Warn("password_login_failed", "username", strings.TrimSpace(username))
		return Session{}, ErrInvalidCredentials
	}

	user := User{
		Subject:    "local:" + s.username,
		Username:   s.username,
		AuthSource: "password",
		Role:       RoleAdmin,
	}

	session := s.newSession(user)
	s.logger.Info("password_login_succeeded", "username", user.Username, "role", user.Role)
	return session, nil
}

func (s *InMemoryService) OIDCEnabled() bool {
	return s.oidc != nil
}

func (s *InMemoryService) ShowDefaultCredentialsHint() bool {
	return s.showDefaultCredentialsHint
}

func (s *InMemoryService) BeginOIDCAuth() (string, error) {
	if s.oidc == nil {
		return "", ErrOIDCNotConfigured
	}

	state, err := randomBase64URL(32)
	if err != nil {
		s.logger.Error("oidc_state_generation_failed", "error", err)
		return "", fmt.Errorf("create oidc state: %w", err)
	}

	verifier, err := randomBase64URL(64)
	if err != nil {
		s.logger.Error("oidc_pkce_verifier_generation_failed", "error", err)
		return "", fmt.Errorf("create pkce verifier: %w", err)
	}

	nonce, err := randomBase64URL(32)
	if err != nil {
		s.logger.Error("oidc_nonce_generation_failed", "error", err)
		return "", fmt.Errorf("create oidc nonce: %w", err)
	}

	flow := oidcFlow{
		Verifier: verifier,
		Nonce:    nonce,
		Expires:  time.Now().Add(5 * time.Minute),
	}

	s.mu.Lock()
	s.cleanupExpiredFlowsLocked()
	s.flows[state] = flow
	s.mu.Unlock()

	codeChallenge := buildPKCEChallenge(verifier)
	s.logger.Debug("oidc_auth_started")
	return s.oidc.authCodeURL(state, nonce, codeChallenge), nil
}

func (s *InMemoryService) CompleteOIDCAuth(ctx context.Context, state, code string) (Session, error) {
	if s.oidc == nil {
		return Session{}, ErrOIDCNotConfigured
	}

	state = strings.TrimSpace(state)
	code = strings.TrimSpace(code)
	if state == "" || code == "" {
		s.logger.Warn("oidc_callback_invalid_payload")
		return Session{}, ErrInvalidOIDCCode
	}

	s.mu.Lock()
	flow, ok := s.flows[state]
	delete(s.flows, state)
	s.cleanupExpiredFlowsLocked()
	s.mu.Unlock()
	if !ok || flow.Expires.Before(time.Now()) {
		s.logger.Warn("oidc_callback_invalid_or_expired_state")
		return Session{}, ErrOIDCStateInvalid
	}

	token, err := s.oidc.exchange(ctx, code, flow.Verifier)
	if err != nil {
		s.logger.Warn("oidc_token_exchange_failed", "error", err)
		return Session{}, err
	}

	if err := s.oidc.introspectAccessToken(ctx, token.AccessToken); err != nil {
		s.logger.Warn("oidc_access_token_introspection_failed", "error", err)
		return Session{}, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		s.logger.Warn("oidc_id_token_missing")
		return Session{}, ErrInvalidOIDCCode
	}

	claims, err := s.oidc.verifyIDToken(ctx, rawIDToken)
	if err != nil {
		s.logger.Warn("oidc_id_token_verify_failed", "error", err)
		return Session{}, err
	}

	if flow.Nonce != claims.Nonce {
		s.logger.Warn("oidc_nonce_mismatch")
		return Session{}, ErrOIDCNonceInvalid
	}

	groups := parseGroups(claims.Groups)
	role, err := mapGroupsToRole(groups, s.oidc.config.AdminGroup, s.oidc.config.UserGroup)
	if err != nil {
		s.logger.Warn("oidc_groups_rejected", "error", err)
		return Session{}, err
	}

	username := claims.PreferredUsername
	if strings.TrimSpace(username) == "" {
		username = claims.Name
	}
	if strings.TrimSpace(username) == "" {
		username = claims.Email
	}
	if strings.TrimSpace(username) == "" {
		username = claims.Subject
	}

	user := User{
		Subject:    claims.Subject,
		Username:   username,
		Email:      claims.Email,
		AuthSource: "oidc",
		Groups:     groups,
		Role:       role,
	}

	session := s.newSession(user)
	s.logger.Info("oidc_login_succeeded", "username", user.Username, "role", user.Role)
	return session, nil
}

func (s *InMemoryService) GetSession(sessionID string) (Session, bool) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return Session{}, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return Session{}, false
	}

	return session, true
}

func (s *InMemoryService) ValidateSession(sessionID string) bool {
	_, ok := s.GetSession(sessionID)
	return ok
}

func (s *InMemoryService) RevokeSession(sessionID string) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	s.logger.Info("session_revoked")
}

func (s *InMemoryService) newSession(user User) Session {
	sessionID := randomHex(24)
	session := Session{
		ID:        sessionID,
		User:      user,
		CreatedAt: time.Now(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = session

	return session
}

func (s *InMemoryService) cleanupExpiredFlowsLocked() {
	now := time.Now()
	for state, flow := range s.flows {
		if flow.Expires.Before(now) {
			delete(s.flows, state)
		}
	}
}

func randomHex(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		copy(buf, "go-pdns-ui-session-fallback")
	}
	return hex.EncodeToString(buf)
}

func randomBase64URL(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
