package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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

	sessions map[string]Session
	flows    map[string]oidcFlow
}

func NewInMemoryService(ctx context.Context, username, password string, oidcConfig OIDCConfig) (*InMemoryService, error) {
	oidcProvider, err := newOIDCProvider(ctx, oidcConfig)
	if err != nil {
		return nil, err
	}

	return &InMemoryService{
		username: strings.TrimSpace(username),
		password: password,
		oidc:     oidcProvider,
		sessions: make(map[string]Session),
		flows:    make(map[string]oidcFlow),
	}, nil
}

func NewInMemoryServiceFromEnv(ctx context.Context) (*InMemoryService, error) {
	username := getenvOrDefault("GO_PDNS_UI_USERNAME", "admin")
	password := getenvOrDefault("GO_PDNS_UI_PASSWORD", "admin")
	oidcConfig := LoadOIDCConfigFromEnv()

	return NewInMemoryService(ctx, username, password, oidcConfig)
}

func (s *InMemoryService) LoginWithPassword(username, password string) (Session, error) {
	if strings.TrimSpace(username) != s.username || password != s.password {
		return Session{}, ErrInvalidCredentials
	}

	user := User{
		Subject:    "local:" + s.username,
		Username:   s.username,
		AuthSource: "password",
		Role:       RoleAdmin,
	}

	return s.newSession(user), nil
}

func (s *InMemoryService) OIDCEnabled() bool {
	return s.oidc != nil
}

func (s *InMemoryService) BeginOIDCAuth() (string, error) {
	if s.oidc == nil {
		return "", ErrOIDCNotConfigured
	}

	state, err := randomBase64URL(32)
	if err != nil {
		return "", fmt.Errorf("create oidc state: %w", err)
	}

	verifier, err := randomBase64URL(64)
	if err != nil {
		return "", fmt.Errorf("create pkce verifier: %w", err)
	}

	nonce, err := randomBase64URL(32)
	if err != nil {
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
	return s.oidc.authCodeURL(state, nonce, codeChallenge), nil
}

func (s *InMemoryService) CompleteOIDCAuth(ctx context.Context, state, code string) (Session, error) {
	if s.oidc == nil {
		return Session{}, ErrOIDCNotConfigured
	}

	state = strings.TrimSpace(state)
	code = strings.TrimSpace(code)
	if state == "" || code == "" {
		return Session{}, ErrInvalidOIDCCode
	}

	s.mu.Lock()
	flow, ok := s.flows[state]
	delete(s.flows, state)
	s.cleanupExpiredFlowsLocked()
	s.mu.Unlock()
	if !ok || flow.Expires.Before(time.Now()) {
		return Session{}, ErrOIDCStateInvalid
	}

	token, err := s.oidc.exchange(ctx, code, flow.Verifier)
	if err != nil {
		return Session{}, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || strings.TrimSpace(rawIDToken) == "" {
		return Session{}, ErrInvalidOIDCCode
	}

	claims, err := s.oidc.verifyIDToken(ctx, rawIDToken)
	if err != nil {
		return Session{}, err
	}

	if flow.Nonce != claims.Nonce {
		return Session{}, ErrOIDCNonceInvalid
	}

	groups := parseGroups(claims.Groups)
	role, err := mapGroupsToRole(groups, s.oidc.config.AdminGroup, s.oidc.config.UserGroup)
	if err != nil {
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

	return s.newSession(user), nil
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
