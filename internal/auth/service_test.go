package auth

import (
	"context"
	"errors"
	"net/url"
	"testing"
)

type passwordStoreStub struct {
	authFn           func(username, password string) (PasswordPrincipal, error)
	hasCredentialsFn func(username string) (bool, error)
	changeFn         func(principalID, currentPassword, newPassword string) error
}

func (s *passwordStoreStub) AuthenticatePassword(username, password string) (PasswordPrincipal, error) {
	if s.authFn == nil {
		return PasswordPrincipal{}, ErrInvalidCredentials
	}
	return s.authFn(username, password)
}

func (s *passwordStoreStub) ChangePassword(principalID, currentPassword, newPassword string) error {
	if s.changeFn == nil {
		return errors.New("not implemented")
	}
	return s.changeFn(principalID, currentPassword, newPassword)
}

func (s *passwordStoreStub) HasPasswordCredentials(username string) (bool, error) {
	if s.hasCredentialsFn == nil {
		return false, nil
	}
	return s.hasCredentialsFn(username)
}

func TestPasswordLoginCreatesAdminSession(t *testing.T) {
	t.Parallel()

	svc, err := NewInMemoryService(context.Background(), "admin", "secret", OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}

	session, err := svc.LoginWithPassword("admin", "secret")
	if err != nil {
		t.Fatalf("expected successful login, got error: %v", err)
	}

	if !svc.ValidateSession(session.ID) {
		t.Fatalf("session should be valid after login")
	}

	if session.User.Role != RoleAdmin {
		t.Fatalf("expected local login role admin, got %q", session.User.Role)
	}
}

func TestMapGroupsToRole(t *testing.T) {
	t.Parallel()

	role, err := mapGroupsToRole([]string{"users", "admin"}, "admin", "user", "audit")
	if err != nil {
		t.Fatalf("expected admin group to map, got error: %v", err)
	}
	if role != RoleAdmin {
		t.Fatalf("expected admin role, got %q", role)
	}

	role, err = mapGroupsToRole([]string{"staff", "user"}, "admin", "user", "audit")
	if err != nil {
		t.Fatalf("expected user group to map, got error: %v", err)
	}
	if role != RoleUser {
		t.Fatalf("expected user role, got %q", role)
	}

	role, err = mapGroupsToRole([]string{"user", "admin"}, "admin", "user", "audit")
	if err != nil {
		t.Fatalf("expected both groups to map, got error: %v", err)
	}
	if role != RoleAdmin {
		t.Fatalf("expected highest role to win, got %q", role)
	}

	role, err = mapGroupsToRole([]string{"admin", "user"}, "admin", "user", "audit")
	if err != nil {
		t.Fatalf("expected both groups to map, got error: %v", err)
	}
	if role != RoleAdmin {
		t.Fatalf("expected highest role independent of order, got %q", role)
	}
}

func TestMapGroupsFallbacksToViewerForUnknownGroups(t *testing.T) {
	t.Parallel()

	role, err := mapGroupsToRole([]string{"guests"}, "admin", "user", "audit")
	if err != nil {
		t.Fatalf("expected unknown groups to fallback to viewer, got error: %v", err)
	}
	if role != RoleViewer {
		t.Fatalf("expected viewer role, got %q", role)
	}
}

func TestMapGroupsWithoutGroupsReturnsViewer(t *testing.T) {
	t.Parallel()

	role, err := mapGroupsToRole(nil, "admin", "user", "audit")
	if err != nil {
		t.Fatalf("expected empty groups to fallback to viewer, got error: %v", err)
	}
	if role != RoleViewer {
		t.Fatalf("expected viewer role, got %q", role)
	}
}

func TestMapGroupsMapsAuditRole(t *testing.T) {
	t.Parallel()

	role, err := mapGroupsToRole([]string{"audit"}, "admin", "user", "audit")
	if err != nil {
		t.Fatalf("expected audit group to map, got error: %v", err)
	}
	if role != RoleAudit {
		t.Fatalf("expected audit role, got %q", role)
	}
}

func TestMapGroupsPrefersUserOverAudit(t *testing.T) {
	t.Parallel()

	role, err := mapGroupsToRole([]string{"audit", "user"}, "admin", "user", "audit")
	if err != nil {
		t.Fatalf("expected audit+user groups to map, got error: %v", err)
	}
	if role != RoleUser {
		t.Fatalf("expected user role, got %q", role)
	}
}

func TestShowDefaultCredentialsHintFalseForExplicitCredentials(t *testing.T) {
	svc, err := NewInMemoryService(context.Background(), "admin", "secret", OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}
	if svc.ShowDefaultCredentialsHint() {
		t.Fatalf("expected default-credentials hint to be disabled for explicit credentials")
	}
}

func TestShowDefaultCredentialsHintFalseWhenEnvOverridesAreSet(t *testing.T) {
	t.Setenv("GO_PDNS_UI_USERNAME", "custom-admin")
	t.Setenv("GO_PDNS_UI_PASSWORD", "custom-secret")

	svc, err := NewInMemoryServiceFromEnv(context.Background())
	if err != nil {
		t.Fatalf("new auth service from env failed: %v", err)
	}
	if svc.ShowDefaultCredentialsHint() {
		t.Fatalf("expected default-credentials hint to be disabled when env credentials are set")
	}
}

func TestBuildOIDCLogoutURLSkipsNonOIDCSessions(t *testing.T) {
	t.Parallel()

	svc, err := NewInMemoryService(context.Background(), "admin", "secret", OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}

	logoutURL, ok := svc.BuildOIDCLogoutURL(Session{User: User{AuthSource: "password"}}, "https://app.example/login")
	if ok || logoutURL != "" {
		t.Fatalf("expected no OIDC logout URL for password session, got %q", logoutURL)
	}
}

func TestBuildOIDCLogoutURLForOIDCSession(t *testing.T) {
	t.Parallel()

	svc := &InMemoryService{
		oidc: &oidcProvider{
			config:        OIDCConfig{ClientID: "client"},
			endSessionURL: "https://issuer.example/logout",
		},
	}

	logoutURL, ok := svc.BuildOIDCLogoutURL(
		Session{
			User:    User{AuthSource: "oidc"},
			IDToken: "id-token-123",
		},
		"https://app.example/login",
	)
	if !ok {
		t.Fatalf("expected OIDC logout URL")
	}

	parsedURL, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("parse logout URL failed: %v", err)
	}
	if got := parsedURL.Query().Get("id_token_hint"); got != "id-token-123" {
		t.Fatalf("unexpected id_token_hint: %q", got)
	}
}

func TestPasswordLoginUsesPasswordStore(t *testing.T) {
	t.Parallel()

	svc, err := NewInMemoryService(context.Background(), "admin", "secret", OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}
	svc.SetPasswordStore(&passwordStoreStub{
		authFn: func(username, password string) (PasswordPrincipal, error) {
			if username != "alice" || password != "correct-password" {
				return PasswordPrincipal{}, ErrInvalidCredentials
			}
			return PasswordPrincipal{
				PrincipalID:        "p-123",
				Subject:            "local:alice",
				Username:           "alice",
				Email:              "alice@example.org",
				Role:               RoleUser,
				MustChangePassword: true,
			}, nil
		},
	})

	session, err := svc.LoginWithPassword("alice", "correct-password")
	if err != nil {
		t.Fatalf("expected successful password-store login, got: %v", err)
	}
	if session.User.Username != "alice" {
		t.Fatalf("unexpected username %q", session.User.Username)
	}
	if !session.User.MustChangePassword {
		t.Fatalf("expected must-change-password flag to be set")
	}
}

func TestChangePasswordClearsMustChangeFlag(t *testing.T) {
	t.Parallel()

	svc, err := NewInMemoryService(context.Background(), "admin", "secret", OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}
	svc.SetPasswordStore(&passwordStoreStub{
		authFn: func(username, password string) (PasswordPrincipal, error) {
			return PasswordPrincipal{
				PrincipalID:        "p-123",
				Subject:            "local:alice",
				Username:           "alice",
				Role:               RoleUser,
				MustChangePassword: true,
			}, nil
		},
		changeFn: func(principalID, currentPassword, newPassword string) error {
			if principalID != "p-123" {
				t.Fatalf("unexpected principal id %q", principalID)
			}
			if currentPassword != "old-password" || newPassword != "new-password" {
				t.Fatalf("unexpected password update payload")
			}
			return nil
		},
	})

	session, err := svc.LoginWithPassword("alice", "old-password")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	if err := svc.ChangePassword(session.ID, "old-password", "new-password"); err != nil {
		t.Fatalf("change password failed: %v", err)
	}

	updated, ok := svc.GetSession(session.ID)
	if !ok {
		t.Fatalf("expected session to remain valid")
	}
	if updated.User.MustChangePassword {
		t.Fatalf("must-change-password flag should be cleared after successful password change")
	}
}

func TestChangePasswordRejectsShortPasswords(t *testing.T) {
	t.Parallel()

	svc, err := NewInMemoryService(context.Background(), "admin", "secret", OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}
	session, err := svc.LoginWithPassword("admin", "secret")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	err = svc.ChangePassword(session.ID, "secret", "short")
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected ErrInvalidPassword, got %v", err)
	}
}

func TestPasswordLoginRejectsEnvFallbackWhenPasswordStoreHasCredentials(t *testing.T) {
	t.Parallel()

	svc, err := NewInMemoryService(context.Background(), "admin", "secret", OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}
	svc.SetPasswordStore(&passwordStoreStub{
		authFn: func(username, password string) (PasswordPrincipal, error) {
			return PasswordPrincipal{}, ErrInvalidCredentials
		},
		hasCredentialsFn: func(username string) (bool, error) {
			if username == "admin" {
				return true, nil
			}
			return false, nil
		},
	})

	if _, err := svc.LoginWithPassword("admin", "secret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials when store has credentials, got %v", err)
	}
}

func TestPasswordLoginKeepsEnvFallbackWhenPasswordStoreHasNoCredentials(t *testing.T) {
	t.Parallel()

	svc, err := NewInMemoryService(context.Background(), "admin", "secret", OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}
	svc.SetPasswordStore(&passwordStoreStub{
		authFn: func(username, password string) (PasswordPrincipal, error) {
			return PasswordPrincipal{}, ErrInvalidCredentials
		},
		hasCredentialsFn: func(username string) (bool, error) {
			return false, nil
		},
	})

	session, err := svc.LoginWithPassword("admin", "secret")
	if err != nil {
		t.Fatalf("expected env fallback login to remain possible without store credentials, got: %v", err)
	}
	if session.User.Username != "admin" {
		t.Fatalf("unexpected username %q", session.User.Username)
	}
}
