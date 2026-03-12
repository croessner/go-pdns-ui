package auth

import (
	"context"
	"testing"
)

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

	role, err := mapGroupsToRole([]string{"users", "admin"}, "admin", "user")
	if err != nil {
		t.Fatalf("expected admin group to map, got error: %v", err)
	}
	if role != RoleAdmin {
		t.Fatalf("expected admin role, got %q", role)
	}

	role, err = mapGroupsToRole([]string{"staff", "user"}, "admin", "user")
	if err != nil {
		t.Fatalf("expected user group to map, got error: %v", err)
	}
	if role != RoleUser {
		t.Fatalf("expected user role, got %q", role)
	}

	role, err = mapGroupsToRole([]string{"user", "admin"}, "admin", "user")
	if err != nil {
		t.Fatalf("expected both groups to map, got error: %v", err)
	}
	if role != RoleAdmin {
		t.Fatalf("expected highest role to win, got %q", role)
	}

	role, err = mapGroupsToRole([]string{"admin", "user"}, "admin", "user")
	if err != nil {
		t.Fatalf("expected both groups to map, got error: %v", err)
	}
	if role != RoleAdmin {
		t.Fatalf("expected highest role independent of order, got %q", role)
	}
}

func TestMapGroupsFallbacksToViewerForUnknownGroups(t *testing.T) {
	t.Parallel()

	role, err := mapGroupsToRole([]string{"guests"}, "admin", "user")
	if err != nil {
		t.Fatalf("expected unknown groups to fallback to viewer, got error: %v", err)
	}
	if role != RoleViewer {
		t.Fatalf("expected viewer role, got %q", role)
	}
}

func TestMapGroupsWithoutGroupsReturnsViewer(t *testing.T) {
	t.Parallel()

	role, err := mapGroupsToRole(nil, "admin", "user")
	if err != nil {
		t.Fatalf("expected empty groups to fallback to viewer, got error: %v", err)
	}
	if role != RoleViewer {
		t.Fatalf("expected viewer role, got %q", role)
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
