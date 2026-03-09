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
}

func TestMapGroupsRejectsUnknownGroups(t *testing.T) {
	t.Parallel()

	_, err := mapGroupsToRole([]string{"guests"}, "admin", "user")
	if err == nil {
		t.Fatalf("expected unknown groups to fail")
	}
}
