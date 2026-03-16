package auth

import "time"

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleUser   Role = "user"
	RoleAudit  Role = "audit"
	RoleViewer Role = "viewer"
)

type User struct {
	PrincipalID        string
	Subject            string
	Username           string
	Email              string
	AuthSource         string
	Groups             []string
	Role               Role
	MustChangePassword bool
}

type Session struct {
	ID         string
	User       User
	IDToken    string
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time
}
