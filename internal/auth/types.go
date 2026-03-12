package auth

import "time"

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleUser   Role = "user"
	RoleViewer Role = "viewer"
)

type User struct {
	Subject    string
	Username   string
	Email      string
	AuthSource string
	Groups     []string
	Role       Role
}

type Session struct {
	ID        string
	User      User
	CreatedAt time.Time
}
