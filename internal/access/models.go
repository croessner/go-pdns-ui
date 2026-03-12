package access

import (
	"errors"
	"time"

	"github.com/croessner/go-pdns-ui/internal/auth"
)

var (
	ErrAccessDisabled    = errors.New("access control is disabled")
	ErrInvalidInput      = errors.New("invalid access input")
	ErrCompanyExists     = errors.New("company already exists")
	ErrCompanyNotFound   = errors.New("company not found")
	ErrPrincipalNotFound = errors.New("principal not found")
)

type Company struct {
	ID        string
	Name      string
	Slug      string
	CreatedAt time.Time
}

type Principal struct {
	ID         string
	AuthSource string
	Subject    string
	Username   string
	Email      string
	Role       auth.Role
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type CompanyMembership struct {
	CompanyID         string
	CompanyName       string
	PrincipalID       string
	PrincipalUsername string
	CreatedAt         time.Time
}

type ZoneAssignment struct {
	ZoneName    string
	CompanyID   string
	CompanyName string
	CreatedAt   time.Time
}
