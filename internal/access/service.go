package access

import (
	"context"
	"errors"
	"log/slog"

	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
)

type Service interface {
	Enabled() bool
	Close() error
	SyncPrincipal(ctx context.Context, user auth.User) (Principal, error)
	FilterZones(ctx context.Context, user auth.User, zones []domain.Zone) ([]domain.Zone, error)
	CanAccessZone(ctx context.Context, user auth.User, zoneName string) (bool, error)
	AuthenticatePassword(username, password string) (auth.PasswordPrincipal, error)
	HasPasswordCredentials(username string) (bool, error)
	ChangePassword(principalID, currentPassword, newPassword string) error
	ListCompanies(ctx context.Context) ([]Company, error)
	ListPrincipals(ctx context.Context) ([]Principal, error)
	ListCompanyMemberships(ctx context.Context) ([]CompanyMembership, error)
	ListZoneAssignments(ctx context.Context) ([]ZoneAssignment, error)
	CreatePrincipal(ctx context.Context, authSource, subject, username, email string) (Principal, error)
	CreatePasswordPrincipal(ctx context.Context, username, email, password string, mustChangePassword bool) (Principal, error)
	UpdatePrincipal(ctx context.Context, principalID, username, email string) error
	ResetPrincipalPassword(ctx context.Context, principalID, password string, mustChangePassword bool) error
	DeletePrincipal(ctx context.Context, principalID string) error
	CreateCompany(ctx context.Context, name string) (Company, error)
	DeleteCompany(ctx context.Context, companyID string) error
	SetMembership(ctx context.Context, companyID, principalID string, member bool) error
	AssignZoneToCompany(ctx context.Context, zoneName, companyID string) error
	UnassignZone(ctx context.Context, zoneName string) error
}

type NoopService struct{}

func NewNoopService() Service {
	return &NoopService{}
}

func (s *NoopService) Enabled() bool {
	return false
}

func (s *NoopService) Close() error {
	return nil
}

func (s *NoopService) SyncPrincipal(_ context.Context, user auth.User) (Principal, error) {
	return Principal{
		AuthSource: user.AuthSource,
		Subject:    user.Subject,
		Username:   user.Username,
		Email:      user.Email,
		Role:       user.Role,
	}, nil
}

func (s *NoopService) FilterZones(_ context.Context, user auth.User, zones []domain.Zone) ([]domain.Zone, error) {
	if user.Role == auth.RoleAudit {
		return []domain.Zone{}, nil
	}

	result := make([]domain.Zone, len(zones))
	copy(result, zones)

	return result, nil
}

func (s *NoopService) CanAccessZone(_ context.Context, user auth.User, _ string) (bool, error) {
	return user.Role != auth.RoleAudit, nil
}

func (s *NoopService) AuthenticatePassword(_, _ string) (auth.PasswordPrincipal, error) {
	return auth.PasswordPrincipal{}, ErrAccessDisabled
}

func (s *NoopService) HasPasswordCredentials(_ string) (bool, error) {
	return false, ErrAccessDisabled
}

func (s *NoopService) ChangePassword(_, _, _ string) error {
	return ErrAccessDisabled
}

func (s *NoopService) ListCompanies(_ context.Context) ([]Company, error) {
	return nil, ErrAccessDisabled
}

func (s *NoopService) ListPrincipals(_ context.Context) ([]Principal, error) {
	return nil, ErrAccessDisabled
}

func (s *NoopService) ListCompanyMemberships(_ context.Context) ([]CompanyMembership, error) {
	return nil, ErrAccessDisabled
}

func (s *NoopService) ListZoneAssignments(_ context.Context) ([]ZoneAssignment, error) {
	return nil, ErrAccessDisabled
}

func (s *NoopService) CreatePrincipal(_ context.Context, _, _, _, _ string) (Principal, error) {
	return Principal{}, ErrAccessDisabled
}

func (s *NoopService) CreatePasswordPrincipal(_ context.Context, _, _, _ string, _ bool) (Principal, error) {
	return Principal{}, ErrAccessDisabled
}

func (s *NoopService) UpdatePrincipal(_ context.Context, _, _, _ string) error {
	return ErrAccessDisabled
}

func (s *NoopService) ResetPrincipalPassword(_ context.Context, _, _ string, _ bool) error {
	return ErrAccessDisabled
}

func (s *NoopService) DeletePrincipal(_ context.Context, _ string) error {
	return ErrAccessDisabled
}

func (s *NoopService) CreateCompany(_ context.Context, _ string) (Company, error) {
	return Company{}, ErrAccessDisabled
}

func (s *NoopService) DeleteCompany(_ context.Context, _ string) error {
	return ErrAccessDisabled
}

func (s *NoopService) SetMembership(_ context.Context, _, _ string, _ bool) error {
	return ErrAccessDisabled
}

func (s *NoopService) AssignZoneToCompany(_ context.Context, _, _ string) error {
	return ErrAccessDisabled
}

func (s *NoopService) UnassignZone(_ context.Context, _ string) error {
	return ErrAccessDisabled
}

type DBConfig struct {
	DSN                 string
	MaxOpenConns        int
	MaxIdleConns        int
	ConnMaxLifetimeSecs int
	OIDCAutoCreate      *bool
}

func NewService(ctx context.Context, mode string, cfg DBConfig, logger *slog.Logger) (Service, error) {
	switch mode {
	case "", "off":
		return NewNoopService(), nil
	case "company":
		return NewPostgresService(ctx, cfg, logger)
	default:
		return nil, errors.New("invalid authz mode")
	}
}
