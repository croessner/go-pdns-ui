package ui

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/croessner/go-pdns-ui/internal/access"
	"github.com/croessner/go-pdns-ui/internal/assets"
	"github.com/croessner/go-pdns-ui/internal/audit"
	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
	"github.com/croessner/go-pdns-ui/internal/i18n"
)

type accessControlRenderStub struct {
	access.Service
	principals                  []access.Principal
	memberships                 []access.CompanyMembership
	createPasswordPrincipalCall int
}

func (s *accessControlRenderStub) Enabled() bool {
	return true
}

func (s *accessControlRenderStub) SyncPrincipal(_ context.Context, user auth.User) (access.Principal, error) {
	return access.Principal{
		ID:         "admin-principal",
		AuthSource: user.AuthSource,
		Subject:    user.Subject,
		Username:   user.Username,
		Role:       user.Role,
	}, nil
}

func (s *accessControlRenderStub) FilterZones(_ context.Context, _ auth.User, zones []domain.Zone) ([]domain.Zone, error) {
	result := make([]domain.Zone, len(zones))
	copy(result, zones)
	return result, nil
}

func (s *accessControlRenderStub) ListCompanies(context.Context) ([]access.Company, error) {
	return []access.Company{}, nil
}

func (s *accessControlRenderStub) ListPrincipals(context.Context) ([]access.Principal, error) {
	return s.principals, nil
}

func (s *accessControlRenderStub) ListCompanyMemberships(context.Context) ([]access.CompanyMembership, error) {
	return s.memberships, nil
}

func (s *accessControlRenderStub) ListZoneAssignments(context.Context) ([]access.ZoneAssignment, error) {
	return []access.ZoneAssignment{}, nil
}

func (s *accessControlRenderStub) CreatePasswordPrincipal(context.Context, string, string, string, bool) (access.Principal, error) {
	s.createPasswordPrincipalCall++
	return access.Principal{}, access.ErrAccessDisabled
}

func TestAccessControlRendersDeleteForOIDCPrincipalRegression(t *testing.T) {
	t.Parallel()

	i18nSvc, err := i18n.NewService(assets.Files, "locales", "en")
	if err != nil {
		t.Fatalf("new i18n service failed: %v", err)
	}

	zoneSvc := domain.NewDraftZoneService(domain.NewInMemoryZoneRepository([]domain.Zone{
		{Name: "example.org", Kind: domain.ZoneForward},
	}))
	templateSvc := domain.NewInMemoryZoneTemplateService(nil)

	authSvc, err := auth.NewInMemoryService(context.Background(), "admin", "admin", auth.OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}

	accessSvc := &accessControlRenderStub{
		Service: access.NewNoopService(),
		principals: []access.Principal{
			{
				ID:         "oidc-principal-1",
				AuthSource: "oidc",
				Subject:    "subject-1",
				Username:   "oidc-user",
				Email:      "oidc-user@example.org",
				Role:       auth.RoleUser,
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewHandler(assets.Files, zoneSvc, templateSvc, authSvc, i18nSvc, accessSvc, audit.NewNoopService(), HandlerOptions{}, logger)
	if err != nil {
		t.Fatalf("new handler failed: %v", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	session, err := authSvc.LoginWithPassword("admin", "admin")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?tab=access", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID, Path: "/"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `hx-post="/access/principals/oidc-principal-1/delete"`) {
		t.Fatalf("expected OIDC principal delete form to be rendered")
	}
}

func TestAccessControlHidesPasswordPrincipalsWhenOIDCOnly(t *testing.T) {
	t.Parallel()

	i18nSvc, err := i18n.NewService(assets.Files, "locales", "en")
	if err != nil {
		t.Fatalf("new i18n service failed: %v", err)
	}

	zoneSvc := domain.NewDraftZoneService(domain.NewInMemoryZoneRepository([]domain.Zone{
		{Name: "example.org", Kind: domain.ZoneForward},
	}))
	templateSvc := domain.NewInMemoryZoneTemplateService(nil)

	authSvc, err := auth.NewInMemoryService(context.Background(), "admin", "admin", auth.OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}

	accessSvc := &accessControlRenderStub{
		Service: access.NewNoopService(),
		principals: []access.Principal{
			{ID: "oidc-principal", AuthSource: "oidc", Username: "oidc-visible", Role: auth.RoleUser},
			{ID: "password-principal", AuthSource: "password", Username: "legacy-pass-user", Role: auth.RoleUser},
		},
		memberships: []access.CompanyMembership{
			{CompanyID: "c1", CompanyName: "Example", PrincipalID: "oidc-principal", PrincipalUsername: "oidc-visible"},
			{CompanyID: "c1", CompanyName: "Example", PrincipalID: "password-principal", PrincipalUsername: "legacy-pass-user"},
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewHandler(
		assets.Files,
		zoneSvc,
		templateSvc,
		authSvc,
		i18nSvc,
		accessSvc,
		audit.NewNoopService(),
		HandlerOptions{OIDCOnlyLogin: true},
		logger,
	)
	if err != nil {
		t.Fatalf("new handler failed: %v", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	session, err := authSvc.LoginWithPassword("admin", "admin")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/?tab=access", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID, Path: "/"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "oidc-visible") {
		t.Fatalf("expected OIDC principal to be visible")
	}
	if strings.Contains(body, "legacy-pass-user") {
		t.Fatalf("expected password principal to be hidden in oidc-only mode")
	}
	if strings.Contains(body, `option value="password"`) {
		t.Fatalf("expected password auth source option to be hidden in oidc-only mode")
	}
}

func TestCreatePrincipalRejectsPasswordWhenOIDCOnly(t *testing.T) {
	t.Parallel()

	i18nSvc, err := i18n.NewService(assets.Files, "locales", "en")
	if err != nil {
		t.Fatalf("new i18n service failed: %v", err)
	}

	zoneSvc := domain.NewDraftZoneService(domain.NewInMemoryZoneRepository([]domain.Zone{
		{Name: "example.org", Kind: domain.ZoneForward},
	}))
	templateSvc := domain.NewInMemoryZoneTemplateService(nil)

	authSvc, err := auth.NewInMemoryService(context.Background(), "admin", "admin", auth.OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}

	accessSvc := &accessControlRenderStub{Service: access.NewNoopService()}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewHandler(
		assets.Files,
		zoneSvc,
		templateSvc,
		authSvc,
		i18nSvc,
		accessSvc,
		audit.NewNoopService(),
		HandlerOptions{OIDCOnlyLogin: true},
		logger,
	)
	if err != nil {
		t.Fatalf("new handler failed: %v", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	session, err := authSvc.LoginWithPassword("admin", "admin")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	form := url.Values{
		"csrf_token":  {session.CSRFToken},
		"auth_source": {"password"},
		"username":    {"evil-local-user"},
		"password":    {"super-secret-password"},
		"tab":         {"access"},
	}
	req := httptest.NewRequest(http.MethodPost, "/access/principals", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID, Path: "/"})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
	if accessSvc.createPasswordPrincipalCall != 0 {
		t.Fatalf("expected password principal creation to be blocked before access service call")
	}
}
