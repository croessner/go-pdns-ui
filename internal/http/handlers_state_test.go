package ui

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/croessner/go-pdns-ui/internal/access"
	"github.com/croessner/go-pdns-ui/internal/assets"
	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
	"github.com/croessner/go-pdns-ui/internal/i18n"
)

type accessStub struct {
	enabled     bool
	filterFn    func([]domain.Zone) []domain.Zone
	canAccessFn func(zoneName string) bool
}

func (s *accessStub) Enabled() bool {
	return s.enabled
}

func (s *accessStub) Close() error {
	return nil
}

func (s *accessStub) SyncPrincipal(_ context.Context, user auth.User) (access.Principal, error) {
	return access.Principal{
		ID:         "p-1",
		AuthSource: user.AuthSource,
		Subject:    user.Subject,
		Username:   user.Username,
		Role:       user.Role,
	}, nil
}

func (s *accessStub) FilterZones(_ context.Context, _ auth.User, zones []domain.Zone) ([]domain.Zone, error) {
	if s.filterFn == nil {
		result := make([]domain.Zone, len(zones))
		copy(result, zones)
		return result, nil
	}

	return s.filterFn(zones), nil
}

func (s *accessStub) CanAccessZone(_ context.Context, _ auth.User, zoneName string) (bool, error) {
	if s.canAccessFn == nil {
		return true, nil
	}
	return s.canAccessFn(zoneName), nil
}

func (s *accessStub) ListCompanies(context.Context) ([]access.Company, error) {
	return nil, errors.New("not implemented")
}

func (s *accessStub) ListPrincipals(context.Context) ([]access.Principal, error) {
	return nil, errors.New("not implemented")
}

func (s *accessStub) ListCompanyMemberships(context.Context) ([]access.CompanyMembership, error) {
	return nil, errors.New("not implemented")
}

func (s *accessStub) ListZoneAssignments(context.Context) ([]access.ZoneAssignment, error) {
	return nil, errors.New("not implemented")
}

func (s *accessStub) CreatePrincipal(context.Context, string, string, string, string) (access.Principal, error) {
	return access.Principal{}, errors.New("not implemented")
}

func (s *accessStub) DeletePrincipal(context.Context, string) error {
	return errors.New("not implemented")
}

func (s *accessStub) CreateCompany(context.Context, string) (access.Company, error) {
	return access.Company{}, errors.New("not implemented")
}

func (s *accessStub) DeleteCompany(context.Context, string) error {
	return errors.New("not implemented")
}

func (s *accessStub) SetMembership(context.Context, string, string, bool) error {
	return errors.New("not implemented")
}

func (s *accessStub) AssignZoneToCompany(context.Context, string, string) error {
	return errors.New("not implemented")
}

func (s *accessStub) UnassignZone(context.Context, string) error {
	return errors.New("not implemented")
}

func TestFilterZones(t *testing.T) {
	t.Parallel()

	input := []domain.Zone{
		{Name: "example.org"},
		{Name: "internal.example.org"},
		{Name: "2.0.192.in-addr.arpa"},
	}

	filtered := filterZones(input, "example")
	if len(filtered) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(filtered))
	}
}

func TestZoneExists(t *testing.T) {
	t.Parallel()

	zones := []domain.Zone{
		{Name: "alpha-test.example.org"},
		{Name: "beta-test.example.org"},
	}

	if !zoneExists(zones, "alpha-test.example.org") {
		t.Fatalf("expected exact zone match")
	}
	if !zoneExists(zones, "ALPHA-TEST.EXAMPLE.ORG") {
		t.Fatalf("expected case-insensitive zone match")
	}
	if zoneExists(zones, "foobar.org") {
		t.Fatalf("expected unknown zone to not match")
	}
}

func TestFilterAssignableZones(t *testing.T) {
	t.Parallel()

	zones := []domain.Zone{
		{Name: "alpha-test.example.org"},
		{Name: "beta-test.example.org"},
		{Name: "gamma-test.example.org"},
	}
	assigned := map[string]string{
		"beta-test.example.org": "company-1",
	}

	assignable := filterAssignableZones(zones, assigned)
	if len(assignable) != 2 {
		t.Fatalf("expected 2 assignable zones, got %d", len(assignable))
	}
	if assignable[0].Name != "alpha-test.example.org" || assignable[1].Name != "gamma-test.example.org" {
		t.Fatalf("unexpected assignable zones: %+v", assignable)
	}
}

func TestPaginateZones(t *testing.T) {
	t.Parallel()

	input := []domain.Zone{
		{Name: "a"},
		{Name: "b"},
		{Name: "c"},
	}

	pageZones, page, totalPages := paginateZones(input, 2, 2)
	if page != 2 {
		t.Fatalf("expected page 2, got %d", page)
	}
	if totalPages != 2 {
		t.Fatalf("expected total pages 2, got %d", totalPages)
	}
	if len(pageZones) != 1 || pageZones[0].Name != "c" {
		t.Fatalf("unexpected page content: %+v", pageZones)
	}
}

func TestParsePage(t *testing.T) {
	t.Parallel()

	if page := parsePage(""); page != 1 {
		t.Fatalf("expected default page 1, got %d", page)
	}
	if page := parsePage("3"); page != 3 {
		t.Fatalf("expected page 3, got %d", page)
	}
	if page := parsePage("-1"); page != 1 {
		t.Fatalf("expected clamped page 1, got %d", page)
	}
}

func TestIsHXRequest(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("HX-Request", "true")
	if !isHXRequest(req) {
		t.Fatalf("expected HX request to be detected")
	}

	reqNoHX := httptest.NewRequest("GET", "/", nil)
	if isHXRequest(reqNoHX) {
		t.Fatalf("expected non-HX request to be false")
	}
}

func TestRequestIsSecure(t *testing.T) {
	t.Parallel()

	httpsReq := httptest.NewRequest("GET", "https://ui.example.test/", nil)
	if !requestIsSecure(httpsReq) {
		t.Fatalf("expected HTTPS request to be secure")
	}

	proxyReq := httptest.NewRequest("GET", "http://ui.example.test/", nil)
	proxyReq.Header.Set("X-Forwarded-Proto", "https")
	if !requestIsSecure(proxyReq) {
		t.Fatalf("expected forwarded HTTPS request to be secure")
	}

	httpReq := httptest.NewRequest("GET", "http://ui.example.test/", nil)
	if requestIsSecure(httpReq) {
		t.Fatalf("expected plain HTTP request to be insecure")
	}
}

func TestCanEditZones(t *testing.T) {
	t.Parallel()

	if !canEditZones(auth.RoleAdmin) {
		t.Fatalf("expected admin to have zone write access")
	}
	if !canEditZones(auth.RoleUser) {
		t.Fatalf("expected user to have zone write access")
	}
	if canEditZones(auth.RoleViewer) {
		t.Fatalf("expected viewer to be read-only")
	}
}

func TestNormalizeWorkspaceTab(t *testing.T) {
	t.Parallel()

	if got := normalizeWorkspaceTab("templates", true, true); got != tabTemplates {
		t.Fatalf("expected templates tab, got %q", got)
	}
	if got := normalizeWorkspaceTab("access", true, true); got != tabAccess {
		t.Fatalf("expected access tab, got %q", got)
	}
	if got := normalizeWorkspaceTab("access", true, false); got != tabZones {
		t.Fatalf("expected zones fallback when access control is disabled, got %q", got)
	}
	if got := normalizeWorkspaceTab("templates", false, true); got != tabZones {
		t.Fatalf("expected zones fallback for non-admin, got %q", got)
	}
}

func TestBuildDashboardStateTemplatesHiddenForUserRole(t *testing.T) {
	t.Parallel()

	i18nSvc, err := i18n.NewService(assets.Files, "locales", "en")
	if err != nil {
		t.Fatalf("new i18n service failed: %v", err)
	}

	zoneRepo := domain.NewInMemoryZoneRepository([]domain.Zone{
		{
			Name: "example.org",
			Kind: domain.ZoneForward,
		},
	})
	zoneSvc := domain.NewDraftZoneService(zoneRepo)
	templateSvc := domain.NewInMemoryZoneTemplateService([]domain.ZoneTemplate{
		{
			Name: "Forward Basic",
			Kind: domain.ZoneForward,
			Records: []domain.Record{
				{Name: "@", Type: "NS", TTL: 3600, Content: "ns1.{{ZONE_FQDN}}"},
			},
		},
	})

	h := &Handler{
		zones:         zoneSvc,
		zoneTemplates: templateSvc,
		i18n:          i18nSvc,
		access:        access.NewNoopService(),
	}
	authSvc, err := auth.NewInMemoryService(context.Background(), "admin", "admin", auth.OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}
	h.auth = authSvc

	userSession := auth.Session{User: auth.User{Role: auth.RoleUser}}
	userData, err := h.buildDashboardState(context.Background(), "en", "", 1, "example.org", "Forward Basic", "", userSession)
	if err != nil {
		t.Fatalf("build user dashboard state failed: %v", err)
	}
	if len(userData.Templates) != 0 {
		t.Fatalf("expected templates hidden for user, got %d", len(userData.Templates))
	}
	if userData.SelectedTemplate != nil {
		t.Fatalf("expected no selected template for user, got %+v", userData.SelectedTemplate)
	}

	adminSession := auth.Session{User: auth.User{Role: auth.RoleAdmin}}
	adminData, err := h.buildDashboardState(context.Background(), "en", "", 1, "example.org", "Forward Basic", "", adminSession)
	if err != nil {
		t.Fatalf("build admin dashboard state failed: %v", err)
	}
	if len(adminData.Templates) != 1 {
		t.Fatalf("expected templates visible for admin, got %d", len(adminData.Templates))
	}
	if adminData.SelectedTemplate == nil || adminData.SelectedTemplate.Name != "Forward Basic" {
		t.Fatalf("expected selected template for admin, got %+v", adminData.SelectedTemplate)
	}
}

func TestBuildDashboardStateFiltersZonesByAccessControl(t *testing.T) {
	t.Parallel()

	i18nSvc, err := i18n.NewService(assets.Files, "locales", "en")
	if err != nil {
		t.Fatalf("new i18n service failed: %v", err)
	}

	zoneRepo := domain.NewInMemoryZoneRepository([]domain.Zone{
		{Name: "allowed.example.org", Kind: domain.ZoneForward},
		{Name: "hidden.example.org", Kind: domain.ZoneForward},
	})
	zoneSvc := domain.NewDraftZoneService(zoneRepo)
	templateSvc := domain.NewInMemoryZoneTemplateService(nil)

	h := &Handler{
		zones:         zoneSvc,
		zoneTemplates: templateSvc,
		i18n:          i18nSvc,
		access: &accessStub{
			enabled: true,
			filterFn: func(zones []domain.Zone) []domain.Zone {
				result := make([]domain.Zone, 0, len(zones))
				for _, zone := range zones {
					if zone.Name == "allowed.example.org" {
						result = append(result, zone)
					}
				}
				return result
			},
		},
	}
	authSvc, err := auth.NewInMemoryService(context.Background(), "admin", "admin", auth.OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}
	h.auth = authSvc

	userSession := auth.Session{User: auth.User{Role: auth.RoleUser}}
	data, err := h.buildDashboardState(context.Background(), "en", "", 1, "hidden.example.org", "", "", userSession)
	if err != nil {
		t.Fatalf("build dashboard state failed: %v", err)
	}
	if len(data.Zones) != 1 {
		t.Fatalf("expected one accessible zone, got %d", len(data.Zones))
	}
	if data.Zones[0].Name != "allowed.example.org" {
		t.Fatalf("unexpected accessible zone %q", data.Zones[0].Name)
	}
	if data.SelectedZone == nil || data.SelectedZone.Name != "allowed.example.org" {
		t.Fatalf("expected selected zone to be accessible one, got %+v", data.SelectedZone)
	}
}
