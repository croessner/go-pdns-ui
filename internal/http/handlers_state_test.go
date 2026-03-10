package ui

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/croessner/go-pdns-ui/internal/assets"
	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
	"github.com/croessner/go-pdns-ui/internal/i18n"
)

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
	}
	authSvc, err := auth.NewInMemoryService(context.Background(), "admin", "admin", auth.OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}
	h.auth = authSvc

	userSession := auth.Session{User: auth.User{Role: auth.RoleUser}}
	userData, err := h.buildDashboardState(context.Background(), "en", "", 1, "example.org", "Forward Basic", userSession)
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
	adminData, err := h.buildDashboardState(context.Background(), "en", "", 1, "example.org", "Forward Basic", adminSession)
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
