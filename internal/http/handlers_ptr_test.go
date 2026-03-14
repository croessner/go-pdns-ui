package ui

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/croessner/go-pdns-ui/internal/assets"
	"github.com/croessner/go-pdns-ui/internal/audit"
	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
	"github.com/croessner/go-pdns-ui/internal/i18n"
)

func TestResolvePTRTargetIPv4LongestReverseZoneMatch(t *testing.T) {
	t.Parallel()

	target, ok := resolvePTRTarget(
		"example.org",
		domain.Record{Name: "www", Type: "A", Content: "192.0.2.10"},
		[]domain.Zone{
			{Name: "0.192.in-addr.arpa", Kind: domain.ZoneReverseV4},
			{Name: "2.0.192.in-addr.arpa", Kind: domain.ZoneReverseV4},
		},
	)
	if !ok {
		t.Fatalf("expected reverse target to resolve")
	}
	if target.ReverseZone != "2.0.192.in-addr.arpa" {
		t.Fatalf("expected longest matching reverse zone, got %q", target.ReverseZone)
	}
	if target.RecordName != "10" {
		t.Fatalf("expected reverse record name 10, got %q", target.RecordName)
	}
	if target.Content != "www.example.org." {
		t.Fatalf("expected PTR content www.example.org., got %q", target.Content)
	}
}

func TestPtrDomainForAddrIPv6(t *testing.T) {
	t.Parallel()

	addr, err := netip.ParseAddr("2001:db8::1")
	if err != nil {
		t.Fatalf("parse addr failed: %v", err)
	}

	ptrDomain, kind := ptrDomainForAddr(addr)
	if kind != domain.ZoneReverseV6 {
		t.Fatalf("expected reverse-v6 kind, got %q", kind)
	}

	const expected = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	if ptrDomain != expected {
		t.Fatalf("unexpected v6 ptr domain %q", ptrDomain)
	}
}

func TestBuildDashboardStatePTRAddActionVisibility(t *testing.T) {
	t.Parallel()

	i18nSvc, err := i18n.NewService(assets.Files, "locales", "en")
	if err != nil {
		t.Fatalf("new i18n service failed: %v", err)
	}

	zoneSvc := domain.NewDraftZoneService(domain.NewInMemoryZoneRepository([]domain.Zone{
		{
			Name: "example.org",
			Kind: domain.ZoneForward,
			Records: []domain.Record{
				{Name: "www", Type: "A", TTL: 3600, Content: "192.0.2.10"},
			},
		},
		{Name: "2.0.192.in-addr.arpa", Kind: domain.ZoneReverseV4},
	}))
	templateSvc := domain.NewInMemoryZoneTemplateService(nil)
	authSvc, err := auth.NewInMemoryService(context.Background(), "admin", "admin", auth.OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}

	h := &Handler{
		zones:         zoneSvc,
		zoneTemplates: templateSvc,
		auth:          authSvc,
		access:        &accessStub{},
		audit:         audit.NewNoopService(),
		i18n:          i18nSvc,
	}

	data, err := h.buildDashboardState(context.Background(), "en", "", 1, "example.org", "", "", auth.Session{User: auth.User{Role: auth.RoleUser}})
	if err != nil {
		t.Fatalf("build dashboard state failed: %v", err)
	}

	key := recordActionKey(domain.Record{Name: "www", Type: "A", Content: "192.0.2.10"})
	action, exists := data.PTRAddActionsByRecord[key]
	if !exists {
		t.Fatalf("expected PTR add action for A record")
	}
	if !action.Show {
		t.Fatalf("expected PTR add action to be visible")
	}
	if action.ReverseZone != "2.0.192.in-addr.arpa" {
		t.Fatalf("unexpected reverse zone %q", action.ReverseZone)
	}
	if action.PTRName != "10" {
		t.Fatalf("expected PTR name 10, got %q", action.PTRName)
	}
}

func TestBuildDashboardStatePTRAddActionMarkedAsReplaceWhenPTRExists(t *testing.T) {
	t.Parallel()

	i18nSvc, err := i18n.NewService(assets.Files, "locales", "en")
	if err != nil {
		t.Fatalf("new i18n service failed: %v", err)
	}

	zoneSvc := domain.NewDraftZoneService(domain.NewInMemoryZoneRepository([]domain.Zone{
		{
			Name: "example.org",
			Kind: domain.ZoneForward,
			Records: []domain.Record{
				{Name: "www", Type: "A", TTL: 3600, Content: "192.0.2.10"},
			},
		},
		{
			Name: "2.0.192.in-addr.arpa",
			Kind: domain.ZoneReverseV4,
			Records: []domain.Record{
				{Name: "10", Type: "PTR", TTL: 3600, Content: "www.example.org."},
			},
		},
	}))
	templateSvc := domain.NewInMemoryZoneTemplateService(nil)
	authSvc, err := auth.NewInMemoryService(context.Background(), "admin", "admin", auth.OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}

	h := &Handler{
		zones:         zoneSvc,
		zoneTemplates: templateSvc,
		auth:          authSvc,
		access:        &accessStub{},
		audit:         audit.NewNoopService(),
		i18n:          i18nSvc,
	}

	data, err := h.buildDashboardState(context.Background(), "en", "", 1, "example.org", "", "", auth.Session{User: auth.User{Role: auth.RoleUser}})
	if err != nil {
		t.Fatalf("build dashboard state failed: %v", err)
	}

	key := recordActionKey(domain.Record{Name: "www", Type: "A", Content: "192.0.2.10"})
	action, exists := data.PTRAddActionsByRecord[key]
	if !exists || !action.Show {
		t.Fatalf("expected PTR action to stay visible when PTR already exists")
	}
	if !action.PTRExists {
		t.Fatalf("expected PTR action to indicate replace mode")
	}
}

func TestAddPTRRecordRouteCreatesPTR(t *testing.T) {
	t.Parallel()

	mux, authSvc, zoneSvc := newPTRTestMux(t, []domain.Zone{
		{
			Name: "example.org",
			Kind: domain.ZoneForward,
			Records: []domain.Record{
				{Name: "www", Type: "A", TTL: 7200, Content: "192.0.2.10"},
			},
		},
		{Name: "2.0.192.in-addr.arpa", Kind: domain.ZoneReverseV4},
	})

	session, err := authSvc.LoginWithPassword("admin", "admin")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	form := url.Values{
		"csrf_token":        []string{session.CSRFToken},
		"source_name":       []string{"www"},
		"source_type":       []string{"A"},
		"q":                 []string{""},
		"page":              []string{"1"},
		"tab":               []string{"zones"},
		"selected_template": []string{""},
	}
	req := httptest.NewRequest(http.MethodPost, "/zones/example.org/records/ptr", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID, Path: "/"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	reverseDraft, err := zoneSvc.GetDraft(context.Background(), "2.0.192.in-addr.arpa")
	if err != nil {
		t.Fatalf("get reverse draft failed: %v", err)
	}
	ptr, exists := findRecord(reverseDraft.Records, "10", "PTR")
	if !exists {
		t.Fatalf("expected PTR record to be created in reverse zone")
	}
	if ptr.Content != "www.example.org." {
		t.Fatalf("unexpected PTR content %q", ptr.Content)
	}
	if ptr.TTL != 7200 {
		t.Fatalf("expected PTR TTL to follow source TTL, got %d", ptr.TTL)
	}
}

func TestAddPTRRecordRouteRejectsConflictingPTR(t *testing.T) {
	t.Parallel()

	mux, authSvc, zoneSvc := newPTRTestMux(t, []domain.Zone{
		{
			Name: "example.org",
			Kind: domain.ZoneForward,
			Records: []domain.Record{
				{Name: "www", Type: "A", TTL: 3600, Content: "192.0.2.10"},
			},
		},
		{
			Name: "2.0.192.in-addr.arpa",
			Kind: domain.ZoneReverseV4,
			Records: []domain.Record{
				{Name: "10", Type: "PTR", TTL: 3600, Content: "mail.example.org."},
			},
		},
	})

	session, err := authSvc.LoginWithPassword("admin", "admin")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	form := url.Values{
		"csrf_token":        []string{session.CSRFToken},
		"source_name":       []string{"www"},
		"source_type":       []string{"A"},
		"q":                 []string{""},
		"page":              []string{"1"},
		"tab":               []string{"zones"},
		"selected_template": []string{""},
	}
	req := httptest.NewRequest(http.MethodPost, "/zones/example.org/records/ptr", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID, Path: "/"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected status %d, got %d", http.StatusConflict, rec.Code)
	}

	reverseDraft, err := zoneSvc.GetDraft(context.Background(), "2.0.192.in-addr.arpa")
	if err != nil {
		t.Fatalf("get reverse draft failed: %v", err)
	}
	ptr, exists := findRecord(reverseDraft.Records, "10", "PTR")
	if !exists {
		t.Fatalf("expected existing PTR record to remain")
	}
	if ptr.Content != "mail.example.org." {
		t.Fatalf("expected PTR content to remain unchanged, got %q", ptr.Content)
	}
}

func TestAddPTRRecordRouteReplacesConflictingPTRWhenConfirmed(t *testing.T) {
	t.Parallel()

	mux, authSvc, zoneSvc := newPTRTestMux(t, []domain.Zone{
		{
			Name: "example.org",
			Kind: domain.ZoneForward,
			Records: []domain.Record{
				{Name: "www", Type: "A", TTL: 1800, Content: "192.0.2.10"},
			},
		},
		{
			Name: "2.0.192.in-addr.arpa",
			Kind: domain.ZoneReverseV4,
			Records: []domain.Record{
				{Name: "10", Type: "PTR", TTL: 3600, Content: "mail.example.org."},
			},
		},
	})

	session, err := authSvc.LoginWithPassword("admin", "admin")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	form := url.Values{
		"csrf_token":        []string{session.CSRFToken},
		"source_name":       []string{"www"},
		"source_type":       []string{"A"},
		"replace_existing":  []string{"true"},
		"q":                 []string{""},
		"page":              []string{"1"},
		"tab":               []string{"zones"},
		"selected_template": []string{""},
	}
	req := httptest.NewRequest(http.MethodPost, "/zones/example.org/records/ptr", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID, Path: "/"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	reverseDraft, err := zoneSvc.GetDraft(context.Background(), "2.0.192.in-addr.arpa")
	if err != nil {
		t.Fatalf("get reverse draft failed: %v", err)
	}
	ptr, exists := findRecord(reverseDraft.Records, "10", "PTR")
	if !exists {
		t.Fatalf("expected PTR record to exist")
	}
	if ptr.Content != "www.example.org." {
		t.Fatalf("expected PTR content to be replaced, got %q", ptr.Content)
	}
	if ptr.TTL != 1800 {
		t.Fatalf("expected PTR TTL to follow source TTL, got %d", ptr.TTL)
	}
}

func newPTRTestMux(t *testing.T, zones []domain.Zone) (*http.ServeMux, *auth.InMemoryService, *domain.DraftZoneService) {
	t.Helper()

	i18nSvc, err := i18n.NewService(assets.Files, "locales", "en")
	if err != nil {
		t.Fatalf("new i18n service failed: %v", err)
	}

	zoneSvc := domain.NewDraftZoneService(domain.NewInMemoryZoneRepository(zones))
	templateSvc := domain.NewInMemoryZoneTemplateService(nil)
	authSvc, err := auth.NewInMemoryService(context.Background(), "admin", "admin", auth.OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewHandler(assets.Files, zoneSvc, templateSvc, authSvc, i18nSvc, nil, nil, HandlerOptions{}, logger)
	if err != nil {
		t.Fatalf("new handler failed: %v", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	return mux, authSvc, zoneSvc
}
