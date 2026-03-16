package ui

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/go-pdns-ui/internal/assets"
	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
	"github.com/croessner/go-pdns-ui/internal/i18n"
)

func TestLoginPageThemeBootstrapRegression(t *testing.T) {
	t.Parallel()

	mux, _ := newThemeTestMux(t)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	assertContainsAll(t, body,
		`window.__goPDNSUITheme = { applyTheme, resolveTheme };`,
		`<body class="min-h-screen bg-base-200 text-base-content">`,
		`<script src="/assets/login.js" defer></script>`,
	)
	assertThemeBootstrapBeforeStylesheet(t, body)
}

func TestDashboardPageThemeBootstrapRegression(t *testing.T) {
	t.Parallel()

	mux, authSvc := newThemeTestMux(t)

	session, err := authSvc.LoginWithPassword("admin", "admin")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID, Path: "/"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	assertContainsAll(t, body,
		`window.__goPDNSUITheme = { applyTheme, resolveTheme };`,
		`<body class="min-h-screen bg-base-200 text-base-content">`,
		`<script src="/assets/dashboard.js" defer></script>`,
		`id="zone-search-input"`,
		`type="submit" class="btn btn-primary join-item">Search</button>`,
	)
	assertThemeBootstrapBeforeStylesheet(t, body)
}

func newThemeTestMux(t *testing.T) (*http.ServeMux, *auth.InMemoryService) {
	return newThemeTestMuxWithOptions(t, HandlerOptions{})
}

func TestLoginPageHidesPasswordFormWhenOIDCOnly(t *testing.T) {
	t.Parallel()

	mux, _ := newThemeTestMuxWithOptions(t, HandlerOptions{OIDCOnlyLogin: true})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, `action="/login/password"`) {
		t.Fatalf("expected password login form to be hidden in oidc-only mode")
	}
	if strings.Contains(body, "Local password login is disabled.") {
		t.Fatalf("expected no oidc-only hint in response body")
	}
}

func TestPasswordLoginRouteBlockedWhenOIDCOnly(t *testing.T) {
	t.Parallel()

	mux, _ := newThemeTestMuxWithOptions(t, HandlerOptions{OIDCOnlyLogin: true})

	req := httptest.NewRequest(http.MethodPost, "/login/password", strings.NewReader("username=admin&password=admin"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Local password login is disabled.") {
		t.Fatalf("expected no oidc-only login hint in response")
	}
}

func TestStaticScriptAssetsAreServed(t *testing.T) {
	t.Parallel()

	mux, _ := newThemeTestMux(t)

	loginReq := httptest.NewRequest(http.MethodGet, "/assets/login.js", nil)
	loginRec := httptest.NewRecorder()
	mux.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("expected login.js status %d, got %d", http.StatusOK, loginRec.Code)
	}
	if !strings.Contains(loginRec.Body.String(), "const themeController = window.__goPDNSUITheme || null;") {
		t.Fatalf("expected login.js payload to be served")
	}

	dashboardReq := httptest.NewRequest(http.MethodGet, "/assets/dashboard.js", nil)
	dashboardRec := httptest.NewRecorder()
	mux.ServeHTTP(dashboardRec, dashboardReq)
	if dashboardRec.Code != http.StatusOK {
		t.Fatalf("expected dashboard.js status %d, got %d", http.StatusOK, dashboardRec.Code)
	}
	if !strings.Contains(dashboardRec.Body.String(), "document.body.addEventListener(\"htmx:afterSwap\"") {
		t.Fatalf("expected dashboard.js payload to be served")
	}
}

func newThemeTestMuxWithOptions(t *testing.T, options HandlerOptions) (*http.ServeMux, *auth.InMemoryService) {
	t.Helper()

	i18nSvc, err := i18n.NewService(assets.Files, "locales", "en")
	if err != nil {
		t.Fatalf("new i18n service failed: %v", err)
	}

	zoneSvc := domain.NewDraftZoneService(domain.NewInMemoryZoneRepository([]domain.Zone{
		{
			Name: "example.org",
			Kind: domain.ZoneForward,
			Records: []domain.Record{
				{
					Name:    "@",
					Type:    "SOA",
					TTL:     3600,
					Content: "ns1.example.org. hostmaster.example.org. 1 10800 3600 604800 3600",
				},
				{
					Name:    "@",
					Type:    "NS",
					TTL:     3600,
					Content: "ns1.example.org.",
				},
			},
		},
	}))
	templateSvc := domain.NewInMemoryZoneTemplateService(nil)

	authSvc, err := auth.NewInMemoryService(context.Background(), "admin", "admin", auth.OIDCConfig{})
	if err != nil {
		t.Fatalf("new auth service failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewHandler(assets.Files, zoneSvc, templateSvc, authSvc, i18nSvc, nil, nil, options, logger)
	if err != nil {
		t.Fatalf("new handler failed: %v", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	return mux, authSvc
}

func assertContainsAll(t *testing.T, body string, snippets ...string) {
	t.Helper()

	for _, snippet := range snippets {
		if !strings.Contains(body, snippet) {
			t.Fatalf("expected response to contain snippet %q", snippet)
		}
	}
}

func assertThemeBootstrapBeforeStylesheet(t *testing.T, body string) {
	t.Helper()

	bootstrapIdx := strings.Index(body, `window.__goPDNSUITheme = { applyTheme, resolveTheme };`)
	stylesheetIdx := strings.Index(body, `<link href="https://cdn.jsdelivr.net/npm/daisyui@5"`)

	if bootstrapIdx == -1 {
		t.Fatalf("expected theme bootstrap snippet before stylesheet")
	}
	if stylesheetIdx == -1 {
		t.Fatalf("expected daisyui stylesheet link")
	}
	if bootstrapIdx > stylesheetIdx {
		t.Fatalf("expected theme bootstrap script before daisyui stylesheet link")
	}
}
