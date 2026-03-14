package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/croessner/go-pdns-ui/internal/domain"
)

func TestParseZoneRFCTextBasic(t *testing.T) {
	t.Parallel()

	input := `
$ORIGIN example.org.
$TTL 7200
@ IN SOA ns1.example.org. hostmaster.example.org. 2026031401 10800 3600 604800 3600
@ IN NS ns1.example.org.
www IN A 192.0.2.10
api 300 IN AAAA 2001:db8::1
`

	records, err := parseZoneRFCText("example.org", input)
	if err != nil {
		t.Fatalf("parseZoneRFCText failed: %v", err)
	}

	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}

	a, exists := findRecord(records, "www", "A")
	if !exists {
		t.Fatalf("expected A record for www")
	}
	if a.TTL != 7200 {
		t.Fatalf("expected inherited ttl 7200, got %d", a.TTL)
	}

	aaaa, exists := findRecord(records, "api", "AAAA")
	if !exists {
		t.Fatalf("expected AAAA record for api")
	}
	if aaaa.TTL != 300 {
		t.Fatalf("expected explicit ttl 300, got %d", aaaa.TTL)
	}
}

func TestParseZoneRFCTextRejectsDuplicateNameType(t *testing.T) {
	t.Parallel()

	input := `
$ORIGIN example.org.
@ IN SOA ns1.example.org. hostmaster.example.org. 2026031401 10800 3600 604800 3600
www IN A 192.0.2.10
www IN A 192.0.2.20
`

	_, err := parseZoneRFCText("example.org", input)
	if err == nil {
		t.Fatalf("expected duplicate name+type parse error")
	}
}

func TestImportZoneRFCRouteReplacesDraftRecords(t *testing.T) {
	t.Parallel()

	mux, authSvc, zoneSvc := newPTRTestMux(t, []domain.Zone{
		{
			Name: "example.org",
			Kind: domain.ZoneForward,
			Records: []domain.Record{
				{Name: "@", Type: "SOA", TTL: 3600, Content: "ns1.example.org. hostmaster.example.org. 1 10800 3600 604800 3600"},
				{Name: "@", Type: "NS", TTL: 3600, Content: "ns1.example.org."},
				{Name: "old", Type: "A", TTL: 3600, Content: "192.0.2.5"},
			},
		},
	})

	session, err := authSvc.LoginWithPassword("admin", "admin")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	zoneText := strings.TrimSpace(`
$ORIGIN example.org.
$TTL 1800
@ IN SOA ns1.example.org. hostmaster.example.org. 2026031401 10800 3600 604800 3600
@ IN NS ns1.example.org.
www IN A 192.0.2.10
`)

	form := url.Values{
		"csrf_token":        []string{session.CSRFToken},
		"zone_data":         []string{zoneText},
		"q":                 []string{""},
		"page":              []string{"1"},
		"tab":               []string{"zones"},
		"selected_template": []string{""},
	}

	req := httptest.NewRequest(http.MethodPost, "/zones/example.org/import", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID, Path: "/"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	draft, err := zoneSvc.GetDraft(context.Background(), "example.org")
	if err != nil {
		t.Fatalf("get draft failed: %v", err)
	}
	if _, exists := findRecord(draft.Records, "old", "A"); exists {
		t.Fatalf("expected stale old A record to be removed by full import")
	}
	if imported, exists := findRecord(draft.Records, "www", "A"); !exists || imported.Content != "192.0.2.10" {
		t.Fatalf("expected imported A record to exist, got exists=%v record=%+v", exists, imported)
	}
}

func TestExportZoneRFCRouteReturnsZoneText(t *testing.T) {
	t.Parallel()

	mux, authSvc, _ := newPTRTestMux(t, []domain.Zone{
		{
			Name: "example.org",
			Kind: domain.ZoneForward,
			Records: []domain.Record{
				{Name: "@", Type: "SOA", TTL: 3600, Content: "ns1.example.org. hostmaster.example.org. 1 10800 3600 604800 3600"},
				{Name: "@", Type: "NS", TTL: 3600, Content: "ns1.example.org."},
				{Name: "www", Type: "A", TTL: 3600, Content: "192.0.2.10"},
			},
		},
	})

	session, err := authSvc.LoginWithPassword("admin", "admin")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	form := url.Values{
		"csrf_token": []string{session.CSRFToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/zones/example.org/export", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID, Path: "/"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "$ORIGIN example.org.") {
		t.Fatalf("expected export to contain $ORIGIN, got: %s", body)
	}
	if !strings.Contains(body, "www\t3600\tIN\tA\t192.0.2.10") {
		t.Fatalf("expected export to contain A record line, got: %s", body)
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, "example.org.zone") {
		t.Fatalf("expected zone filename in content-disposition, got %q", got)
	}
}
