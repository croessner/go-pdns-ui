package pdns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/go-pdns-ui/internal/domain"
)

func TestBuildRRSetDiffIncludesReplaceAndDelete(t *testing.T) {
	t.Parallel()

	current := domain.Zone{
		Name: "example.org",
		Kind: domain.ZoneForward,
		Records: []domain.Record{
			{Name: "@", Type: "SOA", TTL: 3600, Content: "old"},
			{Name: "www", Type: "A", TTL: 300, Content: "192.0.2.1"},
		},
	}

	desired := domain.Zone{
		Name: "example.org",
		Kind: domain.ZoneForward,
		Records: []domain.Record{
			{Name: "@", Type: "SOA", TTL: 3600, Content: "new"},
			{Name: "api", Type: "A", TTL: 300, Content: "192.0.2.5"},
		},
	}

	diff := buildRRSetDiff(current, desired)
	if len(diff) != 3 {
		t.Fatalf("expected 3 rrset changes (replace soa, add api, delete www), got %d", len(diff))
	}
}

func TestZoneFromPDNSConvertsToRelativeNames(t *testing.T) {
	t.Parallel()

	zone := pdnsZone{
		Name: "example.org.",
		RRSets: []pdnsRRSet{
			{
				Name: "example.org.",
				Type: "NS",
				TTL:  3600,
				Records: []pdnsRecord{
					{Content: "ns1.example.org.", Disabled: false},
				},
			},
			{
				Name: "www.example.org.",
				Type: "A",
				TTL:  300,
				Records: []pdnsRecord{
					{Content: "192.0.2.10", Disabled: false},
				},
			},
		},
	}

	mapped := zoneFromPDNS(zone)
	if mapped.Name != "example.org" {
		t.Fatalf("expected trimmed zone name, got %q", mapped.Name)
	}

	foundRoot := false
	foundWWW := false
	for _, record := range mapped.Records {
		if record.Type == "NS" && record.Name == "@" {
			foundRoot = true
		}
		if record.Type == "A" && record.Name == "www" {
			foundWWW = true
		}
	}

	if !foundRoot || !foundWWW {
		t.Fatalf("expected @ NS and www A records after mapping, got %+v", mapped.Records)
	}
}

func TestMapRepositoryErrorNotFoundOnCollectionIsBackend(t *testing.T) {
	t.Parallel()

	err := mapRepositoryError(&APIError{
		Method: http.MethodGet,
		Path:   "/servers/unknown/zones",
		Status: http.StatusNotFound,
		Body:   "Not Found",
	})
	if !errors.Is(err, domain.ErrBackend) {
		t.Fatalf("expected backend error, got %v", err)
	}
}

func TestMapRepositoryErrorNotFoundOnZoneResourceIsZoneNotFound(t *testing.T) {
	t.Parallel()

	err := mapRepositoryError(&APIError{
		Method: http.MethodGet,
		Path:   "/servers/localhost/zones/example.org.",
		Status: http.StatusNotFound,
		Body:   "Not Found",
	})
	if !errors.Is(err, domain.ErrZoneNotFound) {
		t.Fatalf("expected zone not found, got %v", err)
	}
}

func TestListZonesFallsBackToDiscoveredServerID(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/servers/wrong/zones", func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	})
	mux.HandleFunc("/servers", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"localhost"}]`))
	})
	mux.HandleFunc("/servers/localhost/zones", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := NewClient(Config{
		BaseURL: server.URL,
		APIKey:  "test",
		Timeout: 0,
	}, nil)
	repo := NewRepository(client, "wrong", nil)

	zones, err := repo.ListZones(context.Background())
	if err != nil {
		t.Fatalf("expected fallback to discovered server ID, got error: %v", err)
	}
	if len(zones) != 0 {
		t.Fatalf("expected empty zone list, got %d entries", len(zones))
	}
	if repo.getServerID() != "localhost" {
		t.Fatalf("expected discovered server id localhost, got %q", repo.getServerID())
	}
}
