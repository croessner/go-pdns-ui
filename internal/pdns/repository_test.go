package pdns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/go-pdns-ui/internal/domain"
)

func TestApplyZoneEnablesDNSSECWithSeparateKSKAndZSK(t *testing.T) {
	t.Parallel()

	type request struct {
		method string
		path   string
		body   map[string]any
	}

	requests := make([]request, 0, 6)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if r.Body != nil && r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
		}
		requests = append(requests, request{method: r.Method, path: r.URL.Path, body: body})

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/servers/localhost/zones/example.org.":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"example.org.","kind":"Native","dnssec":false,"rrsets":[]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cryptokeys"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if body["keytype"] == "ksk" {
				_, _ = w.Write([]byte(`{"id":11,"keytype":"csk","active":false,"published":true}`))
			} else {
				_, _ = w.Write([]byte(`{"id":12,"keytype":"zsk","active":false,"published":true}`))
			}
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/cryptokeys/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/cryptokeys"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":11,"keytype":"ksk","active":true,"published":true},{"id":12,"keytype":"zsk","active":true,"published":true}]`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	repo := newTestRepository(server.URL)
	err := repo.ApplyZone(context.Background(), domain.Zone{
		Name:          "example.org",
		Kind:          domain.ZoneForward,
		DNSSECEnabled: true,
	})
	if err != nil {
		t.Fatalf("enable DNSSEC: %v", err)
	}

	if len(requests) != 6 {
		t.Fatalf("expected zone read, two key creations and two activations, got %+v", requests)
	}
	wantMethods := []string{http.MethodGet, http.MethodPost, http.MethodPost, http.MethodPut, http.MethodPut, http.MethodGet}
	gotMethods := make([]string, 0, len(requests))
	for _, got := range requests {
		gotMethods = append(gotMethods, got.method)
	}
	if !slices.Equal(gotMethods, wantMethods) {
		t.Fatalf("unexpected request methods: got %v, want %v", gotMethods, wantMethods)
	}

	for index, keyType := range []string{"ksk", "zsk"} {
		body := requests[index+1].body
		if body["keytype"] != keyType || body["active"] != false || body["published"] != true {
			t.Fatalf("unexpected %s creation payload: %+v", keyType, body)
		}
	}
	if !strings.HasSuffix(requests[3].path, "/cryptokeys/12") {
		t.Fatalf("expected ZSK to be activated first, got %s", requests[3].path)
	}
	if !strings.HasSuffix(requests[4].path, "/cryptokeys/11") {
		t.Fatalf("expected KSK to be activated second, got %s", requests[4].path)
	}
	for _, got := range requests[3:5] {
		if got.body["active"] != true || got.body["published"] != true {
			t.Fatalf("unexpected activation payload for %s: %+v", got.path, got.body)
		}
	}
}

func TestCreateZoneDoesNotRequestDefaultCSK(t *testing.T) {
	t.Parallel()

	var createBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/servers/localhost/zones":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatalf("decode create-zone body: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/servers/localhost/zones/example.org.":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"example.org.","kind":"Native","dnssec":false,"rrsets":[]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cryptokeys"):
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode cryptokey body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if body["keytype"] == "ksk" {
				_, _ = w.Write([]byte(`{"id":21}`))
			} else {
				_, _ = w.Write([]byte(`{"id":22}`))
			}
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/cryptokeys/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/cryptokeys"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":21,"keytype":"ksk","active":true,"published":true},{"id":22,"keytype":"zsk","active":true,"published":true}]`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	repo := newTestRepository(server.URL)
	err := repo.CreateZone(context.Background(), domain.Zone{
		Name:          "example.org",
		Kind:          domain.ZoneForward,
		DNSSECEnabled: true,
	})
	if err != nil {
		t.Fatalf("create DNSSEC zone: %v", err)
	}
	if createBody["dnssec"] != false {
		t.Fatalf("zone creation must not ask PowerDNS to generate its default CSK: %+v", createBody)
	}
}

func TestApplyZoneCleansUpInactiveKSKWhenZSKCreationFails(t *testing.T) {
	t.Parallel()

	var methodsAndPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methodsAndPaths = append(methodsAndPaths, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/servers/localhost/zones/example.org.":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"example.org.","kind":"Native","dnssec":false,"rrsets":[]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cryptokeys"):
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode cryptokey body: %v", err)
			}
			if body["keytype"] == "zsk" {
				http.Error(w, `{"error":"generation failed"}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":31}`))
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/cryptokeys/31"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/cryptokeys/31"):
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	repo := newTestRepository(server.URL)
	err := repo.ApplyZone(context.Background(), domain.Zone{
		Name:          "example.org",
		Kind:          domain.ZoneForward,
		DNSSECEnabled: true,
	})
	if err == nil {
		t.Fatal("expected ZSK generation failure")
	}

	want := []string{
		"GET /servers/localhost/zones/example.org.",
		"POST /servers/localhost/zones/example.org./cryptokeys",
		"POST /servers/localhost/zones/example.org./cryptokeys",
		"PUT /servers/localhost/zones/example.org./cryptokeys/31",
		"DELETE /servers/localhost/zones/example.org./cryptokeys/31",
	}
	if !slices.Equal(methodsAndPaths, want) {
		t.Fatalf("unexpected cleanup requests: got %v, want %v", methodsAndPaths, want)
	}
}

func newTestRepository(baseURL string) *Repository {
	client := NewClient(Config{BaseURL: baseURL, APIKey: "test"}, nil)
	return NewRepository(client, "localhost", nil)
}

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
