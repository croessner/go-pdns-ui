package pdns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientRetriesWithAPIV1SuffixOnNotFound(t *testing.T) {
	t.Parallel()

	rootHits := 0
	apiHits := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/servers/localhost/zones":
			rootHits++
			http.Error(w, `{"error":"Not Found"}`, http.StatusNotFound)
		case "/api/v1/servers/localhost/zones":
			apiHits++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"example.org.","kind":"Native","dnssec":false}]`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
		Timeout: time.Second,
	}, nil)

	var zones []pdnsZone
	if err := client.get(context.Background(), "/servers/localhost/zones", &zones); err != nil {
		t.Fatalf("expected fallback request to succeed, got error: %v", err)
	}

	if len(zones) != 1 || zones[0].Name != "example.org." {
		t.Fatalf("unexpected zones response: %+v", zones)
	}

	expectedBase := server.URL + "/api/v1"
	if got := client.getBaseURL(); got != expectedBase {
		t.Fatalf("expected base URL %q after fallback, got %q", expectedBase, got)
	}

	var zonesAgain []pdnsZone
	if err := client.get(context.Background(), "/servers/localhost/zones", &zonesAgain); err != nil {
		t.Fatalf("expected second request to succeed, got error: %v", err)
	}

	if rootHits != 1 {
		t.Fatalf("expected one request without /api/v1, got %d", rootHits)
	}
	if apiHits != 2 {
		t.Fatalf("expected two requests with /api/v1, got %d", apiHits)
	}
}

func TestClientReturnsRetryErrorWhenFallbackAlsoFails(t *testing.T) {
	t.Parallel()

	rootHits := 0
	apiHits := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/servers/localhost/zones":
			rootHits++
			http.Error(w, `{"error":"Not Found"}`, http.StatusNotFound)
		case "/api/v1/servers/localhost/zones":
			apiHits++
			http.Error(w, `{"error":"Not Found"}`, http.StatusNotFound)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL: server.URL,
		APIKey:  "test-key",
		Timeout: time.Second,
	}, nil)

	var zones []pdnsZone
	err := client.get(context.Background(), "/servers/localhost/zones", &zones)
	if err == nil {
		t.Fatalf("expected request to fail when fallback also returns 404")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.Status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", apiErr.Status)
	}

	if rootHits != 1 {
		t.Fatalf("expected one request without /api/v1, got %d", rootHits)
	}
	if apiHits != 1 {
		t.Fatalf("expected one fallback request with /api/v1, got %d", apiHits)
	}
}

func TestWithAPIV1Suffix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		baseURL  string
		wantURL  string
		wantOkay bool
	}{
		{
			name:     "empty path",
			baseURL:  "https://pdns.example",
			wantURL:  "https://pdns.example/api/v1",
			wantOkay: true,
		},
		{
			name:     "existing path",
			baseURL:  "https://pdns.example/pdns",
			wantURL:  "https://pdns.example/pdns/api/v1",
			wantOkay: true,
		},
		{
			name:     "already set",
			baseURL:  "https://pdns.example/api/v1",
			wantURL:  "https://pdns.example/api/v1",
			wantOkay: false,
		},
		{
			name:     "invalid",
			baseURL:  "://broken",
			wantURL:  "",
			wantOkay: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotURL, gotOkay := withAPIV1Suffix(tc.baseURL)
			if gotURL != tc.wantURL || gotOkay != tc.wantOkay {
				t.Fatalf("withAPIV1Suffix(%q) = (%q, %t), want (%q, %t)", tc.baseURL, gotURL, gotOkay, tc.wantURL, tc.wantOkay)
			}
		})
	}
}
