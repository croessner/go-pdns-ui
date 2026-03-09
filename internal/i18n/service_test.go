package i18n

import (
	"testing"
	"testing/fstest"
)

func TestCatalogFallbackAndOverrides(t *testing.T) {
	t.Parallel()

	files := fstest.MapFS{
		"locales/en.json": {Data: []byte(`{"hello":"Hello","bye":"Bye"}`)},
		"locales/de.json": {Data: []byte(`{"hello":"Hallo"}`)},
	}

	svc, err := NewService(files, "locales", "en")
	if err != nil {
		t.Fatalf("new service failed: %v", err)
	}

	de := svc.Catalog("de-DE")
	if de["hello"] != "Hallo" {
		t.Fatalf("expected german override for hello, got %q", de["hello"])
	}
	if de["bye"] != "Bye" {
		t.Fatalf("expected fallback value for bye, got %q", de["bye"])
	}
}

func TestNormalizeFallsBackToDefault(t *testing.T) {
	t.Parallel()

	files := fstest.MapFS{
		"locales/en.json": {Data: []byte(`{"k":"v"}`)},
	}

	svc, err := NewService(files, "locales", "en")
	if err != nil {
		t.Fatalf("new service failed: %v", err)
	}

	if got := svc.Normalize("fr-FR"); got != "en" {
		t.Fatalf("expected fallback 'en', got %q", got)
	}
}
