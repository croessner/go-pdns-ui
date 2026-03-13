package domain

import (
	"testing"
)

func TestCNAMEConflictDetected(t *testing.T) {
	t.Parallel()

	zone := Zone{
		Name: "example.org",
		Kind: ZoneForward,
		Records: []Record{
			{Name: "www", Type: "CNAME", Content: "cdn.example.org."},
			{Name: "www", Type: "A", Content: "192.0.2.1"},
		},
	}

	warnings := ValidateZoneRecords(zone)
	if len(warnings) == 0 {
		t.Fatal("expected CNAME conflict warning")
	}
	if warnings[0].Code != "cname_conflict" {
		t.Fatalf("expected cname_conflict code, got %q", warnings[0].Code)
	}
}

func TestNoCNAMEConflictWhenAlone(t *testing.T) {
	t.Parallel()

	zone := Zone{
		Name: "example.org",
		Kind: ZoneForward,
		Records: []Record{
			{Name: "www", Type: "CNAME", Content: "cdn.example.org."},
			{Name: "mail", Type: "A", Content: "192.0.2.1"},
		},
	}

	warnings := ValidateZoneRecords(zone)
	for _, w := range warnings {
		if w.Code == "cname_conflict" {
			t.Fatal("unexpected CNAME conflict warning when CNAME is alone")
		}
	}
}

func TestMXInvalidHostname(t *testing.T) {
	t.Parallel()

	zone := Zone{
		Name: "example.org",
		Kind: ZoneForward,
		Records: []Record{
			{Name: "@", Type: "MX", Content: "10 192.0.2.1"},
		},
	}

	warnings := ValidateZoneRecords(zone)
	found := false
	for _, w := range warnings {
		if w.Code == "mx_invalid_hostname" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected mx_invalid_hostname warning for IP target")
	}
}

func TestMXValidHostname(t *testing.T) {
	t.Parallel()

	zone := Zone{
		Name: "example.org",
		Kind: ZoneForward,
		Records: []Record{
			{Name: "@", Type: "MX", Content: "10 mail.example.org."},
		},
	}

	warnings := ValidateZoneRecords(zone)
	for _, w := range warnings {
		if w.Code == "mx_invalid_hostname" {
			t.Fatalf("unexpected mx_invalid_hostname warning for valid hostname: %+v", w)
		}
	}
}

func TestNSInvalidHostname(t *testing.T) {
	t.Parallel()

	zone := Zone{
		Name: "example.org",
		Kind: ZoneForward,
		Records: []Record{
			{Name: "@", Type: "NS", Content: "192.168.1.1"},
		},
	}

	warnings := ValidateZoneRecords(zone)
	found := false
	for _, w := range warnings {
		if w.Code == "ns_invalid_hostname" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ns_invalid_hostname warning for IP target")
	}
}

func TestDuplicateRecordDetected(t *testing.T) {
	t.Parallel()

	zone := Zone{
		Name: "example.org",
		Kind: ZoneForward,
		Records: []Record{
			{Name: "www", Type: "A", Content: "192.0.2.1"},
			{Name: "www", Type: "A", Content: "192.0.2.1"},
		},
	}

	warnings := ValidateZoneRecords(zone)
	found := false
	for _, w := range warnings {
		if w.Code == "duplicate_record" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected duplicate_record warning")
	}
}

func TestNoDuplicateWarningForDifferentContent(t *testing.T) {
	t.Parallel()

	zone := Zone{
		Name: "example.org",
		Kind: ZoneForward,
		Records: []Record{
			{Name: "www", Type: "A", Content: "192.0.2.1"},
			{Name: "www", Type: "A", Content: "192.0.2.2"},
		},
	}

	warnings := ValidateZoneRecords(zone)
	for _, w := range warnings {
		if w.Code == "duplicate_record" {
			t.Fatal("unexpected duplicate_record warning for different content")
		}
	}
}

func TestIsValidHostname(t *testing.T) {
	t.Parallel()

	valid := []string{
		"mail.example.org.",
		"ns1.example.org",
		"a.b.c",
		"my-host.example.com",
	}
	for _, h := range valid {
		if !isValidHostname(h) {
			t.Errorf("expected %q to be valid hostname", h)
		}
	}

	invalid := []string{
		"192.0.2.1",
		"10.0.0.1",
		"::1",
		"2001:db8::1",
		"",
		"-invalid.org",
		"inv..alid.org",
	}
	for _, h := range invalid {
		if isValidHostname(h) {
			t.Errorf("expected %q to be invalid hostname", h)
		}
	}
}

func TestFormatWarningWithCatalog(t *testing.T) {
	t.Parallel()

	catalog := map[string]string{
		"lint_cname_conflict": "CNAME conflict: \"{name}\" has CNAME with {detail}.",
	}

	w := ValidationWarning{
		Code:       "cname_conflict",
		RecordName: "www",
		RecordType: "CNAME",
		Detail:     "A",
	}

	msg := FormatWarning(w, catalog)
	expected := "CNAME conflict: \"www\" has CNAME with A."
	if msg != expected {
		t.Fatalf("expected %q, got %q", expected, msg)
	}
}

func TestFormatWarningFallback(t *testing.T) {
	t.Parallel()

	w := ValidationWarning{
		Code:       "unknown_code",
		RecordName: "www",
		RecordType: "A",
		Detail:     "some detail",
	}

	msg := FormatWarning(w, nil)
	if msg == "" {
		t.Fatal("expected non-empty fallback message")
	}
}

func TestCleanZoneNoWarnings(t *testing.T) {
	t.Parallel()

	zone := Zone{
		Name: "example.org",
		Kind: ZoneForward,
		Records: []Record{
			{Name: "@", Type: "SOA", Content: "ns1.example.org. hostmaster.example.org. 1 10800 3600 604800 3600"},
			{Name: "@", Type: "NS", Content: "ns1.example.org."},
			{Name: "@", Type: "NS", Content: "ns2.example.org."},
			{Name: "@", Type: "MX", Content: "10 mail.example.org."},
			{Name: "www", Type: "A", Content: "192.0.2.1"},
			{Name: "mail", Type: "A", Content: "192.0.2.2"},
		},
	}

	warnings := ValidateZoneRecords(zone)
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for clean zone, got %d: %+v", len(warnings), warnings)
	}
}
