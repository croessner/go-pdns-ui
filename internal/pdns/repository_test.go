package pdns

import (
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
