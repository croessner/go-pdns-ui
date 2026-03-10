package domain

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCreateZoneValidatesReverseSuffixes(t *testing.T) {
	t.Parallel()

	repo := NewInMemoryZoneRepository(nil)
	svc := NewDraftZoneService(repo)
	ctx := context.Background()

	err := svc.CreateZone(ctx, Zone{
		Name: "10.0.0.0",
		Kind: ZoneReverseV4,
	})
	if err == nil {
		t.Fatalf("expected validation error for reverse-v4 zone without suffix")
	}

	err = svc.CreateZone(ctx, Zone{
		Name: "0.0.10.in-addr.arpa",
		Kind: ZoneReverseV4,
	})
	if err != nil {
		t.Fatalf("expected valid reverse-v4 zone, got error: %v", err)
	}
}

func TestSaveRecordApplyAndResetDraft(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := NewInMemoryZoneRepository([]Zone{
		{
			Name: "example.org",
			Kind: ZoneForward,
			Records: []Record{
				{
					Name:    "www",
					Type:    "A",
					TTL:     300,
					Content: "192.0.2.10",
				},
			},
		},
	})
	svc := NewDraftZoneService(repo)

	if err := svc.SaveRecord(ctx, "example.org", "", "", Record{
		Name:    "api",
		Type:    "a",
		TTL:     120,
		Content: "192.0.2.11",
	}); err != nil {
		t.Fatalf("save record failed: %v", err)
	}

	dirty, err := svc.IsDraftDirty(ctx, "example.org")
	if err != nil {
		t.Fatalf("unexpected IsDraftDirty error: %v", err)
	}
	if !dirty {
		t.Fatalf("draft should be dirty after save")
	}

	if err := svc.Apply(ctx, "example.org"); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	dirty, err = svc.IsDraftDirty(ctx, "example.org")
	if err != nil {
		t.Fatalf("unexpected IsDraftDirty error after apply: %v", err)
	}
	if dirty {
		t.Fatalf("draft should be clean after apply")
	}

	if err := svc.SaveRecord(ctx, "example.org", "", "", Record{
		Name:    "new",
		Type:    "TXT",
		TTL:     60,
		Content: "\"hello\"",
	}); err != nil {
		t.Fatalf("save record for reset failed: %v", err)
	}

	if err := svc.ResetDraft(ctx, "example.org"); err != nil {
		t.Fatalf("reset draft failed: %v", err)
	}

	zone, err := svc.GetDraft(ctx, "example.org")
	if err != nil {
		t.Fatalf("get draft failed: %v", err)
	}

	for _, rec := range zone.Records {
		if rec.Name == "new" && rec.Type == "TXT" {
			t.Fatalf("expected reset draft to remove unsaved txt record")
		}
	}
}

type zoneRepoStub struct {
	listZones []Zone
	getZones  map[string]Zone
}

func (s *zoneRepoStub) ListZones(_ context.Context) ([]Zone, error) {
	result := make([]Zone, len(s.listZones))
	copy(result, s.listZones)
	return result, nil
}

func (s *zoneRepoStub) GetZone(_ context.Context, zoneName string) (Zone, error) {
	zone, ok := s.getZones[zoneName]
	if !ok {
		return Zone{}, ErrZoneNotFound
	}
	return cloneZone(zone), nil
}

func (s *zoneRepoStub) CreateZone(_ context.Context, zone Zone) error {
	return nil
}

func (s *zoneRepoStub) DeleteZone(_ context.Context, zoneName string) error {
	return nil
}

func (s *zoneRepoStub) ApplyZone(_ context.Context, zone Zone) error {
	return nil
}

func TestListZonesDoesNotSeedEmptyDraftFromShallowZoneList(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := &zoneRepoStub{
		listZones: []Zone{
			{
				Name: "exampleserver.de",
				Kind: ZoneForward,
			},
		},
		getZones: map[string]Zone{
			"exampleserver.de": {
				Name: "exampleserver.de",
				Kind: ZoneForward,
				Records: []Record{
					{
						Name:    "www",
						Type:    "A",
						TTL:     3600,
						Content: "192.0.2.10",
					},
				},
			},
		},
	}
	svc := NewDraftZoneService(repo)

	if _, err := svc.ListZones(ctx); err != nil {
		t.Fatalf("list zones failed: %v", err)
	}

	draft, err := svc.GetDraft(ctx, "exampleserver.de")
	if err != nil {
		t.Fatalf("get draft failed: %v", err)
	}

	if len(draft.Records) != 1 || draft.Records[0].Name != "www" {
		t.Fatalf("expected draft records from GetZone, got %+v", draft.Records)
	}
}

func TestDefaultRecordsSOAUsesFQDNTargets(t *testing.T) {
	t.Parallel()

	records := defaultRecords("example.org")
	if len(records) < 2 {
		t.Fatalf("expected default records to contain SOA and NS, got %d", len(records))
	}

	soa := records[0]
	if soa.Type != "SOA" {
		t.Fatalf("expected first default record to be SOA, got %s", soa.Type)
	}

	parts := strings.Fields(soa.Content)
	if len(parts) < 2 {
		t.Fatalf("unexpected SOA content: %q", soa.Content)
	}
	if !strings.HasSuffix(parts[0], ".") || !strings.HasSuffix(parts[1], ".") {
		t.Fatalf("expected SOA primary and hostmaster to be FQDNs, got %q", soa.Content)
	}

	ns := records[1]
	if ns.Type != "NS" || !strings.HasSuffix(ns.Content, ".") {
		t.Fatalf("expected NS default target as FQDN, got %+v", ns)
	}
}

func TestSaveRecordTXTPlainContentGetsQuoted(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := NewInMemoryZoneRepository([]Zone{
		{
			Name: "example.org",
			Kind: ZoneForward,
		},
	})
	svc := NewDraftZoneService(repo)

	if err := svc.SaveRecord(ctx, "example.org", "", "", Record{
		Name:    "@",
		Type:    "TXT",
		TTL:     3600,
		Content: "plain text value",
	}); err != nil {
		t.Fatalf("save txt record failed: %v", err)
	}

	zone, err := svc.GetDraft(ctx, "example.org")
	if err != nil {
		t.Fatalf("get draft failed: %v", err)
	}

	record, ok := findRecord(zone.Records, "@", "TXT")
	if !ok {
		t.Fatalf("expected TXT record in draft")
	}
	if record.Content != "\"plain text value\"" {
		t.Fatalf("expected quoted TXT content, got %q", record.Content)
	}
}

func TestSaveRecordSRVValidation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := NewInMemoryZoneRepository([]Zone{
		{
			Name: "example.org",
			Kind: ZoneForward,
		},
	})
	svc := NewDraftZoneService(repo)

	err := svc.SaveRecord(ctx, "example.org", "", "", Record{
		Name:    "_sip._tcp",
		Type:    "SRV",
		TTL:     3600,
		Content: "10 5 target.example.org.",
	})
	if !errors.Is(err, ErrInvalidRec) {
		t.Fatalf("expected invalid record error for malformed SRV, got %v", err)
	}

	if err := svc.SaveRecord(ctx, "example.org", "", "", Record{
		Name:    "_sip._tcp",
		Type:    "SRV",
		TTL:     3600,
		Content: "10 5 5060 sip.example.org.",
	}); err != nil {
		t.Fatalf("expected valid SRV record, got %v", err)
	}
}

func TestSaveRecordAddressValidation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	repo := NewInMemoryZoneRepository([]Zone{
		{
			Name: "example.org",
			Kind: ZoneForward,
		},
	})
	svc := NewDraftZoneService(repo)

	if err := svc.SaveRecord(ctx, "example.org", "", "", Record{
		Name:    "www",
		Type:    "A",
		TTL:     3600,
		Content: "example.org",
	}); !errors.Is(err, ErrInvalidRec) {
		t.Fatalf("expected invalid record for A without IPv4, got %v", err)
	}

	if err := svc.SaveRecord(ctx, "example.org", "", "", Record{
		Name:    "www",
		Type:    "AAAA",
		TTL:     3600,
		Content: "192.0.2.1",
	}); !errors.Is(err, ErrInvalidRec) {
		t.Fatalf("expected invalid record for AAAA with IPv4, got %v", err)
	}
}

func findRecord(records []Record, name, recordType string) (Record, bool) {
	for _, record := range records {
		if record.Name == name && record.Type == recordType {
			return record, true
		}
	}
	return Record{}, false
}
