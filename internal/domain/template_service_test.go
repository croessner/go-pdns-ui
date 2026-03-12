package domain

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestTemplateServiceCreateAndEditRecord(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	svc := NewInMemoryZoneTemplateService(nil)

	err := svc.CreateTemplate(ctx, ZoneTemplate{
		Name: "Forward Basic",
		Kind: ZoneForward,
		Records: []Record{
			{
				Name:    "@",
				Type:    "soa",
				TTL:     3600,
				Content: "ns1.{{ZONE_NAME}} hostmaster.{{ZONE_NAME}} 1 10800 3600 604800 3600",
			},
		},
	})
	if err != nil {
		t.Fatalf("create template failed: %v", err)
	}

	err = svc.SaveTemplateRecord(ctx, "Forward Basic", "", "", Record{
		Name:    "www",
		Type:    "a",
		TTL:     300,
		Content: "192.0.2.20",
	})
	if err != nil {
		t.Fatalf("save template record failed: %v", err)
	}

	err = svc.SaveTemplateRecord(ctx, "Forward Basic", "@", "SOA", Record{
		Name:    "@",
		Type:    "SOA",
		TTL:     7200,
		Content: "ns1.{{ZONE_NAME}} hostmaster.{{ZONE_NAME}} 2 10800 3600 604800 3600",
	})
	if err != nil {
		t.Fatalf("update SOA template record failed: %v", err)
	}

	tpl, err := svc.GetTemplate(ctx, "Forward Basic")
	if err != nil {
		t.Fatalf("get template failed: %v", err)
	}

	found := false
	for _, rec := range tpl.Records {
		if rec.Name == "www" && rec.Type == "A" && rec.Content == "192.0.2.20" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected updated A record in template")
	}
}

func TestInstantiateTemplateRecords(t *testing.T) {
	t.Parallel()

	records := InstantiateTemplateRecords("example.org", []Record{
		{
			Name:    "@",
			Type:    "NS",
			TTL:     3600,
			Content: "ns1." + TemplateZoneNameToken,
		},
		{
			Name:    "www",
			Type:    "CNAME",
			TTL:     3600,
			Content: TemplateZoneFQDNToken,
		},
		{
			Name:    "@",
			Type:    "SOA",
			TTL:     3600,
			Content: "ns1." + TemplateZoneNameToken + " hostmaster." + TemplateZoneNameToken + " 1 10800 3600 604800 3600",
		},
	})

	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}

	if records[0].Content != "ns1.example.org." {
		t.Fatalf("expected token replacement for zone name, got %q", records[0].Content)
	}

	if records[1].Content != "example.org." {
		t.Fatalf("expected token replacement for fqdn, got %q", records[1].Content)
	}

	soaParts := strings.Fields(records[2].Content)
	if len(soaParts) < 2 {
		t.Fatalf("unexpected SOA content after instantiation: %q", records[2].Content)
	}
	if soaParts[0] != "ns1.example.org." || soaParts[1] != "hostmaster.example.org." {
		t.Fatalf("expected SOA hostnames to be FQDNs, got %q", records[2].Content)
	}
}

func TestTemplateServiceValidatesSRVRecord(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	svc := NewInMemoryZoneTemplateService(nil)

	if err := svc.CreateTemplate(ctx, ZoneTemplate{
		Name: "SRV Template",
		Kind: ZoneForward,
	}); err != nil {
		t.Fatalf("create template failed: %v", err)
	}

	err := svc.SaveTemplateRecord(ctx, "SRV Template", "", "", Record{
		Name:    "_ldap._tcp",
		Type:    "SRV",
		TTL:     3600,
		Content: "10 20 dc1.example.org.",
	})
	if !errors.Is(err, ErrInvalidRec) {
		t.Fatalf("expected malformed SRV to fail validation, got %v", err)
	}
}

func TestCreateTemplateSeedsDefaultRecordsByKind(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	svc := NewInMemoryZoneTemplateService(nil)

	if err := svc.CreateTemplate(ctx, ZoneTemplate{
		Name: "Forward Empty",
		Kind: ZoneForward,
	}); err != nil {
		t.Fatalf("create forward template failed: %v", err)
	}

	forwardTpl, err := svc.GetTemplate(ctx, "Forward Empty")
	if err != nil {
		t.Fatalf("get forward template failed: %v", err)
	}
	if len(forwardTpl.Records) < 2 {
		t.Fatalf("expected forward defaults, got %d records", len(forwardTpl.Records))
	}

	if err := svc.CreateTemplate(ctx, ZoneTemplate{
		Name: "Reverse Empty",
		Kind: ZoneReverseV4,
	}); err != nil {
		t.Fatalf("create reverse template failed: %v", err)
	}

	reverseTpl, err := svc.GetTemplate(ctx, "Reverse Empty")
	if err != nil {
		t.Fatalf("get reverse template failed: %v", err)
	}

	hasPTR := false
	for _, rec := range reverseTpl.Records {
		if rec.Type == "PTR" {
			hasPTR = true
			break
		}
	}
	if !hasPTR {
		t.Fatalf("expected reverse template to include PTR placeholder record")
	}
}

func TestDeleteTemplateRecordRejectsSOA(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	svc := NewInMemoryZoneTemplateService(nil)
	if err := svc.CreateTemplate(ctx, ZoneTemplate{
		Name: "SOA Protected",
		Kind: ZoneForward,
		Records: []Record{
			{
				Name:    "@",
				Type:    "SOA",
				TTL:     3600,
				Content: "ns1.{{ZONE_NAME}} hostmaster.{{ZONE_NAME}} 1 10800 3600 604800 3600",
			},
		},
	}); err != nil {
		t.Fatalf("create template failed: %v", err)
	}

	err := svc.DeleteTemplateRecord(ctx, "SOA Protected", "@", "SOA")
	if !errors.Is(err, ErrInvalidRec) {
		t.Fatalf("expected ErrInvalidRec when deleting SOA, got %v", err)
	}
}
