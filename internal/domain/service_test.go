package domain

import (
	"context"
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
