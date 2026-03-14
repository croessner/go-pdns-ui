package audit

import "testing"

func TestResolveRetentionDays(t *testing.T) {
	t.Parallel()

	if got := resolveRetentionDays(0); got != 180 {
		t.Fatalf("expected default retention for zero, got %d", got)
	}
	if got := resolveRetentionDays(-5); got != 180 {
		t.Fatalf("expected default retention for negative value, got %d", got)
	}
	if got := resolveRetentionDays(30); got != 30 {
		t.Fatalf("expected explicit retention value, got %d", got)
	}
}
