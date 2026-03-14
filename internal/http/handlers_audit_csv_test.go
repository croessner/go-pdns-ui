package ui

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/go-pdns-ui/internal/audit"
)

func TestWriteAuditCSV(t *testing.T) {
	t.Parallel()

	entries := []audit.Entry{
		{
			Timestamp:  time.Date(2026, time.March, 14, 13, 30, 0, 0, time.UTC),
			Action:     "zone_updated",
			User:       "admin",
			Role:       "admin",
			AuthSource: "local",
			Target:     "example.org",
			Detail:     "updated MX,TXT",
		},
		{
			Timestamp:  time.Date(2026, time.March, 14, 13, 31, 0, 0, time.UTC),
			Action:     "record_saved",
			User:       "alice",
			Role:       "user",
			AuthSource: "oidc",
			Target:     "www.example.org",
			Detail:     "multiline detail\nwith newline and \"quotes\"",
		},
	}

	var buffer bytes.Buffer
	if err := writeAuditCSV(&buffer, entries); err != nil {
		t.Fatalf("writeAuditCSV failed: %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(buffer.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse csv failed: %v", err)
	}

	if len(rows) != 3 {
		t.Fatalf("expected 3 rows (header + 2 entries), got %d", len(rows))
	}

	if got := rows[0]; len(got) != 7 || got[0] != "timestamp_utc" || got[6] != "detail" {
		t.Fatalf("unexpected header row: %#v", got)
	}

	if got := rows[2][6]; got != `multiline detail
with newline and "quotes"` {
		t.Fatalf("unexpected detail value after csv roundtrip: %q", got)
	}
}
