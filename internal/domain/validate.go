package domain

import (
	"fmt"
	"strings"
)

// ValidationWarning represents a non-fatal issue detected in a zone's records.
type ValidationWarning struct {
	// Code is a machine-readable identifier for i18n lookup (e.g. "cname_conflict").
	Code string
	// RecordName is the record name that triggered the warning.
	RecordName string
	// RecordType is the record type that triggered the warning.
	RecordType string
	// Detail provides additional context (not translated, used as template arg).
	Detail string
}

// ValidateZoneRecords checks a zone's record set for common DNS issues and
// returns a list of warnings. These are advisory and do not block saves.
func ValidateZoneRecords(zone Zone) []ValidationWarning {
	var warnings []ValidationWarning

	warnings = append(warnings, checkCNAMEConflicts(zone.Records)...)
	warnings = append(warnings, checkMXHostnames(zone.Records)...)
	warnings = append(warnings, checkNSHostnames(zone.Records)...)
	warnings = append(warnings, checkDuplicateRecords(zone.Records)...)

	return warnings
}

// checkCNAMEConflicts detects CNAME records coexisting with other record types
// on the same name (RFC 1034 §3.6.2: CNAME must be the only record at a name).
func checkCNAMEConflicts(records []Record) []ValidationWarning {
	// Build a map: name → set of types.
	byName := make(map[string]map[string]struct{})
	for _, rec := range records {
		name := strings.ToLower(rec.Name)
		if byName[name] == nil {
			byName[name] = make(map[string]struct{})
		}
		byName[name][rec.Type] = struct{}{}
	}

	var warnings []ValidationWarning
	for name, types := range byName {
		if _, hasCNAME := types["CNAME"]; !hasCNAME {
			continue
		}
		for otherType := range types {
			if otherType == "CNAME" {
				continue
			}
			warnings = append(warnings, ValidationWarning{
				Code:       "cname_conflict",
				RecordName: name,
				RecordType: "CNAME",
				Detail:     otherType,
			})
		}
	}

	return warnings
}

// checkMXHostnames validates that MX record targets look like valid hostnames
// (not bare IPs, not empty).
func checkMXHostnames(records []Record) []ValidationWarning {
	var warnings []ValidationWarning

	for _, rec := range records {
		if rec.Type != "MX" {
			continue
		}
		fields := strings.Fields(rec.Content)
		if len(fields) < 2 {
			continue // Format already validated in normalizeRecordContent.
		}
		target := fields[1]
		if !isValidHostname(target) {
			warnings = append(warnings, ValidationWarning{
				Code:       "mx_invalid_hostname",
				RecordName: rec.Name,
				RecordType: "MX",
				Detail:     target,
			})
		}
	}

	return warnings
}

// checkNSHostnames validates that NS record targets look like valid hostnames.
func checkNSHostnames(records []Record) []ValidationWarning {
	var warnings []ValidationWarning

	for _, rec := range records {
		if rec.Type != "NS" {
			continue
		}
		target := strings.TrimSpace(rec.Content)
		if !isValidHostname(target) {
			warnings = append(warnings, ValidationWarning{
				Code:       "ns_invalid_hostname",
				RecordName: rec.Name,
				RecordType: "NS",
				Detail:     target,
			})
		}
	}

	return warnings
}

// checkDuplicateRecords detects records with identical name, type, and content.
func checkDuplicateRecords(records []Record) []ValidationWarning {
	type recordKey struct {
		name    string
		rtype   string
		content string
	}

	seen := make(map[recordKey]bool)
	var warnings []ValidationWarning

	for _, rec := range records {
		key := recordKey{
			name:    strings.ToLower(rec.Name),
			rtype:   rec.Type,
			content: rec.Content,
		}
		if seen[key] {
			warnings = append(warnings, ValidationWarning{
				Code:       "duplicate_record",
				RecordName: rec.Name,
				RecordType: rec.Type,
				Detail:     rec.Content,
			})
		}
		seen[key] = true
	}

	return warnings
}

// isValidHostname performs a basic check whether a string looks like a DNS
// hostname (not an IP address, contains at least one label with letters).
func isValidHostname(s string) bool {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" {
		return false
	}

	// Reject bare IPv4 addresses (all digits and dots).
	allDigitsDots := true
	for _, ch := range s {
		if ch != '.' && (ch < '0' || ch > '9') {
			allDigitsDots = false
			break
		}
	}
	if allDigitsDots {
		return false
	}

	// Reject bare IPv6 addresses.
	if strings.Contains(s, ":") {
		return false
	}

	labels := strings.Split(s, ".")
	if len(labels) == 0 {
		return false
	}

	for _, label := range labels {
		if label == "" {
			return false
		}
		if len(label) > 63 {
			return false
		}
		for _, ch := range label {
			if !isHostnameChar(ch) {
				return false
			}
		}
		// Labels must not start or end with hyphen.
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}

	return true
}

func isHostnameChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_'
}

// FormatWarning returns a human-readable string for a validation warning,
// using the provided i18n catalog for translation.
func FormatWarning(w ValidationWarning, catalog map[string]string) string {
	pattern, ok := catalog["lint_"+w.Code]
	if !ok {
		// Fallback: build a generic message.
		return fmt.Sprintf("%s %s: %s (%s)", w.RecordName, w.RecordType, w.Code, w.Detail)
	}

	// Simple placeholder replacement.
	msg := pattern
	msg = strings.ReplaceAll(msg, "{name}", w.RecordName)
	msg = strings.ReplaceAll(msg, "{type}", w.RecordType)
	msg = strings.ReplaceAll(msg, "{detail}", w.Detail)

	return msg
}
