package ui

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/croessner/go-pdns-ui/internal/domain"
)

func formatZoneRFCText(zone domain.Zone) string {
	origin := ensureTrailingDot(normalizeDNSName(zone.Name))
	defaultTTL := uint32(3600)
	for _, record := range zone.Records {
		if record.TTL > 0 {
			defaultTTL = record.TTL
			break
		}
	}

	var builder strings.Builder
	builder.WriteString("$ORIGIN ")
	builder.WriteString(origin)
	builder.WriteString("\n")
	builder.WriteString(fmt.Sprintf("$TTL %d\n", defaultTTL))
	for _, record := range zone.Records {
		name := strings.TrimSpace(record.Name)
		if name == "" {
			name = "@"
		}
		ttl := record.TTL
		if ttl == 0 {
			ttl = defaultTTL
		}

		builder.WriteString(fmt.Sprintf(
			"%s\t%d\tIN\t%s\t%s\n",
			name,
			ttl,
			strings.ToUpper(strings.TrimSpace(record.Type)),
			strings.TrimSpace(record.Content),
		))
	}

	return builder.String()
}

func parseZoneRFCText(zoneName, raw string) ([]domain.Record, error) {
	origin := ensureTrailingDot(normalizeDNSName(zoneName))
	if origin == "." {
		return nil, fmt.Errorf("zone name missing")
	}

	statements, err := splitZoneStatements(raw)
	if err != nil {
		return nil, err
	}
	if len(statements) == 0 {
		return nil, fmt.Errorf("zone input is empty")
	}

	defaultTTL := uint32(3600)
	lastName := "@"
	records := make([]domain.Record, 0, len(statements))
	seen := make(map[string]struct{}, len(statements))

	for _, statement := range statements {
		tokens := tokenizeZoneStatement(statement)
		if len(tokens) == 0 {
			continue
		}

		if strings.HasPrefix(tokens[0], "$") {
			directive := strings.ToUpper(strings.TrimSpace(tokens[0]))
			switch directive {
			case "$ORIGIN":
				if len(tokens) < 2 {
					return nil, fmt.Errorf("$ORIGIN requires a value")
				}
				origin = resolveZoneOrigin(tokens[1], origin)
			case "$TTL":
				if len(tokens) < 2 {
					return nil, fmt.Errorf("$TTL requires a value")
				}
				ttl, ttlErr := strconv.ParseUint(strings.TrimSpace(tokens[1]), 10, 32)
				if ttlErr != nil {
					return nil, fmt.Errorf("invalid $TTL value: %w", ttlErr)
				}
				defaultTTL = uint32(ttl)
			default:
				continue
			}
			continue
		}

		record, parsedName, parseErr := parseZoneRecordTokens(tokens, origin, lastName, defaultTTL)
		if parseErr != nil {
			return nil, parseErr
		}
		lastName = parsedName

		key := recordNameTypeKey(record)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate record name+type in import: %s %s", record.Name, record.Type)
		}
		seen[key] = struct{}{}
		records = append(records, record)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("zone input does not contain records")
	}

	return records, nil
}

func splitZoneStatements(raw string) ([]string, error) {
	lines := strings.Split(raw, "\n")
	statements := make([]string, 0, len(lines))

	var current strings.Builder
	depth := 0
	for _, line := range lines {
		clean := strings.TrimSpace(stripZoneLineComment(line))
		if clean == "" {
			continue
		}

		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(clean)
		depth += parenDelta(clean)
		if depth < 0 {
			return nil, fmt.Errorf("invalid parentheses in zone input")
		}
		if depth > 0 {
			continue
		}

		statement := strings.TrimSpace(current.String())
		if statement != "" {
			statements = append(statements, statement)
		}
		current.Reset()
	}

	if depth != 0 {
		return nil, fmt.Errorf("unterminated parentheses in zone input")
	}
	if current.Len() > 0 {
		statements = append(statements, strings.TrimSpace(current.String()))
	}

	return statements, nil
}

func stripZoneLineComment(line string) string {
	inQuote := false
	escaped := false
	var builder strings.Builder
	for _, r := range line {
		if escaped {
			builder.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			builder.WriteRune(r)
			escaped = true
			continue
		}
		if r == '"' {
			inQuote = !inQuote
			builder.WriteRune(r)
			continue
		}
		if r == ';' && !inQuote {
			break
		}
		builder.WriteRune(r)
	}

	return builder.String()
}

func parenDelta(input string) int {
	inQuote := false
	escaped := false
	delta := 0
	for _, r := range input {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		if r == '(' {
			delta++
		} else if r == ')' {
			delta--
		}
	}

	return delta
}

func tokenizeZoneStatement(statement string) []string {
	tokens := make([]string, 0, 8)
	var current strings.Builder
	inQuote := false
	escaped := false

	flush := func() {
		if current.Len() == 0 {
			return
		}
		tokens = append(tokens, current.String())
		current.Reset()
	}

	for _, r := range statement {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			current.WriteRune(r)
			escaped = true
			continue
		}
		if r == '"' {
			current.WriteRune(r)
			inQuote = !inQuote
			continue
		}
		if !inQuote && (r == '(' || r == ')') {
			flush()
			continue
		}
		if !inQuote && unicode.IsSpace(r) {
			flush()
			continue
		}
		current.WriteRune(r)
	}
	flush()

	return tokens
}

func resolveZoneOrigin(token, currentOrigin string) string {
	token = strings.TrimSpace(token)
	if token == "" || token == "@" {
		return currentOrigin
	}

	if strings.HasSuffix(token, ".") {
		return ensureTrailingDot(normalizeDNSName(token))
	}

	base := strings.TrimSuffix(strings.TrimSpace(currentOrigin), ".")
	if base == "" {
		return ensureTrailingDot(normalizeDNSName(token))
	}

	return ensureTrailingDot(normalizeDNSName(token + "." + base))
}

func parseZoneRecordTokens(tokens []string, origin, lastName string, defaultTTL uint32) (domain.Record, string, error) {
	if len(tokens) == 0 {
		return domain.Record{}, lastName, fmt.Errorf("empty record")
	}

	i := 0
	name := lastName
	first := strings.TrimSpace(tokens[0])
	if !isTTLToken(first) && !isClassToken(first) && !isLikelyRRTypeToken(first) {
		name = first
		i++
	}
	if name == "" {
		return domain.Record{}, lastName, fmt.Errorf("record name missing")
	}

	ttl := defaultTTL
	for i < len(tokens) {
		token := strings.TrimSpace(tokens[i])
		if isTTLToken(token) {
			value, err := strconv.ParseUint(token, 10, 32)
			if err != nil {
				return domain.Record{}, lastName, fmt.Errorf("invalid ttl %q", token)
			}
			ttl = uint32(value)
			i++
			continue
		}
		if isClassToken(token) {
			i++
			continue
		}
		break
	}

	if i >= len(tokens) {
		return domain.Record{}, lastName, fmt.Errorf("record type missing")
	}
	recordType := strings.ToUpper(strings.TrimSpace(tokens[i]))
	if !looksLikeRRType(recordType) {
		return domain.Record{}, lastName, fmt.Errorf("invalid record type %q", tokens[i])
	}
	i++

	if i >= len(tokens) {
		return domain.Record{}, lastName, fmt.Errorf("record content missing")
	}

	content := strings.TrimSpace(strings.Join(tokens[i:], " "))
	if content == "" {
		return domain.Record{}, lastName, fmt.Errorf("record content missing")
	}

	normalizedName := normalizeImportedRecordName(name, origin)
	if normalizedName == "" {
		return domain.Record{}, lastName, fmt.Errorf("record name invalid")
	}

	return domain.Record{
		Name:    normalizedName,
		Type:    recordType,
		TTL:     ttl,
		Content: content,
	}, normalizedName, nil
}

func normalizeImportedRecordName(name, origin string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "@" {
		return "@"
	}

	normalizedOrigin := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(origin)), ".")
	normalizedName := strings.TrimSuffix(strings.ToLower(name), ".")
	if strings.HasSuffix(name, ".") {
		if normalizedName == normalizedOrigin {
			return "@"
		}
		if normalizedOrigin != "" && strings.HasSuffix(normalizedName, "."+normalizedOrigin) {
			return strings.TrimSuffix(normalizedName, "."+normalizedOrigin)
		}
		return normalizedName
	}

	return normalizedName
}

func isTTLToken(token string) bool {
	if token == "" {
		return false
	}
	for _, r := range token {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isClassToken(token string) bool {
	switch strings.ToUpper(strings.TrimSpace(token)) {
	case "IN", "CH", "HS", "CS":
		return true
	default:
		return false
	}
}

func looksLikeRRType(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	for i, r := range token {
		if i == 0 && !unicode.IsLetter(r) {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
			return false
		}
	}

	return true
}

func isLikelyRRTypeToken(token string) bool {
	token = strings.ToUpper(strings.TrimSpace(token))
	if token == "" {
		return false
	}

	if strings.HasPrefix(token, "TYPE") && isTTLToken(strings.TrimPrefix(token, "TYPE")) {
		return true
	}

	switch token {
	case "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "PTR", "SOA", "CAA", "TLSA",
		"NAPTR", "SPF", "SSHFP", "DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM",
		"SVCB", "HTTPS", "ALIAS", "LOC", "RP", "HINFO", "URI":
		return true
	default:
		return false
	}
}
