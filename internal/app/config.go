package app

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

const (
	defaultListenAddress  = ":8080"
	defaultLogLevel       = "INFO"
	defaultAuthzMode      = "off"
	defaultDBMaxOpen      = 10
	defaultDBMaxIdle      = 5
	defaultDBMaxLifetime  = 300
	defaultOIDCAutoCreate = true
	defaultOIDCOnlyLogin  = false
)

var defaultAvailableRecordTypes = []string{
	"A",
	"AAAA",
	"CNAME",
	"MX",
	"NS",
	"TXT",
	"SRV",
	"PTR",
	"SOA",
	"CAA",
	"TLSA",
}

type Config struct {
	ListenAddress         string
	LogLevel              string
	AuthzMode             string
	DatabaseURL           string
	DBMaxOpenConns        int
	DBMaxIdleConns        int
	DBConnMaxLifetimeSecs int
	OIDCAutoCreate        bool
	OIDCOnlyLogin         bool
	AvailableRecordTypes  []string
}

func LoadConfigFromEnv() Config {
	return Config{
		ListenAddress:         getenvOrDefault("GO_PDNS_UI_LISTEN_ADDRESS", defaultListenAddress),
		LogLevel:              getenvOrDefault("GO_PDNS_UI_LOG_LEVEL", defaultLogLevel),
		AuthzMode:             getenvOrDefault("GO_PDNS_UI_AUTHZ_MODE", defaultAuthzMode),
		DatabaseURL:           strings.TrimSpace(os.Getenv("GO_PDNS_UI_DATABASE_URL")),
		DBMaxOpenConns:        getenvIntOrDefault("GO_PDNS_UI_DB_MAX_OPEN_CONNS", defaultDBMaxOpen),
		DBMaxIdleConns:        getenvIntOrDefault("GO_PDNS_UI_DB_MAX_IDLE_CONNS", defaultDBMaxIdle),
		DBConnMaxLifetimeSecs: getenvIntOrDefault("GO_PDNS_UI_DB_CONN_MAX_LIFETIME_SECONDS", defaultDBMaxLifetime),
		OIDCAutoCreate:        getenvBoolOrDefault("GO_PDNS_UI_AUTHZ_OIDC_AUTO_CREATE", defaultOIDCAutoCreate),
		OIDCOnlyLogin:         getenvBoolOrDefault("GO_PDNS_UI_AUTH_OIDC_ONLY", defaultOIDCOnlyLogin),
		AvailableRecordTypes:  loadAvailableRecordTypesFromEnv(),
	}
}

func (c Config) withDefaults() Config {
	result := c
	result.ListenAddress = strings.TrimSpace(result.ListenAddress)
	if result.ListenAddress == "" {
		result.ListenAddress = defaultListenAddress
	}

	result.LogLevel = strings.TrimSpace(result.LogLevel)
	if result.LogLevel == "" {
		result.LogLevel = defaultLogLevel
	}

	result.AuthzMode = strings.ToLower(strings.TrimSpace(result.AuthzMode))
	if result.AuthzMode == "" {
		result.AuthzMode = defaultAuthzMode
	}

	result.DatabaseURL = strings.TrimSpace(result.DatabaseURL)

	if result.DBMaxOpenConns <= 0 {
		result.DBMaxOpenConns = defaultDBMaxOpen
	}
	if result.DBMaxIdleConns <= 0 {
		result.DBMaxIdleConns = defaultDBMaxIdle
	}
	if result.DBConnMaxLifetimeSecs <= 0 {
		result.DBConnMaxLifetimeSecs = defaultDBMaxLifetime
	}
	result.AvailableRecordTypes = normalizeAvailableRecordTypes(result.AvailableRecordTypes)

	return result
}

func loadAvailableRecordTypesFromEnv() []string {
	raw := strings.TrimSpace(os.Getenv("GO_PDNS_UI_AVAILABLE_RECORD_TYPES"))
	if raw == "" {
		return append([]string(nil), defaultAvailableRecordTypes...)
	}

	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
	return normalizeAvailableRecordTypes(parts)
}

func normalizeAvailableRecordTypes(input []string) []string {
	seen := make(map[string]struct{}, len(input))
	result := make([]string, 0, len(input))

	for _, raw := range input {
		recordType := strings.ToUpper(strings.TrimSpace(raw))
		if recordType == "" {
			continue
		}
		if _, exists := seen[recordType]; exists {
			continue
		}
		seen[recordType] = struct{}{}
		result = append(result, recordType)
	}

	if len(result) == 0 {
		return append([]string(nil), defaultAvailableRecordTypes...)
	}

	return result
}

func NewLogger(level string) (*slog.Logger, error) {
	parsedLevel, err := parseLogLevel(level)
	if err != nil {
		return nil, err
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parsedLevel})
	return slog.New(handler), nil
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (allowed: debug, info, warn, error)", value)
	}
}

func getenvOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getenvIntOrDefault(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}

	return parsed
}

func getenvBoolOrDefault(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}

	return parsed
}
