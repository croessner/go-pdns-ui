package app

import "testing"

func TestLoadConfigFromEnvDefaults(t *testing.T) {
	t.Setenv("GO_PDNS_UI_LISTEN_ADDRESS", "")
	t.Setenv("GO_PDNS_UI_LOG_LEVEL", "")
	t.Setenv("GO_PDNS_UI_AUTHZ_MODE", "")
	t.Setenv("GO_PDNS_UI_DATABASE_URL", "")
	t.Setenv("GO_PDNS_UI_DB_MAX_OPEN_CONNS", "")
	t.Setenv("GO_PDNS_UI_DB_MAX_IDLE_CONNS", "")
	t.Setenv("GO_PDNS_UI_DB_CONN_MAX_LIFETIME_SECONDS", "")
	t.Setenv("GO_PDNS_UI_AUTHZ_OIDC_AUTO_CREATE", "")
	t.Setenv("GO_PDNS_UI_AUTH_OIDC_ONLY", "")
	t.Setenv("GO_PDNS_UI_AVAILABLE_RECORD_TYPES", "")

	cfg := LoadConfigFromEnv().withDefaults()

	if cfg.ListenAddress != ":8080" {
		t.Fatalf("unexpected listen address: %q", cfg.ListenAddress)
	}
	if cfg.LogLevel != "INFO" {
		t.Fatalf("unexpected log level: %q", cfg.LogLevel)
	}
	if cfg.AuthzMode != "off" {
		t.Fatalf("unexpected authz mode: %q", cfg.AuthzMode)
	}
	if cfg.DatabaseURL != "" {
		t.Fatalf("expected empty database url, got %q", cfg.DatabaseURL)
	}
	if cfg.DBMaxOpenConns != 10 {
		t.Fatalf("unexpected max open conns: %d", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != 5 {
		t.Fatalf("unexpected max idle conns: %d", cfg.DBMaxIdleConns)
	}
	if cfg.DBConnMaxLifetimeSecs != 300 {
		t.Fatalf("unexpected conn max lifetime: %d", cfg.DBConnMaxLifetimeSecs)
	}
	if !cfg.OIDCAutoCreate {
		t.Fatalf("expected oidc auto-create to default to true")
	}
	if cfg.OIDCOnlyLogin {
		t.Fatalf("expected oidc-only login to default to false")
	}
	if len(cfg.AvailableRecordTypes) == 0 {
		t.Fatalf("expected default available record types to be non-empty")
	}
	if cfg.AvailableRecordTypes[0] != "A" {
		t.Fatalf("expected default available record types to start with A, got %q", cfg.AvailableRecordTypes[0])
	}
}

func TestLoadConfigFromEnvOverrides(t *testing.T) {
	t.Setenv("GO_PDNS_UI_LISTEN_ADDRESS", "127.0.0.1:9090")
	t.Setenv("GO_PDNS_UI_LOG_LEVEL", "debug")
	t.Setenv("GO_PDNS_UI_AUTHZ_MODE", "company")
	t.Setenv("GO_PDNS_UI_DATABASE_URL", "postgres://db")
	t.Setenv("GO_PDNS_UI_DB_MAX_OPEN_CONNS", "20")
	t.Setenv("GO_PDNS_UI_DB_MAX_IDLE_CONNS", "7")
	t.Setenv("GO_PDNS_UI_DB_CONN_MAX_LIFETIME_SECONDS", "600")
	t.Setenv("GO_PDNS_UI_AUTHZ_OIDC_AUTO_CREATE", "false")
	t.Setenv("GO_PDNS_UI_AUTH_OIDC_ONLY", "true")
	t.Setenv("GO_PDNS_UI_AVAILABLE_RECORD_TYPES", "a,aaaa,txt, tlsa")

	cfg := LoadConfigFromEnv().withDefaults()

	if cfg.ListenAddress != "127.0.0.1:9090" {
		t.Fatalf("unexpected listen address: %q", cfg.ListenAddress)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("unexpected log level: %q", cfg.LogLevel)
	}
	if cfg.AuthzMode != "company" {
		t.Fatalf("unexpected authz mode: %q", cfg.AuthzMode)
	}
	if cfg.DatabaseURL != "postgres://db" {
		t.Fatalf("unexpected database url: %q", cfg.DatabaseURL)
	}
	if cfg.DBMaxOpenConns != 20 {
		t.Fatalf("unexpected max open conns: %d", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns != 7 {
		t.Fatalf("unexpected max idle conns: %d", cfg.DBMaxIdleConns)
	}
	if cfg.DBConnMaxLifetimeSecs != 600 {
		t.Fatalf("unexpected conn max lifetime: %d", cfg.DBConnMaxLifetimeSecs)
	}
	if cfg.OIDCAutoCreate {
		t.Fatalf("expected oidc auto-create to be disabled")
	}
	if !cfg.OIDCOnlyLogin {
		t.Fatalf("expected oidc-only login to be enabled")
	}
	if got := len(cfg.AvailableRecordTypes); got != 4 {
		t.Fatalf("expected 4 available record types, got %d (%v)", got, cfg.AvailableRecordTypes)
	}
	if cfg.AvailableRecordTypes[0] != "A" || cfg.AvailableRecordTypes[3] != "TLSA" {
		t.Fatalf("unexpected normalized available record types: %v", cfg.AvailableRecordTypes)
	}
}

func TestNewLoggerRejectsInvalidLevel(t *testing.T) {
	if _, err := NewLogger("trace"); err == nil {
		t.Fatalf("expected invalid level error")
	}
}
