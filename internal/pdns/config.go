package pdns

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	BaseURL  string
	APIKey   string
	ServerID string
	Timeout  time.Duration
}

func (c Config) Enabled() bool {
	return c.BaseURL != "" && c.APIKey != ""
}

func LoadConfigFromEnv() Config {
	timeout := 10 * time.Second
	if raw := strings.TrimSpace(os.Getenv("GO_PDNS_HTTP_TIMEOUT_SECONDS")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
			timeout = time.Duration(seconds) * time.Second
		}
	}

	return Config{
		BaseURL:  strings.TrimRight(strings.TrimSpace(os.Getenv("GO_PDNS_API_URL")), "/"),
		APIKey:   strings.TrimSpace(os.Getenv("GO_PDNS_API_KEY")),
		ServerID: getenvOrDefault("GO_PDNS_SERVER_ID", "localhost"),
		Timeout:  timeout,
	}
}

func getenvOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
