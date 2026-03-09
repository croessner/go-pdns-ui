package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/go-pdns-ui/internal/assets"
	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
	ui "github.com/croessner/go-pdns-ui/internal/http"
	"github.com/croessner/go-pdns-ui/internal/i18n"
	"github.com/croessner/go-pdns-ui/internal/pdns"
)

func Run(ctx context.Context, addr string) error {
	zoneService, err := newZoneService()
	if err != nil {
		return err
	}

	authService, err := auth.NewInMemoryServiceFromEnv(ctx)
	if err != nil {
		return fmt.Errorf("initialize auth: %w", err)
	}

	i18nService, err := i18n.NewService(assets.Files, "locales", "en")
	if err != nil {
		return fmt.Errorf("initialize i18n: %w", err)
	}

	handler, err := ui.NewHandler(assets.Files, zoneService, authService, i18nService)
	if err != nil {
		return fmt.Errorf("initialize handlers: %w", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func newZoneService() (domain.ZoneService, error) {
	pdnsConfig := pdns.LoadConfigFromEnv()
	if pdnsConfig.Enabled() {
		client := pdns.NewClient(pdnsConfig)
		repo := pdns.NewRepository(client, pdnsConfig.ServerID)
		return domain.NewDraftZoneService(repo), nil
	}

	// Local fallback for development when no PowerDNS API config is set.
	inMemoryRepo := domain.NewInMemoryZoneRepository(seedZones())
	return domain.NewDraftZoneService(inMemoryRepo), nil
}

func seedZones() []domain.Zone {
	return []domain.Zone{
		{
			Name: "example.org",
			Kind: domain.ZoneForward,
			Records: []domain.Record{
				{
					Name:    "@",
					Type:    "SOA",
					TTL:     3600,
					Content: "ns1.example.org hostmaster.example.org 1 10800 3600 604800 3600",
				},
				{
					Name:    "@",
					Type:    "NS",
					TTL:     3600,
					Content: "ns1.example.org.",
				},
				{
					Name:    "www",
					Type:    "A",
					TTL:     300,
					Content: "192.0.2.10",
				},
			},
		},
		{
			Name:          "2.0.192.in-addr.arpa",
			Kind:          domain.ZoneReverseV4,
			DNSSECEnabled: false,
			Records: []domain.Record{
				{
					Name:    "10",
					Type:    "PTR",
					TTL:     3600,
					Content: ensureFQDN("www.example.org"),
				},
			},
		},
	}
}

func ensureFQDN(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasSuffix(value, ".") {
		return value
	}
	return value + "."
}
