package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/go-pdns-ui/internal/access"
	"github.com/croessner/go-pdns-ui/internal/assets"
	"github.com/croessner/go-pdns-ui/internal/audit"
	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
	ui "github.com/croessner/go-pdns-ui/internal/http"
	"github.com/croessner/go-pdns-ui/internal/i18n"
	"github.com/croessner/go-pdns-ui/internal/pdns"
)

type Dependencies struct {
	TemplateFS      fs.FS
	ZoneService     domain.ZoneService
	TemplateService domain.ZoneTemplateService
	AuthService     auth.Service
	I18nService     *i18n.Service
	AccessService   access.Service
	AuditService    audit.Service
}

type Runtime struct {
	config Config
	logger *slog.Logger
	deps   Dependencies
}

func NewRuntime(ctx context.Context, config Config, logger *slog.Logger, deps Dependencies) (*Runtime, error) {
	resolvedConfig := config.withDefaults()
	if logger == nil {
		logger = slog.Default()
	}

	resolvedDeps := deps
	if resolvedDeps.TemplateFS == nil {
		resolvedDeps.TemplateFS = assets.Files
	}

	if resolvedDeps.ZoneService == nil {
		zoneService, err := newZoneService(logger)
		if err != nil {
			return nil, err
		}
		resolvedDeps.ZoneService = zoneService
	}

	if resolvedDeps.TemplateService == nil {
		resolvedDeps.TemplateService = newTemplateService(logger)
	}

	if resolvedDeps.AccessService == nil {
		accessService, err := access.NewService(
			ctx,
			resolvedConfig.AuthzMode,
			access.DBConfig{
				DSN:                 resolvedConfig.DatabaseURL,
				MaxOpenConns:        resolvedConfig.DBMaxOpenConns,
				MaxIdleConns:        resolvedConfig.DBMaxIdleConns,
				ConnMaxLifetimeSecs: resolvedConfig.DBConnMaxLifetimeSecs,
				OIDCAutoCreate:      &resolvedConfig.OIDCAutoCreate,
			},
			logger,
		)
		if err != nil {
			return nil, fmt.Errorf("initialize access control: %w", err)
		}
		resolvedDeps.AccessService = accessService
	}

	if resolvedDeps.AuthService == nil {
		authService, err := auth.NewInMemoryServiceFromEnvWithLogger(ctx, logger.With("component", "auth"))
		if err != nil {
			return nil, fmt.Errorf("initialize auth: %w", err)
		}
		resolvedDeps.AuthService = authService
	}
	if binder, ok := resolvedDeps.AuthService.(interface{ SetPasswordStore(auth.PasswordStore) }); ok && resolvedDeps.AccessService != nil && resolvedDeps.AccessService.Enabled() {
		binder.SetPasswordStore(resolvedDeps.AccessService)
	}
	if resolvedConfig.OIDCOnlyLogin && !resolvedDeps.AuthService.OIDCEnabled() {
		return nil, errors.New("GO_PDNS_UI_AUTH_OIDC_ONLY=true requires OIDC to be configured")
	}

	if resolvedDeps.I18nService == nil {
		i18nService, err := i18n.NewService(assets.Files, "locales", "en")
		if err != nil {
			return nil, fmt.Errorf("initialize i18n: %w", err)
		}
		resolvedDeps.I18nService = i18nService
	}

	if resolvedDeps.AuditService == nil {
		auditSvc, err := newAuditService(ctx, resolvedConfig, logger)
		if err != nil {
			return nil, fmt.Errorf("initialize audit log: %w", err)
		}
		resolvedDeps.AuditService = auditSvc
	}

	runtime := &Runtime{
		config: resolvedConfig,
		logger: logger.With("component", "app"),
		deps:   resolvedDeps,
	}

	runtime.logger.Info(
		"runtime initialized",
		"listen_address", runtime.config.ListenAddress,
		"log_level", runtime.config.LogLevel,
		"authz_mode", runtime.config.AuthzMode,
	)

	return runtime, nil
}

func Run(ctx context.Context, config Config, logger *slog.Logger) error {
	runtime, err := NewRuntime(ctx, config, logger, Dependencies{})
	if err != nil {
		return err
	}

	return runtime.Run(ctx)
}

func (r *Runtime) Run(ctx context.Context) error {
	defer func() {
		if r.deps.AuditService != nil {
			if err := r.deps.AuditService.Close(); err != nil {
				r.logger.Warn("audit_service_close_failed", "error", err)
			}
		}
		if r.deps.AccessService != nil {
			if err := r.deps.AccessService.Close(); err != nil {
				r.logger.Warn("access_service_close_failed", "error", err)
			}
		}
	}()

	handler, err := ui.NewHandler(
		r.deps.TemplateFS,
		r.deps.ZoneService,
		r.deps.TemplateService,
		r.deps.AuthService,
		r.deps.I18nService,
		r.deps.AccessService,
		r.deps.AuditService,
		ui.HandlerOptions{
			OIDCOnlyLogin:        r.config.OIDCOnlyLogin,
			ForceInsecureHTTP:    r.config.ForceInsecureHTTP,
			AvailableRecordTypes: r.config.AvailableRecordTypes,
			TrustedProxies:       r.config.TrustedProxies,
		},
		r.logger.With("component", "http"),
	)
	if err != nil {
		return fmt.Errorf("initialize handlers: %w", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	server := &http.Server{
		Addr:              r.config.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		r.logger.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
			r.logger.Error("graceful shutdown failed", "error", shutdownErr)
		}
	}()

	r.logger.Info("http server starting", "listen_address", r.config.ListenAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		r.logger.Error("http server stopped with error", "error", err)
		return err
	}

	r.logger.Info("http server stopped")
	return nil
}

func newZoneService(logger *slog.Logger) (domain.ZoneService, error) {
	pdnsConfig := pdns.LoadConfigFromEnv()
	if pdnsConfig.Enabled() {
		logger.Info(
			"using PowerDNS backend",
			"backend", "powerdns",
			"pdns_api_url", pdnsConfig.BaseURL,
			"pdns_server_id", pdnsConfig.ServerID,
			"http_timeout_seconds", int(pdnsConfig.Timeout/time.Second),
		)
		client := pdns.NewClient(pdnsConfig, logger.With("component", "pdns_client"))
		repo := pdns.NewRepository(client, pdnsConfig.ServerID, logger.With("component", "pdns_repository"))
		return domain.NewDraftZoneService(repo), nil
	}

	logger.Info("using in-memory backend", "backend", "memory", "seed_zone_count", len(seedZones()))
	inMemoryRepo := domain.NewInMemoryZoneRepository(seedZones())
	return domain.NewDraftZoneService(inMemoryRepo), nil
}

func newTemplateService(logger *slog.Logger) domain.ZoneTemplateService {
	templates := seedTemplates()
	logger.Info("template service initialized", "seed_template_count", len(templates))
	return domain.NewInMemoryZoneTemplateService(templates)
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

func seedTemplates() []domain.ZoneTemplate {
	return []domain.ZoneTemplate{
		{
			Name: "Forward Basic",
			Kind: domain.ZoneForward,
			Records: []domain.Record{
				{
					Name:    "@",
					Type:    "SOA",
					TTL:     3600,
					Content: "ns1." + domain.TemplateZoneNameToken + " hostmaster." + domain.TemplateZoneNameToken + " 1 10800 3600 604800 3600",
				},
				{
					Name:    "@",
					Type:    "NS",
					TTL:     3600,
					Content: "ns1." + domain.TemplateZoneFQDNToken,
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
			Name: "Reverse v4 Basic",
			Kind: domain.ZoneReverseV4,
			Records: []domain.Record{
				{
					Name:    "@",
					Type:    "SOA",
					TTL:     3600,
					Content: "ns1." + domain.TemplateZoneNameToken + " hostmaster." + domain.TemplateZoneNameToken + " 1 10800 3600 604800 3600",
				},
				{
					Name:    "@",
					Type:    "NS",
					TTL:     3600,
					Content: "ns1." + domain.TemplateZoneFQDNToken,
				},
			},
		},
		{
			Name: "Reverse v6 Basic",
			Kind: domain.ZoneReverseV6,
			Records: []domain.Record{
				{
					Name:    "@",
					Type:    "SOA",
					TTL:     3600,
					Content: "ns1." + domain.TemplateZoneNameToken + " hostmaster." + domain.TemplateZoneNameToken + " 1 10800 3600 604800 3600",
				},
				{
					Name:    "@",
					Type:    "NS",
					TTL:     3600,
					Content: "ns1." + domain.TemplateZoneFQDNToken,
				},
			},
		},
	}
}

func newAuditService(ctx context.Context, config Config, logger *slog.Logger) (audit.Service, error) {
	dsn := config.DatabaseURL
	if dsn == "" {
		return audit.NewNoopService(), nil
	}

	return audit.NewPostgresService(ctx, audit.DBConfig{
		DSN:                 dsn,
		MaxOpenConns:        config.DBMaxOpenConns,
		MaxIdleConns:        config.DBMaxIdleConns,
		ConnMaxLifetimeSecs: config.DBConnMaxLifetimeSecs,
		RetentionDays:       config.AuditRetentionDays,
	}, logger)
}

func ensureFQDN(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasSuffix(value, ".") {
		return value
	}
	return value + "."
}
