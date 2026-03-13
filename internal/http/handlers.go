package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/go-pdns-ui/internal/access"
	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
	"github.com/croessner/go-pdns-ui/internal/i18n"
)

const (
	sessionCookieName      = "go_pdns_ui_session"
	langCookieName         = "go_pdns_ui_lang"
	zonesPerPage           = 10
	zoneAssignmentsPerPage = 10
	tabZones               = "zones"
	tabTemplates           = "templates"
	tabAccess              = "access"
)

type Handler struct {
	templates            *template.Template
	zones                domain.ZoneService
	zoneTemplates        domain.ZoneTemplateService
	auth                 auth.Service
	access               access.Service
	i18n                 *i18n.Service
	logger               *slog.Logger
	oidcOnlyLogin        bool
	forceInsecureHTTP    bool
	availableRecordTypes []string
	csrf                 *CSRFManager
	secHeaders           *SecurityHeaders
	rateLimiter          *RateLimiter
	trustedProxies       *TrustedProxies
}

type recordFormData struct {
	OldName string
	OldType string
	Name    string
	Type    string
	TTL     uint32
	Content string
	Editing bool
}

type viewData struct {
	L                        map[string]string
	Lang                     string
	Supported                []string
	ShowLoginHint            bool
	PasswordLoginEnabled     bool
	Zones                    []domain.Zone
	ZoneQuery                string
	ZonePage                 int
	ZoneTotal                int
	ZoneTotalPages           int
	ZonePrevPage             int
	ZoneNextPage             int
	ZoneHasPrev              bool
	ZoneHasNext              bool
	SelectedZone             *domain.Zone
	DraftDirty               bool
	Templates                []domain.ZoneTemplate
	SelectedTemplate         *domain.ZoneTemplate
	ZoneRecordForm           recordFormData
	TemplateRecordForm       recordFormData
	ZoneDialogEditing        bool
	TemplateDialogEditing    bool
	Error                    string
	CSRFToken                string
	CSPNonce                 string
	CurrentUser              *auth.User
	CurrentPrincipalID       string
	IsAdmin                  bool
	CanEditZones             bool
	ActiveTab                string
	OIDCEnabled              bool
	AccessControlEnabled     bool
	Companies                []access.Company
	Principals               []access.Principal
	CompanyMemberships       []access.CompanyMembership
	ZoneAssignments          []access.ZoneAssignment
	ZoneAssignmentPage       int
	ZoneAssignmentTotal      int
	ZoneAssignmentTotalPages int
	ZoneAssignmentPrevPage   int
	ZoneAssignmentNextPage   int
	ZoneAssignmentHasPrev    bool
	ZoneAssignmentHasNext    bool
	ManageZones              []domain.Zone
	ZoneCompanyIDByZone      map[string]string
	ZoneCompanyNameByZone    map[string]string
	AvailableRecordTypes     []string
}

type HandlerOptions struct {
	OIDCOnlyLogin        bool
	ForceInsecureHTTP    bool
	AvailableRecordTypes []string
	TrustedProxies       []string
}

type authedHandler func(http.ResponseWriter, *http.Request, auth.Session)

func NewHandler(
	templateFS fs.FS,
	zones domain.ZoneService,
	zoneTemplates domain.ZoneTemplateService,
	authService auth.Service,
	i18nService *i18n.Service,
	accessService access.Service,
	options HandlerOptions,
	logger *slog.Logger,
) (*Handler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "http_handler")
	if accessService == nil {
		accessService = access.NewNoopService()
	}

	tmpl, err := template.New("views").Funcs(template.FuncMap{
		"pathEscape":   url.PathEscape,
		"containsType": containsType,
	}).ParseFS(templateFS, "templates/*.html", "templates/partials/*.html")
	if err != nil {
		logger.Error("template_parse_failed", "error", err)
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	logger.Info("templates_loaded")

	tp, err := NewTrustedProxies(options.TrustedProxies)
	if err != nil {
		logger.Warn("trusted_proxies_parse_failed", "error", err)
		tp = &TrustedProxies{}
	}

	return &Handler{
		templates:            tmpl,
		zones:                zones,
		zoneTemplates:        zoneTemplates,
		auth:                 authService,
		access:               accessService,
		i18n:                 i18nService,
		logger:               logger,
		oidcOnlyLogin:        options.OIDCOnlyLogin,
		forceInsecureHTTP:    options.ForceInsecureHTTP,
		availableRecordTypes: normalizeAvailableRecordTypes(options.AvailableRecordTypes),
		csrf:                 NewCSRFManager(),
		secHeaders:           NewSecurityHeaders(),
		rateLimiter:          NewRateLimiter(),
		trustedProxies:       tp,
	}, nil
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /favicon.ico", h.withRequestLogging(h.favicon))
	mux.HandleFunc("GET /login", h.withRequestLogging(h.loginPage))
	mux.HandleFunc("POST /login/password", h.withRequestLogging(h.loginPassword))
	mux.HandleFunc("GET /login/oidc/start", h.withRequestLogging(h.startOIDCLogin))
	mux.HandleFunc("GET /auth/oidc/callback", h.withRequestLogging(h.oidcCallback))
	mux.HandleFunc("GET /logout", h.withRequestLogging(h.requireAuth(h.logout)))
	mux.HandleFunc("POST /logout", h.withRequestLogging(h.requireAuth(h.csrf.RequireSessionToken(h.logout))))

	mux.HandleFunc("GET /", h.withRequestLogging(h.requireAuth(h.dashboard)))
	mux.HandleFunc("POST /zones", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.createZone))))
	mux.HandleFunc("POST /zones/{zone}/delete", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.deleteZone))))
	mux.HandleFunc("GET /zones/{zone}/editor", h.withRequestLogging(h.requireAuth(h.zoneEditor)))
	mux.HandleFunc("POST /zones/{zone}/dnssec", h.withRequestLogging(h.requireZoneWrite(h.csrf.RequireSessionToken(h.toggleDNSSEC))))
	mux.HandleFunc("POST /zones/{zone}/records", h.withRequestLogging(h.requireZoneWrite(h.csrf.RequireSessionToken(h.saveRecord))))
	mux.HandleFunc("POST /zones/{zone}/records/delete", h.withRequestLogging(h.requireZoneWrite(h.csrf.RequireSessionToken(h.deleteRecord))))
	mux.HandleFunc("POST /zones/{zone}/apply", h.withRequestLogging(h.requireZoneWrite(h.csrf.RequireSessionToken(h.applyZone))))
	mux.HandleFunc("POST /zones/{zone}/reset", h.withRequestLogging(h.requireZoneWrite(h.csrf.RequireSessionToken(h.resetZoneDraft))))

	mux.HandleFunc("POST /templates", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.createTemplate))))
	mux.HandleFunc("POST /templates/{template}/delete", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.deleteTemplate))))
	mux.HandleFunc("GET /templates/{template}/editor", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.templateEditor)))
	mux.HandleFunc("POST /templates/{template}/records", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.saveTemplateRecord))))
	mux.HandleFunc("POST /templates/{template}/records/delete", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.deleteTemplateRecord))))

	mux.HandleFunc("POST /access/principals", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.createPrincipal))))
	mux.HandleFunc("POST /access/principals/{principal}/delete", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.deletePrincipal))))
	mux.HandleFunc("POST /access/companies", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.createCompany))))
	mux.HandleFunc("POST /access/companies/{company}/delete", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.deleteCompany))))
	mux.HandleFunc("POST /access/memberships", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.updateMembership))))
	mux.HandleFunc("POST /access/zones", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.updateZoneAssignment))))
}

func (h *Handler) favicon(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	lang := h.resolveLanguage(w, r)
	if h.isAuthenticated(r) {
		h.logger.Debug("login_page_redirect_authenticated")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	passwordLoginEnabled := !h.oidcOnlyLogin

	csrfToken, err := h.csrf.SetLoginToken(w)
	if err != nil {
		h.logger.Warn("login_csrf_token_generation_failed", "error", err)
	}

	h.render(w, "login.html", viewData{
		L:                    h.i18n.Catalog(lang),
		Lang:                 lang,
		Supported:            h.i18n.Supported(),
		ShowLoginHint:        passwordLoginEnabled && h.auth.ShowDefaultCredentialsHint(),
		PasswordLoginEnabled: passwordLoginEnabled,
		OIDCEnabled:          h.auth.OIDCEnabled(),
		CSRFToken:            csrfToken,
		CSPNonce:             NonceFromContext(r.Context()),
	}, http.StatusOK)
}

func (h *Handler) loginPassword(w http.ResponseWriter, r *http.Request) {
	lang := h.resolveLanguage(w, r)
	passwordLoginEnabled := !h.oidcOnlyLogin
	if !passwordLoginEnabled {
		h.logger.Warn("password_login_rejected", "reason", "oidc_only_mode")
		h.render(w, "login.html", viewData{
			L:                    h.i18n.Catalog(lang),
			Lang:                 lang,
			Supported:            h.i18n.Supported(),
			ShowLoginHint:        false,
			PasswordLoginEnabled: false,
			OIDCEnabled:          h.auth.OIDCEnabled(),
		}, http.StatusForbidden)
		return
	}

	if h.rateLimiter.IsLocked(r) {
		h.logger.Warn("login_rate_limited", "remote_addr", r.RemoteAddr)
		newToken, _ := h.csrf.SetLoginToken(w)
		h.render(w, "login.html", viewData{
			L:                    h.i18n.Catalog(lang),
			Lang:                 lang,
			Supported:            h.i18n.Supported(),
			ShowLoginHint:        h.auth.ShowDefaultCredentialsHint(),
			PasswordLoginEnabled: true,
			OIDCEnabled:          h.auth.OIDCEnabled(),
			Error:                h.i18n.Catalog(lang)["login_failed"],
			CSRFToken:            newToken,
			CSPNonce:             NonceFromContext(r.Context()),
		}, http.StatusTooManyRequests)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	if !h.csrf.ValidateLoginToken(r) {
		h.logger.Warn("login_csrf_validation_failed")
		h.csrf.ClearLoginToken(w)
		newToken, _ := h.csrf.SetLoginToken(w)
		h.render(w, "login.html", viewData{
			L:                    h.i18n.Catalog(lang),
			Lang:                 lang,
			Supported:            h.i18n.Supported(),
			ShowLoginHint:        h.auth.ShowDefaultCredentialsHint(),
			PasswordLoginEnabled: true,
			OIDCEnabled:          h.auth.OIDCEnabled(),
			Error:                h.i18n.Catalog(lang)["login_failed"],
			CSRFToken:            newToken,
			CSPNonce:             NonceFromContext(r.Context()),
		}, http.StatusForbidden)
		return
	}
	h.csrf.ClearLoginToken(w)

	username := strings.TrimSpace(r.FormValue("username"))
	session, err := h.auth.LoginWithPassword(r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		h.rateLimiter.RecordFailure(r)
		h.logger.Warn("password_login_failed", "username", username, "error", err)
		newToken, _ := h.csrf.SetLoginToken(w)
		h.render(w, "login.html", viewData{
			L:                    h.i18n.Catalog(lang),
			Lang:                 lang,
			Supported:            h.i18n.Supported(),
			ShowLoginHint:        h.auth.ShowDefaultCredentialsHint(),
			PasswordLoginEnabled: true,
			OIDCEnabled:          h.auth.OIDCEnabled(),
			Error:                h.i18n.Catalog(lang)["login_failed"],
			CSRFToken:            newToken,
			CSPNonce:             NonceFromContext(r.Context()),
		}, http.StatusUnauthorized)
		return
	}

	h.rateLimiter.RecordSuccess(r)
	h.setSessionCookie(w, session.ID)
	h.logger.Info("password_login_succeeded", "username", username, "role", session.User.Role)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) startOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !h.auth.OIDCEnabled() {
		h.logger.Warn("oidc_login_start_rejected", "reason", "oidc_disabled")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	authURL, err := h.auth.BeginOIDCAuth()
	if err != nil {
		h.logger.Error("oidc_login_start_failed", "error", err)
		http.Error(w, "failed to start oidc flow", http.StatusBadGateway)
		return
	}

	h.logger.Info("oidc_login_started")
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request) {
	lang := h.resolveLanguage(w, r)
	if !h.auth.OIDCEnabled() {
		h.logger.Warn("oidc_callback_rejected", "reason", "oidc_disabled")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if oidcErr := strings.TrimSpace(r.URL.Query().Get("error")); oidcErr != "" {
		h.logger.Warn("oidc_callback_failed", "error", oidcErr)
		h.render(w, "login.html", viewData{
			L:                    h.i18n.Catalog(lang),
			Lang:                 lang,
			Supported:            h.i18n.Supported(),
			ShowLoginHint:        !h.oidcOnlyLogin && h.auth.ShowDefaultCredentialsHint(),
			PasswordLoginEnabled: !h.oidcOnlyLogin,
			OIDCEnabled:          true,
			Error:                oidcErr,
		}, http.StatusUnauthorized)
		return
	}

	session, err := h.auth.CompleteOIDCAuth(r.Context(), r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if err != nil {
		h.logger.Warn("oidc_callback_failed", "error", err)
		h.render(w, "login.html", viewData{
			L:                    h.i18n.Catalog(lang),
			Lang:                 lang,
			Supported:            h.i18n.Supported(),
			ShowLoginHint:        !h.oidcOnlyLogin && h.auth.ShowDefaultCredentialsHint(),
			PasswordLoginEnabled: !h.oidcOnlyLogin,
			OIDCEnabled:          true,
			Error:                h.i18n.Catalog(lang)["oidc_login_failed"],
		}, http.StatusUnauthorized)
		return
	}
	if _, err := h.access.SyncPrincipal(r.Context(), session.User); err != nil {
		h.auth.RevokeSession(session.ID)
		if errors.Is(err, access.ErrPrincipalNotFound) {
			h.logger.Warn("oidc_login_rejected_principal_not_provisioned", "username", session.User.Username, "subject", session.User.Subject)
			h.render(w, "login.html", viewData{
				L:                    h.i18n.Catalog(lang),
				Lang:                 lang,
				Supported:            h.i18n.Supported(),
				ShowLoginHint:        !h.oidcOnlyLogin && h.auth.ShowDefaultCredentialsHint(),
				PasswordLoginEnabled: !h.oidcOnlyLogin,
				OIDCEnabled:          true,
				Error:                h.i18n.Catalog(lang)["oidc_user_not_provisioned"],
			}, http.StatusUnauthorized)
			return
		}

		h.internalError(w, r, "failed to sync principal", err)
		return
	}

	h.setSessionCookie(w, session.ID)
	h.logger.Info("oidc_login_succeeded", "username", session.User.Username, "role", session.User.Role)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request, session auth.Session) {
	redirectTarget := "/login"
	if oidcLogoutURL, ok := h.auth.BuildOIDCLogoutURL(session, h.absoluteURLForRequest(r, "/login")); ok {
		redirectTarget = oidcLogoutURL
		h.logger.Info("oidc_logout_redirect_started")
	}

	sessionID, _ := h.readSessionID(r)
	h.auth.RevokeSession(sessionID)
	h.clearSessionCookie(w)

	h.logger.Info("session_revoked")
	http.Redirect(w, r, redirectTarget, http.StatusSeeOther)
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	zoneQuery := strings.TrimSpace(r.URL.Query().Get("q"))
	zonePage := parsePage(strings.TrimSpace(r.URL.Query().Get("page")))
	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		zoneQuery,
		zonePage,
		strings.TrimSpace(r.URL.Query().Get("zone")),
		strings.TrimSpace(r.URL.Query().Get("template")),
		strings.TrimSpace(r.URL.Query().Get("tab")),
		session,
		strings.TrimSpace(r.URL.Query().Get("zone_assignment_page")),
	)
	if err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	if isHXRequest(r) {
		h.render(w, "workspace", state, http.StatusOK)
		return
	}

	h.render(w, "dashboard.html", state, http.StatusOK)
}

func (h *Handler) createZone(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	zoneName := strings.TrimSpace(r.FormValue("name"))
	kind := domain.ZoneKind(strings.TrimSpace(r.FormValue("kind")))
	templateName := strings.TrimSpace(r.FormValue("template"))
	companyID := strings.TrimSpace(r.FormValue("company_id"))

	zone := domain.Zone{Name: zoneName, Kind: kind}
	if templateName != "" {
		templateDef, err := h.zoneTemplates.GetTemplate(r.Context(), templateName)
		if err != nil {
			h.respondDomainError(w, r, err)
			return
		}

		zone.Kind = templateDef.Kind
		zone.Records = domain.InstantiateTemplateRecords(zoneName, templateDef.Records)
	}

	if err := h.zones.CreateZone(r.Context(), zone); err != nil {
		h.respondDomainError(w, r, err)
		return
	}
	if h.access.Enabled() && companyID != "" {
		if err := h.access.AssignZoneToCompany(r.Context(), zone.Name, companyID); err != nil {
			if rollbackErr := h.zones.DeleteZone(r.Context(), zone.Name); rollbackErr != nil {
				h.logger.Error(
					"zone_assignment_rollback_failed",
					"zone_name", zone.Name,
					"company_id", companyID,
					"assignment_error", err,
					"rollback_error", rollbackErr,
				)
			}
			h.respondAccessError(w, r, err)
			return
		}
	}

	h.logAction("zone_created", session,
		"zone_name", zone.Name,
		"zone_kind", zone.Kind,
		"template_name", templateName,
		"company_id", companyID,
	)

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		zoneName,
		templateName,
		strings.TrimSpace(r.FormValue("tab")),
		session,
	)
	if err != nil {
		h.internalError(w, r, "failed to render workspace", err)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) deleteZone(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	zoneName := strings.TrimSpace(r.PathValue("zone"))

	if err := h.zones.DeleteZone(r.Context(), zoneName); err != nil {
		h.respondDomainError(w, r, err)
		return
	}
	if h.access.Enabled() {
		if err := h.access.UnassignZone(r.Context(), zoneName); err != nil {
			h.logger.Warn("zone_assignment_cleanup_failed", "zone_name", zoneName, "error", err)
		}
	}

	h.logAction("zone_deleted", session, "zone_name", zoneName)

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		"",
		strings.TrimSpace(r.FormValue("selected_template")),
		strings.TrimSpace(r.FormValue("tab")),
		session,
	)
	if err != nil {
		h.internalError(w, r, "failed to render workspace", err)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) zoneEditor(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		h.badRequest(w, r, "zone missing", nil)
		return
	}
	if !h.ensureZoneAccess(w, r, session, zoneName) {
		return
	}

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.URL.Query().Get("q")),
		parsePage(strings.TrimSpace(r.URL.Query().Get("page"))),
		zoneName,
		strings.TrimSpace(r.URL.Query().Get("template")),
		strings.TrimSpace(r.URL.Query().Get("tab")),
		session,
	)
	if err != nil {
		h.internalError(w, r, "failed to render editor", err)
		return
	}

	h.applyZoneRecordFormFromQuery(r, &state)
	h.render(w, "zone_editor", state, http.StatusOK)
}

func (h *Handler) toggleDNSSEC(w http.ResponseWriter, r *http.Request, session auth.Session) {
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		h.badRequest(w, r, "zone missing", nil)
		return
	}
	if !h.ensureZoneAccess(w, r, session, zoneName) {
		return
	}

	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	enabled, err := strconv.ParseBool(strings.TrimSpace(r.FormValue("enabled")))
	if err != nil {
		h.badRequest(w, r, "invalid dnssec value", err)
		return
	}

	if err := h.zones.SetDNSSEC(r.Context(), zoneName, enabled); err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	h.logAction("zone_dnssec_toggled", session, "zone_name", zoneName, "dnssec_enabled", enabled)

	h.renderZoneEditor(w, r, zoneName, session)
}

func (h *Handler) saveRecord(w http.ResponseWriter, r *http.Request, session auth.Session) {
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		h.badRequest(w, r, "zone missing", nil)
		return
	}
	if !h.ensureZoneAccess(w, r, session, zoneName) {
		return
	}

	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	ttl, err := parseTTL(r.FormValue("ttl"))
	if err != nil {
		h.badRequest(w, r, "invalid ttl", err)
		return
	}

	err = h.zones.SaveRecord(
		r.Context(),
		zoneName,
		r.FormValue("old_name"),
		r.FormValue("old_type"),
		domain.Record{
			Name:    r.FormValue("name"),
			Type:    r.FormValue("type"),
			TTL:     ttl,
			Content: r.FormValue("content"),
		},
	)
	if err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	h.logAction(
		"zone_record_saved",
		session,
		"zone_name", zoneName,
		"old_name", strings.TrimSpace(r.FormValue("old_name")),
		"old_type", strings.ToUpper(strings.TrimSpace(r.FormValue("old_type"))),
		"record_name", strings.TrimSpace(r.FormValue("name")),
		"record_type", strings.ToUpper(strings.TrimSpace(r.FormValue("type"))),
		"ttl", ttl,
	)

	h.renderZoneEditor(w, r, zoneName, session)
}

func (h *Handler) deleteRecord(w http.ResponseWriter, r *http.Request, session auth.Session) {
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		h.badRequest(w, r, "zone missing", nil)
		return
	}
	if !h.ensureZoneAccess(w, r, session, zoneName) {
		return
	}

	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	if err := h.zones.DeleteRecord(r.Context(), zoneName, r.FormValue("name"), r.FormValue("type")); err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	h.logAction(
		"zone_record_deleted",
		session,
		"zone_name", zoneName,
		"record_name", strings.TrimSpace(r.FormValue("name")),
		"record_type", strings.ToUpper(strings.TrimSpace(r.FormValue("type"))),
	)

	h.renderZoneEditor(w, r, zoneName, session)
}

func (h *Handler) applyZone(w http.ResponseWriter, r *http.Request, session auth.Session) {
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		h.badRequest(w, r, "zone missing", nil)
		return
	}
	if !h.ensureZoneAccess(w, r, session, zoneName) {
		return
	}

	if err := h.zones.Apply(r.Context(), zoneName); err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	h.logAction("zone_draft_applied", session, "zone_name", zoneName)

	lang := h.resolveLanguage(w, r)
	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		zoneName,
		strings.TrimSpace(r.FormValue("selected_template")),
		strings.TrimSpace(r.FormValue("tab")),
		session,
	)
	if err != nil {
		h.internalError(w, r, "failed to render workspace", err)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) resetZoneDraft(w http.ResponseWriter, r *http.Request, session auth.Session) {
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		h.badRequest(w, r, "zone missing", nil)
		return
	}
	if !h.ensureZoneAccess(w, r, session, zoneName) {
		return
	}

	if err := h.zones.ResetDraft(r.Context(), zoneName); err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	h.logAction("zone_draft_reset", session, "zone_name", zoneName)

	h.renderZoneEditor(w, r, zoneName, session)
}

func (h *Handler) createTemplate(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	templateName := strings.TrimSpace(r.FormValue("name"))
	kind := domain.ZoneKind(strings.TrimSpace(r.FormValue("kind")))

	if err := h.zoneTemplates.CreateTemplate(r.Context(), domain.ZoneTemplate{Name: templateName, Kind: kind}); err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	h.logAction("template_created", session, "template_name", templateName, "zone_kind", kind)

	selectedZone := strings.TrimSpace(r.FormValue("selected_zone"))
	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		selectedZone,
		templateName,
		strings.TrimSpace(r.FormValue("tab")),
		session,
	)
	if err != nil {
		h.internalError(w, r, "failed to render workspace", err)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) deleteTemplate(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	templateName := strings.TrimSpace(r.PathValue("template"))

	if err := h.zoneTemplates.DeleteTemplate(r.Context(), templateName); err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	h.logAction("template_deleted", session, "template_name", templateName)

	selectedZone := strings.TrimSpace(r.FormValue("selected_zone"))
	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		selectedZone,
		"",
		strings.TrimSpace(r.FormValue("tab")),
		session,
	)
	if err != nil {
		h.internalError(w, r, "failed to render workspace", err)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) templateEditor(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	templateName := strings.TrimSpace(r.PathValue("template"))
	if templateName == "" {
		h.badRequest(w, r, "template missing", nil)
		return
	}

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.URL.Query().Get("q")),
		parsePage(strings.TrimSpace(r.URL.Query().Get("page"))),
		strings.TrimSpace(r.URL.Query().Get("zone")),
		templateName,
		strings.TrimSpace(r.URL.Query().Get("tab")),
		session,
	)
	if err != nil {
		h.internalError(w, r, "failed to render editor", err)
		return
	}

	h.applyTemplateRecordFormFromQuery(r, &state)
	h.render(w, "zone_template_editor", state, http.StatusOK)
}

func (h *Handler) saveTemplateRecord(w http.ResponseWriter, r *http.Request, session auth.Session) {
	templateName := strings.TrimSpace(r.PathValue("template"))
	if templateName == "" {
		h.badRequest(w, r, "template missing", nil)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	ttl, err := parseTTL(r.FormValue("ttl"))
	if err != nil {
		h.badRequest(w, r, "invalid ttl", err)
		return
	}

	err = h.zoneTemplates.SaveTemplateRecord(
		r.Context(),
		templateName,
		r.FormValue("old_name"),
		r.FormValue("old_type"),
		domain.Record{
			Name:    r.FormValue("name"),
			Type:    r.FormValue("type"),
			TTL:     ttl,
			Content: r.FormValue("content"),
		},
	)
	if err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	h.logAction(
		"template_record_saved",
		session,
		"template_name", templateName,
		"old_name", strings.TrimSpace(r.FormValue("old_name")),
		"old_type", strings.ToUpper(strings.TrimSpace(r.FormValue("old_type"))),
		"record_name", strings.TrimSpace(r.FormValue("name")),
		"record_type", strings.ToUpper(strings.TrimSpace(r.FormValue("type"))),
		"ttl", ttl,
	)

	h.renderTemplateEditor(w, r, templateName, session)
}

func (h *Handler) deleteTemplateRecord(w http.ResponseWriter, r *http.Request, session auth.Session) {
	templateName := strings.TrimSpace(r.PathValue("template"))
	if templateName == "" {
		h.badRequest(w, r, "template missing", nil)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	if err := h.zoneTemplates.DeleteTemplateRecord(r.Context(), templateName, r.FormValue("name"), r.FormValue("type")); err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	h.logAction(
		"template_record_deleted",
		session,
		"template_name", templateName,
		"record_name", strings.TrimSpace(r.FormValue("name")),
		"record_type", strings.ToUpper(strings.TrimSpace(r.FormValue("type"))),
	)

	h.renderTemplateEditor(w, r, templateName, session)
}

func (h *Handler) createCompany(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	company, err := h.access.CreateCompany(r.Context(), name)
	if err != nil {
		h.respondAccessError(w, r, err)
		return
	}

	h.logAction("company_created", session, "company_id", company.ID, "company_name", company.Name)

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		strings.TrimSpace(r.FormValue("selected_zone")),
		strings.TrimSpace(r.FormValue("selected_template")),
		strings.TrimSpace(r.FormValue("tab")),
		session,
		strings.TrimSpace(r.FormValue("zone_assignment_page")),
	)
	if err != nil {
		h.internalError(w, r, "failed to render workspace", err)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) createPrincipal(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	principal, err := h.access.CreatePrincipal(
		r.Context(),
		"oidc",
		"",
		strings.TrimSpace(r.FormValue("username")),
		strings.TrimSpace(r.FormValue("email")),
	)
	if err != nil {
		h.respondAccessError(w, r, err)
		return
	}

	h.logAction(
		"principal_created",
		session,
		"principal_id", principal.ID,
		"auth_source", principal.AuthSource,
		"subject", principal.Subject,
		"username", principal.Username,
	)

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		strings.TrimSpace(r.FormValue("selected_zone")),
		strings.TrimSpace(r.FormValue("selected_template")),
		strings.TrimSpace(r.FormValue("tab")),
		session,
		strings.TrimSpace(r.FormValue("zone_assignment_page")),
	)
	if err != nil {
		h.internalError(w, r, "failed to render workspace", err)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) deletePrincipal(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	principalID := strings.TrimSpace(r.PathValue("principal"))
	if principalID == "" {
		h.badRequest(w, r, "principal missing", nil)
		return
	}
	currentPrincipal, err := h.access.SyncPrincipal(r.Context(), session.User)
	if err != nil {
		h.respondAccessError(w, r, err)
		return
	}
	if currentPrincipal.ID != "" && currentPrincipal.ID == principalID {
		h.logAction("principal_self_delete_blocked", session, "principal_id", principalID)
		http.Error(w, "cannot delete current authenticated principal", http.StatusForbidden)
		return
	}

	if err := h.access.DeletePrincipal(r.Context(), principalID); err != nil {
		h.respondAccessError(w, r, err)
		return
	}

	h.logAction("principal_deleted", session, "principal_id", principalID)

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		strings.TrimSpace(r.FormValue("selected_zone")),
		strings.TrimSpace(r.FormValue("selected_template")),
		strings.TrimSpace(r.FormValue("tab")),
		session,
		strings.TrimSpace(r.FormValue("zone_assignment_page")),
	)
	if err != nil {
		h.internalError(w, r, "failed to render workspace", err)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) deleteCompany(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	companyID := strings.TrimSpace(r.PathValue("company"))
	if companyID == "" {
		h.badRequest(w, r, "company missing", nil)
		return
	}

	if err := h.access.DeleteCompany(r.Context(), companyID); err != nil {
		h.respondAccessError(w, r, err)
		return
	}

	h.logAction("company_deleted", session, "company_id", companyID)

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		strings.TrimSpace(r.FormValue("selected_zone")),
		strings.TrimSpace(r.FormValue("selected_template")),
		strings.TrimSpace(r.FormValue("tab")),
		session,
		strings.TrimSpace(r.FormValue("zone_assignment_page")),
	)
	if err != nil {
		h.internalError(w, r, "failed to render workspace", err)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) updateMembership(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	companyID := strings.TrimSpace(r.FormValue("company_id"))
	principalID := strings.TrimSpace(r.FormValue("principal_id"))
	action := strings.ToLower(strings.TrimSpace(r.FormValue("action")))
	member := action != "remove"
	if action != "add" && action != "remove" {
		h.badRequest(w, r, "invalid membership action", nil)
		return
	}

	if err := h.access.SetMembership(r.Context(), companyID, principalID, member); err != nil {
		h.respondAccessError(w, r, err)
		return
	}

	h.logAction(
		"company_membership_updated",
		session,
		"company_id", companyID,
		"principal_id", principalID,
		"member", member,
	)

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		strings.TrimSpace(r.FormValue("selected_zone")),
		strings.TrimSpace(r.FormValue("selected_template")),
		strings.TrimSpace(r.FormValue("tab")),
		session,
		strings.TrimSpace(r.FormValue("zone_assignment_page")),
	)
	if err != nil {
		h.internalError(w, r, "failed to render workspace", err)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) updateZoneAssignment(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	zoneName := strings.TrimSpace(r.FormValue("zone_name"))
	companyID := strings.TrimSpace(r.FormValue("company_id"))
	action := strings.ToLower(strings.TrimSpace(r.FormValue("action")))

	switch action {
	case "assign":
		allZones, err := h.zones.ListZones(r.Context())
		if err != nil {
			h.respondDomainError(w, r, err)
			return
		}
		if !zoneExists(allZones, zoneName) {
			h.respondAccessError(w, r, access.ErrZoneNotFound)
			return
		}
		if err := h.access.AssignZoneToCompany(r.Context(), zoneName, companyID); err != nil {
			h.respondAccessError(w, r, err)
			return
		}
		h.logAction("zone_company_assigned", session, "zone_name", zoneName, "company_id", companyID)
	case "clear":
		if err := h.access.UnassignZone(r.Context(), zoneName); err != nil {
			h.respondAccessError(w, r, err)
			return
		}
		h.logAction("zone_company_unassigned", session, "zone_name", zoneName)
	default:
		h.badRequest(w, r, "invalid zone assignment action", nil)
		return
	}

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		strings.TrimSpace(r.FormValue("selected_zone")),
		strings.TrimSpace(r.FormValue("selected_template")),
		strings.TrimSpace(r.FormValue("tab")),
		session,
		strings.TrimSpace(r.FormValue("zone_assignment_page")),
	)
	if err != nil {
		h.internalError(w, r, "failed to render workspace", err)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) renderZoneEditor(w http.ResponseWriter, r *http.Request, zoneName string, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		zoneName,
		strings.TrimSpace(r.FormValue("selected_template")),
		strings.TrimSpace(r.FormValue("tab")),
		session,
	)
	if err != nil {
		h.internalError(w, r, "failed to render editor", err)
		return
	}

	h.render(w, "zone_editor", state, http.StatusOK)
}

func (h *Handler) renderTemplateEditor(w http.ResponseWriter, r *http.Request, templateName string, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		strings.TrimSpace(r.FormValue("selected_zone")),
		templateName,
		strings.TrimSpace(r.FormValue("tab")),
		session,
	)
	if err != nil {
		h.internalError(w, r, "failed to render editor", err)
		return
	}

	h.render(w, "zone_template_editor", state, http.StatusOK)
}

func (h *Handler) buildDashboardState(ctx context.Context, lang, zoneQuery string, zonePage int, selectedZone, selectedTemplate, requestedTab string, session auth.Session, zoneAssignmentPageRaw ...string) (viewData, error) {
	allZones, err := h.zones.ListZones(ctx)
	if err != nil {
		return viewData{}, err
	}
	currentPrincipal, err := h.access.SyncPrincipal(ctx, session.User)
	if err != nil {
		return viewData{}, err
	}
	accessibleZones, err := h.access.FilterZones(ctx, session.User, allZones)
	if err != nil {
		return viewData{}, err
	}

	zoneQuery = strings.TrimSpace(zoneQuery)
	// PowerDNS list zones endpoint has no native pagination parameters,
	// so we paginate server-side after fetching the current zone list.
	filteredZones := filterZones(accessibleZones, zoneQuery)
	filteredZoneSet := make(map[string]struct{}, len(filteredZones))
	for _, zone := range filteredZones {
		filteredZoneSet[zone.Name] = struct{}{}
	}
	if selectedZone != "" {
		if _, exists := filteredZoneSet[selectedZone]; !exists {
			selectedZone = ""
		}
	}
	pagedZones, resolvedPage, totalPages := paginateZones(filteredZones, zonePage, zonesPerPage)
	if selectedZone == "" && len(pagedZones) > 0 {
		selectedZone = pagedZones[0].Name
	}
	zoneAssignmentPage := 1
	if len(zoneAssignmentPageRaw) > 0 {
		if raw := strings.TrimSpace(zoneAssignmentPageRaw[0]); raw != "" {
			zoneAssignmentPage = parsePage(raw)
		}
	}

	var templates []domain.ZoneTemplate
	var companies []access.Company
	var principals []access.Principal
	var companyMemberships []access.CompanyMembership
	var zoneAssignments []access.ZoneAssignment
	zoneCompanyIDByZone := make(map[string]string)
	zoneCompanyNameByZone := make(map[string]string)
	manageZones := filteredZones

	if session.User.Role == auth.RoleAdmin {
		templates, err = h.zoneTemplates.ListTemplates(ctx)
		if err != nil {
			return viewData{}, err
		}
		if selectedTemplate == "" && len(templates) > 0 {
			selectedTemplate = templates[0].Name
		}

		if h.access.Enabled() {
			companies, err = h.access.ListCompanies(ctx)
			if err != nil {
				return viewData{}, err
			}

			principals, err = h.access.ListPrincipals(ctx)
			if err != nil {
				return viewData{}, err
			}

			companyMemberships, err = h.access.ListCompanyMemberships(ctx)
			if err != nil {
				return viewData{}, err
			}

			zoneAssignments, err = h.access.ListZoneAssignments(ctx)
			if err != nil {
				return viewData{}, err
			}
			cleanedAssignments := make([]access.ZoneAssignment, 0, len(zoneAssignments))
			for _, assignment := range zoneAssignments {
				if zoneExists(allZones, assignment.ZoneName) {
					cleanedAssignments = append(cleanedAssignments, assignment)
					continue
				}

				if err := h.access.UnassignZone(ctx, assignment.ZoneName); err != nil {
					h.logger.Warn("stale_zone_assignment_cleanup_failed", "zone_name", assignment.ZoneName, "error", err)
					cleanedAssignments = append(cleanedAssignments, assignment)
					continue
				}

				h.logger.Info("stale_zone_assignment_removed", "zone_name", assignment.ZoneName)
			}
			zoneAssignments = cleanedAssignments

			for _, assignment := range zoneAssignments {
				zoneCompanyIDByZone[assignment.ZoneName] = assignment.CompanyID
				zoneCompanyNameByZone[assignment.ZoneName] = assignment.CompanyName
			}
			manageZones = filterAssignableZones(filteredZones, zoneCompanyIDByZone)
		}
	}

	pagedZoneAssignments, resolvedZoneAssignmentPage, zoneAssignmentTotalPages := paginateZoneAssignments(zoneAssignments, zoneAssignmentPage, zoneAssignmentsPerPage)

	defaultRecordType := firstRecordType(h.availableRecordTypes)
	data := viewData{
		L:                        h.i18n.Catalog(lang),
		Lang:                     lang,
		Supported:                h.i18n.Supported(),
		Zones:                    pagedZones,
		ManageZones:              manageZones,
		ZoneQuery:                zoneQuery,
		ZonePage:                 resolvedPage,
		ZoneTotal:                len(filteredZones),
		ZoneTotalPages:           totalPages,
		ZonePrevPage:             resolvedPage - 1,
		ZoneNextPage:             resolvedPage + 1,
		ZoneHasPrev:              resolvedPage > 1,
		ZoneHasNext:              resolvedPage < totalPages,
		Templates:                templates,
		Companies:                companies,
		Principals:               principals,
		CompanyMemberships:       companyMemberships,
		ZoneAssignments:          pagedZoneAssignments,
		ZoneAssignmentPage:       resolvedZoneAssignmentPage,
		ZoneAssignmentTotal:      len(zoneAssignments),
		ZoneAssignmentTotalPages: zoneAssignmentTotalPages,
		ZoneAssignmentPrevPage:   resolvedZoneAssignmentPage - 1,
		ZoneAssignmentNextPage:   resolvedZoneAssignmentPage + 1,
		ZoneAssignmentHasPrev:    resolvedZoneAssignmentPage > 1,
		ZoneAssignmentHasNext:    resolvedZoneAssignmentPage < zoneAssignmentTotalPages,
		ZoneRecordForm: recordFormData{
			Type: defaultRecordType,
			TTL:  3600,
		},
		TemplateRecordForm: recordFormData{
			Type: defaultRecordType,
			TTL:  3600,
		},
		CSRFToken:             session.CSRFToken,
		CSPNonce:              NonceFromContext(ctx),
		CurrentUser:           &session.User,
		CurrentPrincipalID:    currentPrincipal.ID,
		IsAdmin:               session.User.Role == auth.RoleAdmin,
		CanEditZones:          canEditZones(session.User.Role),
		ActiveTab:             normalizeWorkspaceTab(requestedTab, session.User.Role == auth.RoleAdmin, h.access.Enabled()),
		OIDCEnabled:           h.auth.OIDCEnabled(),
		AccessControlEnabled:  h.access.Enabled(),
		ZoneCompanyIDByZone:   zoneCompanyIDByZone,
		ZoneCompanyNameByZone: zoneCompanyNameByZone,
		AvailableRecordTypes:  h.availableRecordTypes,
	}

	if selectedZone != "" {
		draft, draftErr := h.zones.GetDraft(ctx, selectedZone)
		if draftErr != nil {
			if !errors.Is(draftErr, domain.ErrZoneNotFound) {
				return viewData{}, draftErr
			}
		} else {
			dirty, dirtyErr := h.zones.IsDraftDirty(ctx, selectedZone)
			if dirtyErr != nil {
				return viewData{}, dirtyErr
			}

			data.SelectedZone = &draft
			data.DraftDirty = dirty
		}
	}

	if session.User.Role == auth.RoleAdmin && selectedTemplate != "" {
		tpl, tplErr := h.zoneTemplates.GetTemplate(ctx, selectedTemplate)
		if tplErr != nil {
			if !errors.Is(tplErr, domain.ErrTemplateNotFound) {
				return viewData{}, tplErr
			}
		} else {
			data.SelectedTemplate = &tpl
		}
	}

	return data, nil
}

func filterZones(zones []domain.Zone, query string) []domain.Zone {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		result := make([]domain.Zone, len(zones))
		copy(result, zones)
		return result
	}

	result := make([]domain.Zone, 0, len(zones))
	for _, zone := range zones {
		if strings.Contains(strings.ToLower(zone.Name), query) {
			result = append(result, zone)
		}
	}

	return result
}

func zoneExists(zones []domain.Zone, name string) bool {
	needle := strings.TrimSpace(name)
	if needle == "" {
		return false
	}

	for _, zone := range zones {
		if strings.EqualFold(strings.TrimSpace(zone.Name), needle) {
			return true
		}
	}

	return false
}

func filterAssignableZones(zones []domain.Zone, assignedByZone map[string]string) []domain.Zone {
	if len(zones) == 0 {
		return nil
	}
	if len(assignedByZone) == 0 {
		result := make([]domain.Zone, len(zones))
		copy(result, zones)
		return result
	}

	result := make([]domain.Zone, 0, len(zones))
	for _, zone := range zones {
		if _, assigned := assignedByZone[zone.Name]; assigned {
			continue
		}
		result = append(result, zone)
	}

	return result
}

func paginateZones(zones []domain.Zone, page, pageSize int) ([]domain.Zone, int, int) {
	if pageSize <= 0 {
		pageSize = zonesPerPage
	}

	totalPages := (len(zones) + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * pageSize
	if start >= len(zones) {
		return []domain.Zone{}, page, totalPages
	}

	end := start + pageSize
	if end > len(zones) {
		end = len(zones)
	}

	result := make([]domain.Zone, end-start)
	copy(result, zones[start:end])
	return result, page, totalPages
}

func paginateZoneAssignments(assignments []access.ZoneAssignment, page, pageSize int) ([]access.ZoneAssignment, int, int) {
	if pageSize <= 0 {
		pageSize = zoneAssignmentsPerPage
	}

	totalPages := (len(assignments) + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * pageSize
	if start >= len(assignments) {
		return []access.ZoneAssignment{}, page, totalPages
	}

	end := start + pageSize
	if end > len(assignments) {
		end = len(assignments)
	}

	result := make([]access.ZoneAssignment, end-start)
	copy(result, assignments[start:end])
	return result, page, totalPages
}

func (h *Handler) applyZoneRecordFormFromQuery(r *http.Request, data *viewData) {
	if data.SelectedZone == nil {
		return
	}

	oldName := strings.TrimSpace(r.URL.Query().Get("edit_name"))
	oldType := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("edit_type")))
	if oldName == "" || oldType == "" {
		return
	}

	record, ok := findRecord(data.SelectedZone.Records, oldName, oldType)
	if !ok {
		return
	}

	data.ZoneRecordForm = recordFormData{
		OldName: oldName,
		OldType: oldType,
		Name:    record.Name,
		Type:    record.Type,
		TTL:     record.TTL,
		Content: record.Content,
		Editing: true,
	}
	data.ZoneDialogEditing = isDialogRecordType(record.Type)
}

func (h *Handler) applyTemplateRecordFormFromQuery(r *http.Request, data *viewData) {
	if data.SelectedTemplate == nil {
		return
	}

	oldName := strings.TrimSpace(r.URL.Query().Get("edit_name"))
	oldType := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("edit_type")))
	if oldName == "" || oldType == "" {
		return
	}

	record, ok := findRecord(data.SelectedTemplate.Records, oldName, oldType)
	if !ok {
		return
	}

	data.TemplateRecordForm = recordFormData{
		OldName: oldName,
		OldType: oldType,
		Name:    record.Name,
		Type:    record.Type,
		TTL:     record.TTL,
		Content: record.Content,
		Editing: true,
	}
	data.TemplateDialogEditing = isDialogRecordType(record.Type)
}

func findRecord(records []domain.Record, name, recordType string) (domain.Record, bool) {
	for _, record := range records {
		if record.Name == name && record.Type == recordType {
			return record, true
		}
	}

	return domain.Record{}, false
}

func isDialogRecordType(recordType string) bool {
	switch strings.ToUpper(strings.TrimSpace(recordType)) {
	case "TXT", "SRV", "SOA", "CAA", "TLSA":
		return true
	default:
		return false
	}
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
		return []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "PTR", "SOA", "CAA", "TLSA"}
	}

	return result
}

func firstRecordType(available []string) string {
	normalized := normalizeAvailableRecordTypes(available)
	if len(normalized) == 0 {
		return "A"
	}
	return normalized[0]
}

func containsType(recordTypes []string, recordType string) bool {
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	if recordType == "" {
		return false
	}
	for _, candidate := range recordTypes {
		if strings.EqualFold(strings.TrimSpace(candidate), recordType) {
			return true
		}
	}
	return false
}

func parseTTL(raw string) (uint32, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 3600, nil
	}

	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, err
	}

	return uint32(value), nil
}

func parsePage(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 1
	}

	page, err := strconv.Atoi(raw)
	if err != nil || page < 1 {
		return 1
	}

	return page
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (h *Handler) withRequestLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = h.secHeaders.Apply(w, r, h.requestIsSecure(r))
		started := time.Now()
		recorder := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next(recorder, r)

		durationMs := time.Since(started).Milliseconds()
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"duration_ms", durationMs,
			"remote_addr", r.RemoteAddr,
			"hx", isHXRequest(r),
		}

		if session, ok := h.currentSession(r); ok {
			attrs = append(attrs, "user", session.User.Username, "role", session.User.Role)
		}

		switch {
		case recorder.status >= http.StatusInternalServerError:
			h.logger.Error("http_request", attrs...)
		case recorder.status >= http.StatusBadRequest:
			h.logger.Warn("http_request", attrs...)
		default:
			h.logger.Info("http_request", attrs...)
		}
	}
}

func (h *Handler) logAction(message string, session auth.Session, attrs ...any) {
	user := strings.TrimSpace(session.User.Username)
	if user == "" {
		user = strings.TrimSpace(session.User.Subject)
	}

	baseAttrs := []any{
		"user", user,
		"role", session.User.Role,
		"auth_source", session.User.AuthSource,
	}
	baseAttrs = append(baseAttrs, attrs...)
	h.logger.Info(message, baseAttrs...)
}

func (h *Handler) badRequest(w http.ResponseWriter, r *http.Request, message string, err error) {
	attrs := []any{
		"method", r.Method,
		"path", r.URL.Path,
		"message", message,
	}
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	h.logger.Warn("bad_request", attrs...)
	http.Error(w, message, http.StatusBadRequest)
}

func (h *Handler) internalError(w http.ResponseWriter, r *http.Request, message string, err error) {
	attrs := []any{
		"method", r.Method,
		"path", r.URL.Path,
		"message", message,
	}
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	h.logger.Error("internal_error", attrs...)
	http.Error(w, message, http.StatusInternalServerError)
}

func (h *Handler) render(w http.ResponseWriter, templateName string, data viewData, status int) {
	var out bytes.Buffer
	if err := h.templates.ExecuteTemplate(&out, templateName, data); err != nil {
		h.logger.Error("template_render_failed", "template", templateName, "error", err)
		http.Error(w, "template rendering failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if _, err := w.Write(out.Bytes()); err != nil {
		h.logger.Warn("response_write_failed", "template", templateName, "error", err)
	}
}

func (h *Handler) requireAuth(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := h.currentSession(r)
		if ok {
			if _, err := h.access.SyncPrincipal(r.Context(), session.User); err != nil {
				if errors.Is(err, access.ErrPrincipalNotFound) {
					h.logAction("session_rejected_principal_not_provisioned", session, "path", r.URL.Path, "method", r.Method)
					h.auth.RevokeSession(session.ID)
					h.clearSessionCookie(w)
					if isHXRequest(r) {
						w.Header().Set("HX-Redirect", "/login")
						w.WriteHeader(http.StatusUnauthorized)
						return
					}

					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				}

				h.internalError(w, r, "failed to sync principal", err)
				return
			}
			next(w, r, session)
			return
		}

		if isHXRequest(r) {
			h.logUnauthorizedRequest(r, true)
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		h.logUnauthorizedRequest(r, false)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func (h *Handler) ensureZoneAccess(w http.ResponseWriter, r *http.Request, session auth.Session, zoneName string) bool {
	allowed, err := h.access.CanAccessZone(r.Context(), session.User, zoneName)
	if err != nil {
		h.internalError(w, r, "failed to evaluate zone access", err)
		return false
	}
	if allowed {
		return true
	}

	h.logAction("zone_access_denied", session, "zone_name", zoneName, "path", r.URL.Path, "method", r.Method)
	http.NotFound(w, r)
	return false
}

func isHXRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("HX-Request"), "true")
}

func (h *Handler) absoluteURLForRequest(r *http.Request, path string) string {
	normalizedPath := "/" + strings.TrimLeft(strings.TrimSpace(path), "/")

	trusted := h.trustedProxies != nil && h.trustedProxies.IsTrusted(r.RemoteAddr)

	host := strings.TrimSpace(r.Host)
	if trusted {
		if fwdHost := strings.TrimSpace(firstHeaderValue(r.Header.Get("X-Forwarded-Host"))); fwdHost != "" {
			host = fwdHost
		}
	}
	if host == "" {
		return normalizedPath
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if h.forceInsecureHTTP {
		scheme = "http"
	} else if trusted {
		if forwardedProto := strings.TrimSpace(firstHeaderValue(r.Header.Get("X-Forwarded-Proto"))); forwardedProto != "" {
			scheme = strings.ToLower(forwardedProto)
		}
	}

	return (&url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   normalizedPath,
	}).String()
}

func (h *Handler) requestIsSecure(r *http.Request) bool {
	if h.forceInsecureHTTP {
		return false
	}

	if r.TLS != nil {
		return true
	}

	trusted := h.trustedProxies != nil && h.trustedProxies.IsTrusted(r.RemoteAddr)
	if !trusted {
		return false
	}

	forwardedProto := strings.TrimSpace(firstHeaderValue(r.Header.Get("X-Forwarded-Proto")))
	return strings.EqualFold(forwardedProto, "https")
}

func firstHeaderValue(raw string) string {
	if raw == "" {
		return ""
	}

	parts := strings.Split(raw, ",")
	return strings.TrimSpace(parts[0])
}

func (h *Handler) logUnauthorizedRequest(r *http.Request, hx bool) {
	attrs := []any{"path", r.URL.Path, "method", r.Method, "hx", hx}
	if isExpectedUnauthenticatedPath(r.URL.Path, r.Method) {
		h.logger.Debug("unauthorized_request_expected", attrs...)
		return
	}
	h.logger.Warn("unauthorized_request", attrs...)
}

func isExpectedUnauthenticatedPath(path, method string) bool {
	normalizedPath := strings.TrimSpace(path)
	switch normalizedPath {
	case "/favicon.ico":
		return method == http.MethodGet
	case "/logout":
		return method == http.MethodGet || method == http.MethodPost
	default:
		return false
	}
}

func (h *Handler) requireRole(required auth.Role, next authedHandler) http.HandlerFunc {
	return h.requireAuth(func(w http.ResponseWriter, r *http.Request, session auth.Session) {
		if session.User.Role != required {
			h.logAction("forbidden_request", session, "required_role", required, "path", r.URL.Path, "method", r.Method)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r, session)
	})
}

func (h *Handler) requireZoneWrite(next authedHandler) http.HandlerFunc {
	return h.requireAuth(func(w http.ResponseWriter, r *http.Request, session auth.Session) {
		if !canEditZones(session.User.Role) {
			h.logAction("forbidden_request", session, "required_zone_write", true, "path", r.URL.Path, "method", r.Method)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r, session)
	})
}

func canEditZones(role auth.Role) bool {
	return role == auth.RoleAdmin || role == auth.RoleUser
}

func normalizeWorkspaceTab(requested string, isAdmin, accessControlEnabled bool) string {
	if !isAdmin {
		return tabZones
	}

	switch strings.ToLower(strings.TrimSpace(requested)) {
	case tabTemplates:
		return tabTemplates
	case tabAccess:
		if accessControlEnabled {
			return tabAccess
		}
		return tabZones
	case tabZones:
		return tabZones
	default:
		return tabZones
	}
}

func (h *Handler) currentSession(r *http.Request) (auth.Session, bool) {
	sessionID, ok := h.readSessionID(r)
	if !ok {
		return auth.Session{}, false
	}

	return h.auth.TouchSession(sessionID)
}

func (h *Handler) isAuthenticated(r *http.Request) bool {
	_, ok := h.currentSession(r)
	return ok
}

func (h *Handler) readSessionID(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}

	sessionID := strings.TrimSpace(cookie.Value)
	if sessionID == "" {
		return "", false
	}

	return sessionID, true
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) resolveLanguage(w http.ResponseWriter, r *http.Request) string {
	requested := strings.TrimSpace(r.URL.Query().Get("lang"))
	if requested != "" {
		lang := h.i18n.Normalize(requested)
		http.SetCookie(w, &http.Cookie{
			Name:     langCookieName,
			Value:    lang,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(180 * 24 * time.Hour),
		})
		return lang
	}

	cookie, err := r.Cookie(langCookieName)
	if err != nil {
		return h.i18n.Fallback()
	}

	return h.i18n.Normalize(cookie.Value)
}

func (h *Handler) respondDomainError(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError

	switch {
	case errors.Is(err, domain.ErrInvalidZone), errors.Is(err, domain.ErrInvalidRec), errors.Is(err, domain.ErrInvalidTemplate):
		status = http.StatusBadRequest
	case errors.Is(err, domain.ErrZoneNotFound), errors.Is(err, domain.ErrTemplateNotFound):
		status = http.StatusNotFound
	case errors.Is(err, domain.ErrZoneExists), errors.Is(err, domain.ErrTemplateExists):
		status = http.StatusConflict
	case errors.Is(err, domain.ErrBackend):
		status = http.StatusBadGateway
	case errors.Is(err, access.ErrInvalidInput):
		status = http.StatusBadRequest
	case errors.Is(err, access.ErrCompanyNotFound), errors.Is(err, access.ErrPrincipalNotFound), errors.Is(err, access.ErrZoneNotFound):
		status = http.StatusNotFound
	case errors.Is(err, access.ErrCompanyExists):
		status = http.StatusConflict
	case errors.Is(err, access.ErrAccessDisabled):
		status = http.StatusServiceUnavailable
	}

	attrs := []any{
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"error", err,
	}
	if status >= http.StatusInternalServerError {
		h.logger.Error("domain_request_failed", attrs...)
	} else {
		h.logger.Warn("domain_request_failed", attrs...)
	}

	http.Error(w, err.Error(), status)
}

func (h *Handler) respondAccessError(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError

	switch {
	case errors.Is(err, access.ErrInvalidInput):
		status = http.StatusBadRequest
	case errors.Is(err, access.ErrCompanyNotFound), errors.Is(err, access.ErrPrincipalNotFound), errors.Is(err, access.ErrZoneNotFound):
		status = http.StatusNotFound
	case errors.Is(err, access.ErrCompanyExists):
		status = http.StatusConflict
	case errors.Is(err, access.ErrAccessDisabled):
		status = http.StatusServiceUnavailable
	}

	attrs := []any{
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"error", err,
	}
	if status >= http.StatusInternalServerError {
		h.logger.Error("access_request_failed", attrs...)
	} else {
		h.logger.Warn("access_request_failed", attrs...)
	}

	http.Error(w, err.Error(), status)
}
