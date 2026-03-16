package ui

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/go-pdns-ui/internal/access"
	"github.com/croessner/go-pdns-ui/internal/audit"
	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
	"github.com/croessner/go-pdns-ui/internal/i18n"
)

const (
	sessionCookieName      = "go_pdns_ui_session"
	langCookieName         = "go_pdns_ui_lang"
	zonesPerPage           = 10
	zoneAssignmentsPerPage = 10
	auditLogPerPage        = 25
	auditExportPageSize    = 250
	tabZones               = "zones"
	tabTemplates           = "templates"
	tabAccess              = "access"
	tabAudit               = "audit"
)

type Handler struct {
	templates            *template.Template
	assetFS              fs.FS
	zones                domain.ZoneService
	zoneTemplates        domain.ZoneTemplateService
	auth                 auth.Service
	access               access.Service
	audit                audit.Service
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

type ptrAddAction struct {
	Show        bool
	ReverseZone string
	PTRName     string
	PTRContent  string
	PTRExists   bool
}

type ptrTarget struct {
	ReverseZone string
	RecordName  string
	Content     string
}

type viewData struct {
	L                        map[string]string
	Lang                     string
	Supported                []string
	ShowLoginHint            bool
	PasswordLoginEnabled     bool
	PasswordChangeRequired   bool
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
	IsAudit                  bool
	CanEditZones             bool
	CanViewZones             bool
	CanViewAudit             bool
	ActiveTab                string
	OIDCEnabled              bool
	OIDCOnlyLogin            bool
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
	PTRAddActionsByRecord    map[string]ptrAddAction
	AvailableRecordTypes     []string
	ZoneWarnings             []string
	AuditEnabled             bool
	AuditEntries             []audit.Entry
	AuditQuery               string
	AuditAction              string
	AuditActions             []string
	AuditPage                int
	AuditTotal               int
	AuditTotalPages          int
	AuditPrevPage            int
	AuditNextPage            int
	AuditHasPrev             bool
	AuditHasNext             bool
	StatsZoneCount           int
	StatsRecordCount         int
	StatsTemplateCount       int
	StatsDNSSECEnabled       int
	StatsDNSSECDisabled      int
	StatsRecentChanges       []audit.Entry
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
	auditService audit.Service,
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
	if auditService == nil {
		auditService = audit.NewNoopService()
	}

	tmpl, err := template.New("views").Funcs(template.FuncMap{
		"pathEscape":      url.PathEscape,
		"containsType":    containsType,
		"recordActionKey": recordActionKey,
		"formatTime": func(t time.Time) string {
			return t.UTC().Format("2006-01-02 15:04:05")
		},
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
		assetFS:              templateFS,
		zones:                zones,
		zoneTemplates:        zoneTemplates,
		auth:                 authService,
		access:               accessService,
		audit:                auditService,
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
	mux.HandleFunc("GET /assets/{path...}", h.withRequestLogging(h.serveAsset))
	mux.HandleFunc("GET /login", h.withRequestLogging(h.loginPage))
	mux.HandleFunc("POST /login/password", h.withRequestLogging(h.loginPassword))
	mux.HandleFunc("GET /login/oidc/start", h.withRequestLogging(h.startOIDCLogin))
	mux.HandleFunc("GET /auth/oidc/callback", h.withRequestLogging(h.oidcCallback))
	mux.HandleFunc("GET /logout", h.withRequestLogging(h.requireAuth(h.logout)))
	mux.HandleFunc("POST /logout", h.withRequestLogging(h.requireAuth(h.csrf.RequireSessionToken(h.logout))))
	mux.HandleFunc("GET /account/password", h.withRequestLogging(h.requireAuth(h.passwordChangePage)))
	mux.HandleFunc("POST /account/password", h.withRequestLogging(h.requireAuth(h.csrf.RequireSessionToken(h.changePassword))))

	mux.HandleFunc("GET /", h.withRequestLogging(h.requireAuth(h.dashboard)))
	mux.HandleFunc("GET /audit/export.csv", h.withRequestLogging(h.requireAuditAccess(h.exportAuditCSV)))
	mux.HandleFunc("POST /zones", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.createZone))))
	mux.HandleFunc("POST /zones/{zone}/delete", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.deleteZone))))
	mux.HandleFunc("GET /zones/{zone}/editor", h.withRequestLogging(h.requireAuth(h.zoneEditor)))
	mux.HandleFunc("POST /zones/{zone}/export", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.exportZoneRFC))))
	mux.HandleFunc("POST /zones/{zone}/dnssec", h.withRequestLogging(h.requireZoneWrite(h.csrf.RequireSessionToken(h.toggleDNSSEC))))
	mux.HandleFunc("POST /zones/{zone}/import", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.importZoneRFC))))
	mux.HandleFunc("POST /zones/{zone}/records", h.withRequestLogging(h.requireZoneWrite(h.csrf.RequireSessionToken(h.saveRecord))))
	mux.HandleFunc("POST /zones/{zone}/records/ptr", h.withRequestLogging(h.requireZoneWrite(h.csrf.RequireSessionToken(h.addPTRRecord))))
	mux.HandleFunc("POST /zones/{zone}/records/delete", h.withRequestLogging(h.requireZoneWrite(h.csrf.RequireSessionToken(h.deleteRecord))))
	mux.HandleFunc("POST /zones/{zone}/apply", h.withRequestLogging(h.requireZoneWrite(h.csrf.RequireSessionToken(h.applyZone))))
	mux.HandleFunc("POST /zones/{zone}/reset", h.withRequestLogging(h.requireZoneWrite(h.csrf.RequireSessionToken(h.resetZoneDraft))))

	mux.HandleFunc("POST /templates", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.createTemplate))))
	mux.HandleFunc("POST /templates/{template}/delete", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.deleteTemplate))))
	mux.HandleFunc("GET /templates/{template}/editor", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.templateEditor)))
	mux.HandleFunc("POST /templates/{template}/records", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.saveTemplateRecord))))
	mux.HandleFunc("POST /templates/{template}/records/delete", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.deleteTemplateRecord))))

	mux.HandleFunc("POST /access/principals", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.createPrincipal))))
	mux.HandleFunc("POST /access/principals/{principal}/update", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.updatePrincipal))))
	mux.HandleFunc("POST /access/principals/{principal}/reset-password", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.resetPrincipalPassword))))
	mux.HandleFunc("POST /access/principals/{principal}/delete", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.deletePrincipal))))
	mux.HandleFunc("POST /access/companies", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.createCompany))))
	mux.HandleFunc("POST /access/companies/{company}/delete", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.deleteCompany))))
	mux.HandleFunc("POST /access/memberships", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.updateMembership))))
	mux.HandleFunc("POST /access/zones", h.withRequestLogging(h.requireRole(auth.RoleAdmin, h.csrf.RequireSessionToken(h.updateZoneAssignment))))
}

func (h *Handler) favicon(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) serveAsset(w http.ResponseWriter, r *http.Request) {
	rawAssetPath := strings.TrimSpace(r.PathValue("path"))
	if rawAssetPath == "" {
		http.NotFound(w, r)
		return
	}

	cleanAssetPath := strings.TrimPrefix(path.Clean("/"+rawAssetPath), "/")
	if cleanAssetPath == "." || cleanAssetPath == "" || strings.HasPrefix(cleanAssetPath, "..") {
		http.NotFound(w, r)
		return
	}

	assetFSPath := path.Join("static", cleanAssetPath)
	if _, err := fs.Stat(h.assetFS, assetFSPath); err != nil {
		http.NotFound(w, r)
		return
	}

	http.ServeFileFS(w, r, h.assetFS, assetFSPath)
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
	if session.User.MustChangePassword {
		http.Redirect(w, r, "/account/password", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) passwordChangePage(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	if !strings.EqualFold(strings.TrimSpace(session.User.AuthSource), "password") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	h.render(w, "change_password.html", viewData{
		L:                      h.i18n.Catalog(lang),
		Lang:                   lang,
		Supported:              h.i18n.Supported(),
		OIDCEnabled:            h.auth.OIDCEnabled(),
		CSRFToken:              session.CSRFToken,
		CSPNonce:               NonceFromContext(r.Context()),
		CurrentUser:            &session.User,
		PasswordChangeRequired: session.User.MustChangePassword,
	}, http.StatusOK)
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	if !strings.EqualFold(strings.TrimSpace(session.User.AuthSource), "password") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")
	if newPassword != confirmPassword {
		h.render(w, "change_password.html", viewData{
			L:                      h.i18n.Catalog(lang),
			Lang:                   lang,
			Supported:              h.i18n.Supported(),
			OIDCEnabled:            h.auth.OIDCEnabled(),
			CSRFToken:              session.CSRFToken,
			CSPNonce:               NonceFromContext(r.Context()),
			CurrentUser:            &session.User,
			Error:                  h.i18n.Catalog(lang)["password_change_mismatch"],
			PasswordChangeRequired: session.User.MustChangePassword,
		}, http.StatusBadRequest)
		return
	}

	if err := h.auth.ChangePassword(session.ID, currentPassword, newPassword); err != nil {
		message := h.i18n.Catalog(lang)["password_change_failed"]
		if errors.Is(err, auth.ErrInvalidPassword) {
			message = h.i18n.Catalog(lang)["password_policy_error"]
		}

		h.render(w, "change_password.html", viewData{
			L:                      h.i18n.Catalog(lang),
			Lang:                   lang,
			Supported:              h.i18n.Supported(),
			OIDCEnabled:            h.auth.OIDCEnabled(),
			CSRFToken:              session.CSRFToken,
			CSPNonce:               NonceFromContext(r.Context()),
			CurrentUser:            &session.User,
			Error:                  message,
			PasswordChangeRequired: session.User.MustChangePassword,
		}, http.StatusUnauthorized)
		return
	}

	h.logAction("password_changed", session)
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

	h.populateAuditData(
		r.Context(), &state,
		strings.TrimSpace(r.URL.Query().Get("audit_q")),
		strings.TrimSpace(r.URL.Query().Get("audit_action")),
		parsePage(strings.TrimSpace(r.URL.Query().Get("audit_page"))),
	)

	if isHXRequest(r) {
		h.render(w, "workspace", state, http.StatusOK)
		return
	}

	h.render(w, "dashboard.html", state, http.StatusOK)
}

func (h *Handler) exportAuditCSV(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	if !h.audit.Enabled() {
		http.NotFound(w, r)
		return
	}

	auditQuery := strings.TrimSpace(r.URL.Query().Get("audit_q"))
	auditAction := strings.TrimSpace(r.URL.Query().Get("audit_action"))

	var entries []audit.Entry
	for page := 1; ; page++ {
		result, err := h.audit.Search(r.Context(), audit.SearchParams{
			Query:  auditQuery,
			Action: auditAction,
			Page:   page,
			Limit:  auditExportPageSize,
		})
		if err != nil {
			h.internalError(w, r, "failed to export audit csv", err)
			return
		}

		entries = append(entries, result.Entries...)
		if page >= result.TotalPages || len(result.Entries) == 0 {
			break
		}
	}

	var csvBuffer bytes.Buffer
	if err := writeAuditCSV(&csvBuffer, entries); err != nil {
		h.internalError(w, r, "failed to generate audit csv", err)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set(
		"Content-Disposition",
		fmt.Sprintf("attachment; filename=\"audit-log-%s.csv\"", time.Now().UTC().Format("20060102T150405Z")),
	)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(csvBuffer.Bytes()); err != nil {
		h.logger.Warn("audit_csv_write_failed", "error", err)
	}
}

func (h *Handler) exportZoneRFC(w http.ResponseWriter, r *http.Request, session auth.Session) {
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		h.badRequest(w, r, "zone missing", nil)
		return
	}
	if !h.ensureZoneAccess(w, r, session, zoneName) {
		return
	}

	zone, err := h.zones.GetDraft(r.Context(), zoneName)
	if err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	payload := formatZoneRFCText(zone)
	filename := strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(strings.TrimSpace(zone.Name))
	if filename == "" {
		filename = "zone"
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.zone\"", filename))
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, payload); err != nil {
		h.logger.Warn("zone_rfc_export_write_failed", "zone_name", zoneName, "error", err)
		return
	}

	h.logAction("zone_rfc_exported", session, "zone_name", zoneName)
}

func (h *Handler) importZoneRFC(w http.ResponseWriter, r *http.Request, session auth.Session) {
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

	zoneData := strings.TrimSpace(r.FormValue("zone_data"))
	if zoneData == "" {
		h.badRequest(w, r, "zone file input missing", nil)
		return
	}

	records, err := parseZoneRFCText(zoneName, zoneData)
	if err != nil {
		h.badRequest(w, r, "invalid zone rfc content", err)
		return
	}
	if !containsRecordType(records, "SOA") {
		h.badRequest(w, r, "zone import requires an SOA record", nil)
		return
	}

	if err := h.replaceZoneDraftRecords(r.Context(), zoneName, records); err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	h.logAction("zone_rfc_imported", session, "zone_name", zoneName, "record_count", len(records))
	h.renderZoneEditor(w, r, zoneName, session)
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

func (h *Handler) addPTRRecord(w http.ResponseWriter, r *http.Request, session auth.Session) {
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

	sourceName := strings.TrimSpace(r.FormValue("source_name"))
	sourceType := strings.ToUpper(strings.TrimSpace(r.FormValue("source_type")))
	replaceExisting := strings.EqualFold(strings.TrimSpace(r.FormValue("replace_existing")), "true")
	if sourceName == "" {
		h.badRequest(w, r, "source record name missing", nil)
		return
	}
	if sourceType != "A" && sourceType != "AAAA" {
		h.badRequest(w, r, "source record type must be A or AAAA", nil)
		return
	}

	forwardDraft, err := h.zones.GetDraft(r.Context(), zoneName)
	if err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	sourceRecord, found := findRecord(forwardDraft.Records, sourceName, sourceType)
	if !found {
		h.badRequest(w, r, "source record not found", nil)
		return
	}

	allZones, err := h.zones.ListZones(r.Context())
	if err != nil {
		h.respondDomainError(w, r, fmt.Errorf("%w: list zones: %v", domain.ErrBackend, err))
		return
	}
	accessibleZones, err := h.access.FilterZones(r.Context(), session.User, allZones)
	if err != nil {
		h.respondAccessError(w, r, err)
		return
	}

	target, ok := resolvePTRTarget(forwardDraft.Name, sourceRecord, accessibleZones)
	if !ok {
		h.badRequest(w, r, "no matching reverse zone found for source record", nil)
		return
	}

	reverseDraft, err := h.zones.GetDraft(r.Context(), target.ReverseZone)
	if err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	if existing, exists := findRecord(reverseDraft.Records, target.RecordName, "PTR"); exists {
		if strings.EqualFold(strings.TrimSpace(existing.Content), strings.TrimSpace(target.Content)) {
			h.renderZoneEditor(w, r, zoneName, session)
			return
		}
		if !replaceExisting {
			http.Error(w, "ptr record already exists; replacement not confirmed", http.StatusConflict)
			return
		}

		err = h.zones.SaveRecord(
			r.Context(),
			target.ReverseZone,
			target.RecordName,
			"PTR",
			domain.Record{
				Name:    target.RecordName,
				Type:    "PTR",
				TTL:     sourceRecord.TTL,
				Content: target.Content,
			},
		)
		if err != nil {
			h.respondDomainError(w, r, err)
			return
		}

		h.logAction(
			"zone_ptr_record_replaced",
			session,
			"zone_name", zoneName,
			"record_name", sourceRecord.Name,
			"record_type", sourceRecord.Type,
			"reverse_zone", target.ReverseZone,
			"ptr_name", target.RecordName,
			"old_ptr_content", existing.Content,
			"new_ptr_content", target.Content,
			"ttl", sourceRecord.TTL,
		)

		h.renderZoneEditor(w, r, zoneName, session)
		return
	}

	err = h.zones.SaveRecord(
		r.Context(),
		target.ReverseZone,
		"",
		"",
		domain.Record{
			Name:    target.RecordName,
			Type:    "PTR",
			TTL:     sourceRecord.TTL,
			Content: target.Content,
		},
	)
	if err != nil {
		h.respondDomainError(w, r, err)
		return
	}

	h.logAction(
		"zone_ptr_record_saved",
		session,
		"zone_name", zoneName,
		"record_name", sourceRecord.Name,
		"record_type", sourceRecord.Type,
		"reverse_zone", target.ReverseZone,
		"ptr_name", target.RecordName,
		"ptr_content", target.Content,
		"ttl", sourceRecord.TTL,
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

	authSource := strings.ToLower(strings.TrimSpace(r.FormValue("auth_source")))
	if authSource == "" {
		authSource = "oidc"
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	mustChangePassword := strings.EqualFold(strings.TrimSpace(r.FormValue("must_change_password")), "on")
	if h.oidcOnlyLogin && authSource == "password" {
		h.logger.Warn("principal_create_rejected", "reason", "oidc_only_mode", "requested_auth_source", authSource, "username", username)
		http.Error(w, "password principals are disabled in oidc-only mode", http.StatusForbidden)
		return
	}

	var (
		principal access.Principal
		err       error
	)
	switch authSource {
	case "password":
		principal, err = h.access.CreatePasswordPrincipal(
			r.Context(),
			username,
			email,
			r.FormValue("password"),
			mustChangePassword,
		)
	default:
		mustChangePassword = false
		principal, err = h.access.CreatePrincipal(
			r.Context(),
			"oidc",
			"",
			username,
			email,
		)
	}
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
		"must_change_password", mustChangePassword,
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

func (h *Handler) updatePrincipal(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	principalID := strings.TrimSpace(r.PathValue("principal"))
	if principalID == "" {
		h.badRequest(w, r, "principal missing", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	if err := h.access.UpdatePrincipal(r.Context(), principalID, username, email); err != nil {
		h.respondAccessError(w, r, err)
		return
	}

	h.logAction(
		"principal_updated",
		session,
		"principal_id", principalID,
		"username", username,
		"email", email,
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

func (h *Handler) resetPrincipalPassword(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	principalID := strings.TrimSpace(r.PathValue("principal"))
	if principalID == "" {
		h.badRequest(w, r, "principal missing", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.badRequest(w, r, "invalid form", err)
		return
	}

	password := r.FormValue("password")
	mustChangePassword := strings.EqualFold(strings.TrimSpace(r.FormValue("must_change_password")), "on")
	if err := h.access.ResetPrincipalPassword(r.Context(), principalID, password, mustChangePassword); err != nil {
		h.respondAccessError(w, r, err)
		return
	}

	h.logAction(
		"principal_password_reset",
		session,
		"principal_id", principalID,
		"must_change_password", mustChangePassword,
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
			if h.oidcOnlyLogin {
				var allowedPrincipalIDs map[string]struct{}
				principals, allowedPrincipalIDs = filterPrincipalsByAuthSource(principals, "oidc")
				companyMemberships = filterCompanyMembershipsByPrincipalIDs(companyMemberships, allowedPrincipalIDs)
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
	activeTab := normalizeWorkspaceTab(requestedTab, session.User.Role, h.access.Enabled(), h.audit.Enabled())

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
		IsAudit:               session.User.Role == auth.RoleAudit,
		CanEditZones:          canEditZones(session.User.Role),
		CanViewZones:          canViewZones(session.User.Role),
		CanViewAudit:          canAccessAudit(session.User.Role) && h.audit.Enabled(),
		ActiveTab:             activeTab,
		OIDCEnabled:           h.auth.OIDCEnabled(),
		OIDCOnlyLogin:         h.oidcOnlyLogin,
		AccessControlEnabled:  h.access.Enabled(),
		AuditEnabled:          h.audit.Enabled(),
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
			data.ZoneWarnings = formatZoneWarnings(draft, data.L)
			data.PTRAddActionsByRecord = h.computePTRAddActions(ctx, draft, accessibleZones)
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

	// Dashboard statistics
	data.StatsZoneCount = len(accessibleZones)
	data.StatsTemplateCount = len(templates)
	var totalRecords int
	var dnssecEnabled int
	for _, z := range accessibleZones {
		draft, draftErr := h.zones.GetDraft(ctx, z.Name)
		if draftErr != nil {
			continue
		}
		totalRecords += len(draft.Records)
		if draft.DNSSECEnabled {
			dnssecEnabled++
		}
	}
	data.StatsRecordCount = totalRecords
	data.StatsDNSSECEnabled = dnssecEnabled
	data.StatsDNSSECDisabled = data.StatsZoneCount - dnssecEnabled

	if h.audit.Enabled() {
		recent, recentErr := h.audit.Search(ctx, audit.SearchParams{Page: 1, Limit: 5})
		if recentErr == nil {
			data.StatsRecentChanges = recent.Entries
		}
	}

	return data, nil
}

func (h *Handler) populateAuditData(ctx context.Context, data *viewData, auditQuery, auditAction string, auditPage int) {
	if !h.audit.Enabled() || !data.CanViewAudit || data.ActiveTab != tabAudit {
		return
	}

	if auditPage < 1 {
		auditPage = 1
	}

	actions, err := h.audit.Actions(ctx)
	if err != nil {
		h.logger.Warn("audit_actions_list_failed", "error", err)
	}
	data.AuditActions = actions
	data.AuditQuery = auditQuery
	data.AuditAction = auditAction

	result, err := h.audit.Search(ctx, audit.SearchParams{
		Query:  auditQuery,
		Action: auditAction,
		Page:   auditPage,
		Limit:  auditLogPerPage,
	})
	if err != nil {
		h.logger.Warn("audit_log_search_failed", "error", err)
		data.AuditPage = 1
		data.AuditTotalPages = 1
		return
	}

	data.AuditEntries = result.Entries
	data.AuditTotal = result.Total
	data.AuditPage = result.Page
	data.AuditTotalPages = result.TotalPages
	data.AuditPrevPage = result.Page - 1
	data.AuditNextPage = result.Page + 1
	data.AuditHasPrev = result.Page > 1
	data.AuditHasNext = result.Page < result.TotalPages
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

func filterPrincipalsByAuthSource(principals []access.Principal, authSource string) ([]access.Principal, map[string]struct{}) {
	want := strings.ToLower(strings.TrimSpace(authSource))
	if len(principals) == 0 {
		return nil, map[string]struct{}{}
	}

	filtered := make([]access.Principal, 0, len(principals))
	allowedIDs := make(map[string]struct{}, len(principals))
	for _, principal := range principals {
		if strings.ToLower(strings.TrimSpace(principal.AuthSource)) != want {
			continue
		}
		filtered = append(filtered, principal)
		allowedIDs[principal.ID] = struct{}{}
	}

	return filtered, allowedIDs
}

func filterCompanyMembershipsByPrincipalIDs(memberships []access.CompanyMembership, allowedPrincipalIDs map[string]struct{}) []access.CompanyMembership {
	if len(memberships) == 0 {
		return nil
	}
	if len(allowedPrincipalIDs) == 0 {
		return []access.CompanyMembership{}
	}

	filtered := make([]access.CompanyMembership, 0, len(memberships))
	for _, membership := range memberships {
		if _, ok := allowedPrincipalIDs[membership.PrincipalID]; !ok {
			continue
		}
		filtered = append(filtered, membership)
	}

	return filtered
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
	case "TXT", "MX", "SRV", "SOA", "CAA", "TLSA":
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

func containsRecordType(records []domain.Record, recordType string) bool {
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	if recordType == "" {
		return false
	}
	for _, record := range records {
		if strings.EqualFold(strings.TrimSpace(record.Type), recordType) {
			return true
		}
	}

	return false
}

func (h *Handler) replaceZoneDraftRecords(ctx context.Context, zoneName string, records []domain.Record) error {
	draft, err := h.zones.GetDraft(ctx, zoneName)
	if err != nil {
		return err
	}

	existingByNameType := make(map[string]domain.Record, len(draft.Records))
	for _, record := range draft.Records {
		existingByNameType[recordNameTypeKey(record)] = record
	}

	importedByNameType := make(map[string]domain.Record, len(records))
	for _, record := range records {
		importedByNameType[recordNameTypeKey(record)] = record
	}

	for _, record := range draft.Records {
		if _, keep := importedByNameType[recordNameTypeKey(record)]; keep {
			continue
		}
		if err := h.zones.DeleteRecord(ctx, zoneName, record.Name, record.Type); err != nil {
			return err
		}
	}

	for _, record := range records {
		oldName := ""
		oldType := ""
		if _, exists := existingByNameType[recordNameTypeKey(record)]; exists {
			oldName = record.Name
			oldType = record.Type
		}

		if err := h.zones.SaveRecord(ctx, zoneName, oldName, oldType, record); err != nil {
			return err
		}
	}

	return nil
}

func (h *Handler) computePTRAddActions(ctx context.Context, forwardZone domain.Zone, accessibleZones []domain.Zone) map[string]ptrAddAction {
	reverseZones := collectReverseZones(accessibleZones)
	if len(reverseZones) == 0 || len(forwardZone.Records) == 0 {
		return nil
	}

	reverseRecords := make(map[string][]domain.Record, len(reverseZones))
	for _, reverseZone := range reverseZones {
		draft, err := h.zones.GetDraft(ctx, reverseZone.Name)
		if err != nil {
			continue
		}
		reverseRecords[reverseZone.Name] = draft.Records
	}

	actions := make(map[string]ptrAddAction)
	for _, record := range forwardZone.Records {
		target, ok := resolvePTRTarget(forwardZone.Name, record, reverseZones)
		if !ok {
			continue
		}

		records, exists := reverseRecords[target.ReverseZone]
		if !exists {
			continue
		}

		_, ptrExists := findRecord(records, target.RecordName, "PTR")

		actions[recordActionKey(record)] = ptrAddAction{
			Show:        true,
			ReverseZone: target.ReverseZone,
			PTRName:     target.RecordName,
			PTRContent:  target.Content,
			PTRExists:   ptrExists,
		}
	}

	if len(actions) == 0 {
		return nil
	}

	return actions
}

func resolvePTRTarget(forwardZoneName string, record domain.Record, zones []domain.Zone) (ptrTarget, bool) {
	recordType := strings.ToUpper(strings.TrimSpace(record.Type))
	if recordType != "A" && recordType != "AAAA" {
		return ptrTarget{}, false
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(record.Content))
	if err != nil {
		return ptrTarget{}, false
	}
	if recordType == "A" && !addr.Is4() {
		return ptrTarget{}, false
	}
	if recordType == "AAAA" && !addr.Is6() {
		return ptrTarget{}, false
	}

	ptrDomain, reverseKind := ptrDomainForAddr(addr)
	reverseZone, ok := findBestMatchingReverseZone(ptrDomain, reverseKind, zones)
	if !ok {
		return ptrTarget{}, false
	}

	recordName := relativeRecordName(ptrDomain, reverseZone)
	if recordName == "" {
		return ptrTarget{}, false
	}

	content := ensureTrailingDot(absoluteRecordName(record.Name, forwardZoneName))
	if content == "" {
		return ptrTarget{}, false
	}

	return ptrTarget{
		ReverseZone: reverseZone,
		RecordName:  recordName,
		Content:     content,
	}, true
}

func collectReverseZones(zones []domain.Zone) []domain.Zone {
	result := make([]domain.Zone, 0, len(zones))
	for _, zone := range zones {
		if zone.Kind == domain.ZoneReverseV4 || zone.Kind == domain.ZoneReverseV6 {
			result = append(result, zone)
		}
	}

	return result
}

func recordActionKey(record domain.Record) string {
	return strings.TrimSpace(record.Name) + "\x00" + strings.ToUpper(strings.TrimSpace(record.Type)) + "\x00" + strings.TrimSpace(record.Content)
}

func recordNameTypeKey(record domain.Record) string {
	return strings.TrimSpace(record.Name) + "\x00" + strings.ToUpper(strings.TrimSpace(record.Type))
}

func ptrDomainForAddr(addr netip.Addr) (string, domain.ZoneKind) {
	if addr.Is4() {
		octets := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]), domain.ZoneReverseV4
	}

	hexChars := "0123456789abcdef"
	bytes16 := addr.As16()
	labels := make([]string, 0, 34)
	for i := len(bytes16) - 1; i >= 0; i-- {
		labels = append(labels, string(hexChars[bytes16[i]&0x0f]), string(hexChars[bytes16[i]>>4]))
	}
	labels = append(labels, "ip6", "arpa")

	return strings.Join(labels, "."), domain.ZoneReverseV6
}

func findBestMatchingReverseZone(ptrDomain string, reverseKind domain.ZoneKind, zones []domain.Zone) (string, bool) {
	ptrDomain = normalizeDNSName(ptrDomain)
	if ptrDomain == "" {
		return "", false
	}

	bestZone := ""
	bestZoneOriginal := ""
	for _, zone := range zones {
		if zone.Kind != reverseKind {
			continue
		}

		zoneName := normalizeDNSName(zone.Name)
		if zoneName == "" || !dnsNameHasZoneSuffix(ptrDomain, zoneName) {
			continue
		}

		if len(zoneName) > len(bestZone) {
			bestZone = zoneName
			bestZoneOriginal = strings.TrimSpace(zone.Name)
		}
	}

	if bestZoneOriginal == "" {
		return "", false
	}

	return bestZoneOriginal, true
}

func relativeRecordName(name, zone string) string {
	name = normalizeDNSName(name)
	zone = normalizeDNSName(zone)
	if name == "" || zone == "" {
		return ""
	}
	if name == zone {
		return "@"
	}

	suffix := "." + zone
	if !strings.HasSuffix(name, suffix) {
		return ""
	}

	relative := strings.TrimSuffix(name, suffix)
	if relative == "" {
		return "@"
	}

	return relative
}

func absoluteRecordName(recordName, zoneName string) string {
	recordName = strings.TrimSpace(recordName)
	zoneName = normalizeDNSName(zoneName)
	if zoneName == "" {
		return ""
	}

	switch {
	case recordName == "", recordName == "@":
		return zoneName
	case strings.HasSuffix(recordName, "."):
		return normalizeDNSName(recordName)
	}

	normalizedRecordName := normalizeDNSName(recordName)
	if normalizedRecordName == zoneName || strings.HasSuffix(normalizedRecordName, "."+zoneName) {
		return normalizedRecordName
	}

	return normalizeDNSName(recordName + "." + zoneName)
}

func ensureTrailingDot(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func dnsNameHasZoneSuffix(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func writeAuditCSV(writer io.Writer, entries []audit.Entry) error {
	csvWriter := csv.NewWriter(writer)
	if err := csvWriter.Write([]string{"timestamp_utc", "action", "user", "role", "auth_source", "target", "detail"}); err != nil {
		return err
	}

	for _, entry := range entries {
		if err := csvWriter.Write([]string{
			entry.Timestamp.UTC().Format(time.RFC3339),
			entry.Action,
			entry.User,
			entry.Role,
			entry.AuthSource,
			entry.Target,
			entry.Detail,
		}); err != nil {
			return err
		}
	}

	csvWriter.Flush()
	return csvWriter.Error()
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

	if h.audit.Enabled() {
		target, detail := buildAuditTargetDetail(attrs)
		entry := audit.Entry{
			Timestamp:  time.Now().UTC(),
			Action:     message,
			User:       user,
			Role:       string(session.User.Role),
			AuthSource: session.User.AuthSource,
			Target:     target,
			Detail:     detail,
		}
		if err := h.audit.Log(context.Background(), entry); err != nil {
			h.logger.Warn("audit_log_persist_failed", "action", message, "error", err)
		}
	}
}

// buildAuditTargetDetail extracts a human-readable target and detail string
// from the key-value attrs passed to logAction.
func buildAuditTargetDetail(attrs []any) (string, string) {
	pairs := make([]string, 0, len(attrs)/2)
	var target string
	for i := 0; i+1 < len(attrs); i += 2 {
		key := fmt.Sprintf("%v", attrs[i])
		val := fmt.Sprintf("%v", attrs[i+1])
		if target == "" {
			switch key {
			case "zone_name", "company_name", "principal_id", "template_name":
				target = val
			}
		}
		pairs = append(pairs, key+"="+val)
	}
	return target, strings.Join(pairs, ", ")
}

func formatZoneWarnings(zone domain.Zone, catalog map[string]string) []string {
	validationWarnings := domain.ValidateZoneRecords(zone)
	if len(validationWarnings) == 0 {
		return nil
	}

	messages := make([]string, 0, len(validationWarnings))
	for _, w := range validationWarnings {
		messages = append(messages, domain.FormatWarning(w, catalog))
	}

	return messages
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
			if session.User.MustChangePassword && strings.EqualFold(strings.TrimSpace(session.User.AuthSource), "password") && !isAllowedDuringForcedPasswordChange(r.URL.Path, r.Method) {
				if isHXRequest(r) {
					w.Header().Set("HX-Redirect", "/account/password")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, "/account/password", http.StatusSeeOther)
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
	if !canViewZones(session.User.Role) {
		h.logAction("forbidden_request", session, "required_zone_read", true, "path", r.URL.Path, "method", r.Method)
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}

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

func isAllowedDuringForcedPasswordChange(path, method string) bool {
	normalizedPath := strings.TrimSpace(path)
	switch normalizedPath {
	case "/account/password":
		return method == http.MethodGet || method == http.MethodPost
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

func (h *Handler) requireAuditAccess(next authedHandler) http.HandlerFunc {
	return h.requireAuth(func(w http.ResponseWriter, r *http.Request, session auth.Session) {
		if !canAccessAudit(session.User.Role) {
			h.logAction("forbidden_request", session, "required_audit_access", true, "path", r.URL.Path, "method", r.Method)
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

func canViewZones(role auth.Role) bool {
	return role != auth.RoleAudit
}

func canAccessAudit(role auth.Role) bool {
	return role == auth.RoleAdmin || role == auth.RoleAudit
}

func normalizeWorkspaceTab(requested string, role auth.Role, accessControlEnabled, auditEnabled bool) string {
	if role == auth.RoleAudit {
		return tabAudit
	}
	if role != auth.RoleAdmin {
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
	case tabAudit:
		if auditEnabled {
			return tabAudit
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
