package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
	"github.com/croessner/go-pdns-ui/internal/i18n"
)

const (
	sessionCookieName = "go_pdns_ui_session"
	langCookieName    = "go_pdns_ui_lang"
)

type Handler struct {
	templates *template.Template
	zones     domain.ZoneService
	auth      auth.Service
	i18n      *i18n.Service
}

type viewData struct {
	L            map[string]string
	Lang         string
	Supported    []string
	Zones        []domain.Zone
	SelectedZone *domain.Zone
	DraftDirty   bool
	Error        string
	CurrentUser  *auth.User
	IsAdmin      bool
	OIDCEnabled  bool
}

type authedHandler func(http.ResponseWriter, *http.Request, auth.Session)

func NewHandler(templateFS fs.FS, zones domain.ZoneService, authService auth.Service, i18nService *i18n.Service) (*Handler, error) {
	tmpl, err := template.New("views").Funcs(template.FuncMap{
		"pathEscape": url.PathEscape,
	}).ParseFS(templateFS, "templates/*.html", "templates/partials/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	return &Handler{
		templates: tmpl,
		zones:     zones,
		auth:      authService,
		i18n:      i18nService,
	}, nil
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", h.loginPage)
	mux.HandleFunc("POST /login/password", h.loginPassword)
	mux.HandleFunc("GET /login/oidc/start", h.startOIDCLogin)
	mux.HandleFunc("GET /auth/oidc/callback", h.oidcCallback)
	mux.HandleFunc("POST /logout", h.requireAuth(h.logout))

	mux.HandleFunc("GET /", h.requireAuth(h.dashboard))
	mux.HandleFunc("POST /zones", h.requireRole(auth.RoleAdmin, h.createZone))
	mux.HandleFunc("POST /zones/{zone}/delete", h.requireRole(auth.RoleAdmin, h.deleteZone))
	mux.HandleFunc("GET /zones/{zone}/editor", h.requireAuth(h.zoneEditor))
	mux.HandleFunc("POST /zones/{zone}/dnssec", h.requireRole(auth.RoleAdmin, h.toggleDNSSEC))
	mux.HandleFunc("POST /zones/{zone}/records", h.requireRole(auth.RoleAdmin, h.saveRecord))
	mux.HandleFunc("POST /zones/{zone}/records/delete", h.requireRole(auth.RoleAdmin, h.deleteRecord))
	mux.HandleFunc("POST /zones/{zone}/apply", h.requireRole(auth.RoleAdmin, h.applyZone))
	mux.HandleFunc("POST /zones/{zone}/reset", h.requireRole(auth.RoleAdmin, h.resetZoneDraft))
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	lang := h.resolveLanguage(w, r)
	if h.isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	h.render(w, "login.html", viewData{
		L:           h.i18n.Catalog(lang),
		Lang:        lang,
		Supported:   h.i18n.Supported(),
		OIDCEnabled: h.auth.OIDCEnabled(),
	}, http.StatusOK)
}

func (h *Handler) loginPassword(w http.ResponseWriter, r *http.Request) {
	lang := h.resolveLanguage(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	session, err := h.auth.LoginWithPassword(r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		h.render(w, "login.html", viewData{
			L:           h.i18n.Catalog(lang),
			Lang:        lang,
			Supported:   h.i18n.Supported(),
			OIDCEnabled: h.auth.OIDCEnabled(),
			Error:       h.i18n.Catalog(lang)["login_failed"],
		}, http.StatusUnauthorized)
		return
	}

	h.setSessionCookie(w, session.ID, r.TLS != nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) startOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !h.auth.OIDCEnabled() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	authURL, err := h.auth.BeginOIDCAuth()
	if err != nil {
		http.Error(w, "failed to start oidc flow", http.StatusBadGateway)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request) {
	lang := h.resolveLanguage(w, r)
	if !h.auth.OIDCEnabled() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if oidcErr := strings.TrimSpace(r.URL.Query().Get("error")); oidcErr != "" {
		h.render(w, "login.html", viewData{
			L:           h.i18n.Catalog(lang),
			Lang:        lang,
			Supported:   h.i18n.Supported(),
			OIDCEnabled: true,
			Error:       oidcErr,
		}, http.StatusUnauthorized)
		return
	}

	session, err := h.auth.CompleteOIDCAuth(r.Context(), r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if err != nil {
		h.render(w, "login.html", viewData{
			L:           h.i18n.Catalog(lang),
			Lang:        lang,
			Supported:   h.i18n.Supported(),
			OIDCEnabled: true,
			Error:       h.i18n.Catalog(lang)["oidc_login_failed"],
		}, http.StatusUnauthorized)
		return
	}

	h.setSessionCookie(w, session.ID, r.TLS != nil)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	sessionID, _ := h.readSessionID(r)
	h.auth.RevokeSession(sessionID)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	state, err := h.buildDashboardState(r.Context(), lang, strings.TrimSpace(r.URL.Query().Get("zone")), session)
	if err != nil {
		http.Error(w, "failed to render dashboard", http.StatusInternalServerError)
		return
	}

	h.render(w, "dashboard.html", state, http.StatusOK)
}

func (h *Handler) createZone(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	zoneName := strings.TrimSpace(r.FormValue("name"))
	kind := domain.ZoneKind(strings.TrimSpace(r.FormValue("kind")))

	if err := h.zones.CreateZone(r.Context(), domain.Zone{Name: zoneName, Kind: kind}); err != nil {
		h.respondDomainError(w, err)
		return
	}

	state, err := h.buildDashboardState(r.Context(), lang, zoneName, session)
	if err != nil {
		http.Error(w, "failed to render workspace", http.StatusInternalServerError)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) deleteZone(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	zoneName := strings.TrimSpace(r.PathValue("zone"))

	if err := h.zones.DeleteZone(r.Context(), zoneName); err != nil {
		h.respondDomainError(w, err)
		return
	}

	state, err := h.buildDashboardState(r.Context(), lang, "", session)
	if err != nil {
		http.Error(w, "failed to render workspace", http.StatusInternalServerError)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) zoneEditor(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		http.Error(w, "zone missing", http.StatusBadRequest)
		return
	}

	state, err := h.buildDashboardState(r.Context(), lang, zoneName, session)
	if err != nil {
		http.Error(w, "failed to render editor", http.StatusInternalServerError)
		return
	}

	h.render(w, "zone_editor", state, http.StatusOK)
}

func (h *Handler) toggleDNSSEC(w http.ResponseWriter, r *http.Request, session auth.Session) {
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		http.Error(w, "zone missing", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	enabled, err := strconv.ParseBool(strings.TrimSpace(r.FormValue("enabled")))
	if err != nil {
		http.Error(w, "invalid dnssec value", http.StatusBadRequest)
		return
	}

	if err := h.zones.SetDNSSEC(r.Context(), zoneName, enabled); err != nil {
		h.respondDomainError(w, err)
		return
	}

	h.renderZoneEditor(w, r, zoneName, session)
}

func (h *Handler) saveRecord(w http.ResponseWriter, r *http.Request, session auth.Session) {
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		http.Error(w, "zone missing", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	ttl := uint32(3600)
	rawTTL := strings.TrimSpace(r.FormValue("ttl"))
	if rawTTL != "" {
		value, err := strconv.ParseUint(rawTTL, 10, 32)
		if err != nil {
			http.Error(w, "invalid ttl", http.StatusBadRequest)
			return
		}
		ttl = uint32(value)
	}

	err := h.zones.SaveRecord(
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
		h.respondDomainError(w, err)
		return
	}

	h.renderZoneEditor(w, r, zoneName, session)
}

func (h *Handler) deleteRecord(w http.ResponseWriter, r *http.Request, session auth.Session) {
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		http.Error(w, "zone missing", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	if err := h.zones.DeleteRecord(r.Context(), zoneName, r.FormValue("name"), r.FormValue("type")); err != nil {
		h.respondDomainError(w, err)
		return
	}

	h.renderZoneEditor(w, r, zoneName, session)
}

func (h *Handler) applyZone(w http.ResponseWriter, r *http.Request, session auth.Session) {
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		http.Error(w, "zone missing", http.StatusBadRequest)
		return
	}

	if err := h.zones.Apply(r.Context(), zoneName); err != nil {
		h.respondDomainError(w, err)
		return
	}

	h.renderZoneEditor(w, r, zoneName, session)
}

func (h *Handler) resetZoneDraft(w http.ResponseWriter, r *http.Request, session auth.Session) {
	zoneName := strings.TrimSpace(r.PathValue("zone"))
	if zoneName == "" {
		http.Error(w, "zone missing", http.StatusBadRequest)
		return
	}

	if err := h.zones.ResetDraft(r.Context(), zoneName); err != nil {
		h.respondDomainError(w, err)
		return
	}

	h.renderZoneEditor(w, r, zoneName, session)
}

func (h *Handler) renderZoneEditor(w http.ResponseWriter, r *http.Request, zoneName string, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	state, err := h.buildDashboardState(r.Context(), lang, zoneName, session)
	if err != nil {
		http.Error(w, "failed to render editor", http.StatusInternalServerError)
		return
	}

	h.render(w, "zone_editor", state, http.StatusOK)
}

func (h *Handler) buildDashboardState(ctx context.Context, lang, selected string, session auth.Session) (viewData, error) {
	zones, err := h.zones.ListZones(ctx)
	if err != nil {
		return viewData{}, err
	}
	if selected == "" && len(zones) > 0 {
		selected = zones[0].Name
	}

	data := viewData{
		L:           h.i18n.Catalog(lang),
		Lang:        lang,
		Supported:   h.i18n.Supported(),
		Zones:       zones,
		CurrentUser: &session.User,
		IsAdmin:     session.User.Role == auth.RoleAdmin,
		OIDCEnabled: h.auth.OIDCEnabled(),
	}

	if selected == "" {
		return data, nil
	}

	draft, err := h.zones.GetDraft(ctx, selected)
	if err != nil {
		if errors.Is(err, domain.ErrZoneNotFound) {
			return data, nil
		}
		return viewData{}, err
	}

	dirty, err := h.zones.IsDraftDirty(ctx, selected)
	if err != nil {
		return viewData{}, err
	}

	data.SelectedZone = &draft
	data.DraftDirty = dirty
	return data, nil
}

func (h *Handler) render(w http.ResponseWriter, templateName string, data viewData, status int) {
	var out bytes.Buffer
	if err := h.templates.ExecuteTemplate(&out, templateName, data); err != nil {
		http.Error(w, "template rendering failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(out.Bytes())
}

func (h *Handler) requireAuth(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, ok := h.currentSession(r)
		if ok {
			next(w, r, session)
			return
		}

		if strings.EqualFold(r.Header.Get("HX-Request"), "true") {
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func (h *Handler) requireRole(required auth.Role, next authedHandler) http.HandlerFunc {
	return h.requireAuth(func(w http.ResponseWriter, r *http.Request, session auth.Session) {
		if session.User.Role != required {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r, session)
	})
}

func (h *Handler) currentSession(r *http.Request) (auth.Session, bool) {
	sessionID, ok := h.readSessionID(r)
	if !ok {
		return auth.Session{}, false
	}

	return h.auth.GetSession(sessionID)
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

func (h *Handler) setSessionCookie(w http.ResponseWriter, sessionID string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour),
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

func (h *Handler) respondDomainError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError

	switch {
	case errors.Is(err, domain.ErrInvalidZone), errors.Is(err, domain.ErrInvalidRec):
		status = http.StatusBadRequest
	case errors.Is(err, domain.ErrZoneNotFound):
		status = http.StatusNotFound
	case errors.Is(err, domain.ErrZoneExists):
		status = http.StatusConflict
	case errors.Is(err, domain.ErrBackend):
		status = http.StatusBadGateway
	}

	http.Error(w, err.Error(), status)
}
