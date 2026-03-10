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
	zonesPerPage      = 10
)

type Handler struct {
	templates     *template.Template
	zones         domain.ZoneService
	zoneTemplates domain.ZoneTemplateService
	auth          auth.Service
	i18n          *i18n.Service
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
	L                  map[string]string
	Lang               string
	Supported          []string
	ShowLoginHint      bool
	Zones              []domain.Zone
	ZoneQuery          string
	ZonePage           int
	ZoneTotal          int
	ZoneTotalPages     int
	ZonePrevPage       int
	ZoneNextPage       int
	ZoneHasPrev        bool
	ZoneHasNext        bool
	SelectedZone       *domain.Zone
	DraftDirty         bool
	Templates          []domain.ZoneTemplate
	SelectedTemplate   *domain.ZoneTemplate
	ZoneRecordForm     recordFormData
	TemplateRecordForm recordFormData
	Error              string
	CurrentUser        *auth.User
	IsAdmin            bool
	OIDCEnabled        bool
}

type authedHandler func(http.ResponseWriter, *http.Request, auth.Session)

func NewHandler(templateFS fs.FS, zones domain.ZoneService, zoneTemplates domain.ZoneTemplateService, authService auth.Service, i18nService *i18n.Service) (*Handler, error) {
	tmpl, err := template.New("views").Funcs(template.FuncMap{
		"pathEscape": url.PathEscape,
	}).ParseFS(templateFS, "templates/*.html", "templates/partials/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	return &Handler{
		templates:     tmpl,
		zones:         zones,
		zoneTemplates: zoneTemplates,
		auth:          authService,
		i18n:          i18nService,
	}, nil
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", h.loginPage)
	mux.HandleFunc("POST /login/password", h.loginPassword)
	mux.HandleFunc("GET /login/oidc/start", h.startOIDCLogin)
	mux.HandleFunc("GET /auth/oidc/callback", h.oidcCallback)
	mux.HandleFunc("GET /logout", h.requireAuth(h.logout))
	mux.HandleFunc("POST /logout", h.requireAuth(h.logout))

	mux.HandleFunc("GET /", h.requireAuth(h.dashboard))
	mux.HandleFunc("POST /zones", h.requireRole(auth.RoleAdmin, h.createZone))
	mux.HandleFunc("POST /zones/{zone}/delete", h.requireRole(auth.RoleAdmin, h.deleteZone))
	mux.HandleFunc("GET /zones/{zone}/editor", h.requireAuth(h.zoneEditor))
	mux.HandleFunc("POST /zones/{zone}/dnssec", h.requireAuth(h.toggleDNSSEC))
	mux.HandleFunc("POST /zones/{zone}/records", h.requireAuth(h.saveRecord))
	mux.HandleFunc("POST /zones/{zone}/records/delete", h.requireAuth(h.deleteRecord))
	mux.HandleFunc("POST /zones/{zone}/apply", h.requireAuth(h.applyZone))
	mux.HandleFunc("POST /zones/{zone}/reset", h.requireAuth(h.resetZoneDraft))

	mux.HandleFunc("POST /templates", h.requireRole(auth.RoleAdmin, h.createTemplate))
	mux.HandleFunc("POST /templates/{template}/delete", h.requireRole(auth.RoleAdmin, h.deleteTemplate))
	mux.HandleFunc("GET /templates/{template}/editor", h.requireRole(auth.RoleAdmin, h.templateEditor))
	mux.HandleFunc("POST /templates/{template}/records", h.requireRole(auth.RoleAdmin, h.saveTemplateRecord))
	mux.HandleFunc("POST /templates/{template}/records/delete", h.requireRole(auth.RoleAdmin, h.deleteTemplateRecord))
}

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	lang := h.resolveLanguage(w, r)
	if h.isAuthenticated(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	h.render(w, "login.html", viewData{
		L:             h.i18n.Catalog(lang),
		Lang:          lang,
		Supported:     h.i18n.Supported(),
		ShowLoginHint: h.auth.ShowDefaultCredentialsHint(),
		OIDCEnabled:   h.auth.OIDCEnabled(),
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
			L:             h.i18n.Catalog(lang),
			Lang:          lang,
			Supported:     h.i18n.Supported(),
			ShowLoginHint: h.auth.ShowDefaultCredentialsHint(),
			OIDCEnabled:   h.auth.OIDCEnabled(),
			Error:         h.i18n.Catalog(lang)["login_failed"],
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
			L:             h.i18n.Catalog(lang),
			Lang:          lang,
			Supported:     h.i18n.Supported(),
			ShowLoginHint: h.auth.ShowDefaultCredentialsHint(),
			OIDCEnabled:   true,
			Error:         oidcErr,
		}, http.StatusUnauthorized)
		return
	}

	session, err := h.auth.CompleteOIDCAuth(r.Context(), r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if err != nil {
		h.render(w, "login.html", viewData{
			L:             h.i18n.Catalog(lang),
			Lang:          lang,
			Supported:     h.i18n.Supported(),
			ShowLoginHint: h.auth.ShowDefaultCredentialsHint(),
			OIDCEnabled:   true,
			Error:         h.i18n.Catalog(lang)["oidc_login_failed"],
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
	zoneQuery := strings.TrimSpace(r.URL.Query().Get("q"))
	zonePage := parsePage(strings.TrimSpace(r.URL.Query().Get("page")))
	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		zoneQuery,
		zonePage,
		strings.TrimSpace(r.URL.Query().Get("zone")),
		strings.TrimSpace(r.URL.Query().Get("template")),
		session,
	)
	if err != nil {
		h.respondDomainError(w, err)
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
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	zoneName := strings.TrimSpace(r.FormValue("name"))
	kind := domain.ZoneKind(strings.TrimSpace(r.FormValue("kind")))
	templateName := strings.TrimSpace(r.FormValue("template"))

	zone := domain.Zone{Name: zoneName, Kind: kind}
	if templateName != "" {
		templateDef, err := h.zoneTemplates.GetTemplate(r.Context(), templateName)
		if err != nil {
			h.respondDomainError(w, err)
			return
		}

		zone.Kind = templateDef.Kind
		zone.Records = domain.InstantiateTemplateRecords(zoneName, templateDef.Records)
	}

	if err := h.zones.CreateZone(r.Context(), zone); err != nil {
		h.respondDomainError(w, err)
		return
	}

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		zoneName,
		templateName,
		session,
	)
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

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		"",
		strings.TrimSpace(r.FormValue("selected_template")),
		session,
	)
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

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.URL.Query().Get("q")),
		parsePage(strings.TrimSpace(r.URL.Query().Get("page"))),
		zoneName,
		strings.TrimSpace(r.URL.Query().Get("template")),
		session,
	)
	if err != nil {
		http.Error(w, "failed to render editor", http.StatusInternalServerError)
		return
	}

	h.applyZoneRecordFormFromQuery(r, &state)
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

	ttl, err := parseTTL(r.FormValue("ttl"))
	if err != nil {
		http.Error(w, "invalid ttl", http.StatusBadRequest)
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

func (h *Handler) createTemplate(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	templateName := strings.TrimSpace(r.FormValue("name"))
	kind := domain.ZoneKind(strings.TrimSpace(r.FormValue("kind")))

	if err := h.zoneTemplates.CreateTemplate(r.Context(), domain.ZoneTemplate{Name: templateName, Kind: kind}); err != nil {
		h.respondDomainError(w, err)
		return
	}

	selectedZone := strings.TrimSpace(r.FormValue("selected_zone"))
	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		selectedZone,
		templateName,
		session,
	)
	if err != nil {
		http.Error(w, "failed to render workspace", http.StatusInternalServerError)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) deleteTemplate(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	templateName := strings.TrimSpace(r.PathValue("template"))

	if err := h.zoneTemplates.DeleteTemplate(r.Context(), templateName); err != nil {
		h.respondDomainError(w, err)
		return
	}

	selectedZone := strings.TrimSpace(r.FormValue("selected_zone"))
	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.FormValue("q")),
		parsePage(strings.TrimSpace(r.FormValue("page"))),
		selectedZone,
		"",
		session,
	)
	if err != nil {
		http.Error(w, "failed to render workspace", http.StatusInternalServerError)
		return
	}

	h.render(w, "workspace", state, http.StatusOK)
}

func (h *Handler) templateEditor(w http.ResponseWriter, r *http.Request, session auth.Session) {
	lang := h.resolveLanguage(w, r)
	templateName := strings.TrimSpace(r.PathValue("template"))
	if templateName == "" {
		http.Error(w, "template missing", http.StatusBadRequest)
		return
	}

	state, err := h.buildDashboardState(
		r.Context(),
		lang,
		strings.TrimSpace(r.URL.Query().Get("q")),
		parsePage(strings.TrimSpace(r.URL.Query().Get("page"))),
		strings.TrimSpace(r.URL.Query().Get("zone")),
		templateName,
		session,
	)
	if err != nil {
		http.Error(w, "failed to render editor", http.StatusInternalServerError)
		return
	}

	h.applyTemplateRecordFormFromQuery(r, &state)
	h.render(w, "zone_template_editor", state, http.StatusOK)
}

func (h *Handler) saveTemplateRecord(w http.ResponseWriter, r *http.Request, session auth.Session) {
	templateName := strings.TrimSpace(r.PathValue("template"))
	if templateName == "" {
		http.Error(w, "template missing", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	ttl, err := parseTTL(r.FormValue("ttl"))
	if err != nil {
		http.Error(w, "invalid ttl", http.StatusBadRequest)
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
		h.respondDomainError(w, err)
		return
	}

	h.renderTemplateEditor(w, r, templateName, session)
}

func (h *Handler) deleteTemplateRecord(w http.ResponseWriter, r *http.Request, session auth.Session) {
	templateName := strings.TrimSpace(r.PathValue("template"))
	if templateName == "" {
		http.Error(w, "template missing", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	if err := h.zoneTemplates.DeleteTemplateRecord(r.Context(), templateName, r.FormValue("name"), r.FormValue("type")); err != nil {
		h.respondDomainError(w, err)
		return
	}

	h.renderTemplateEditor(w, r, templateName, session)
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
		session,
	)
	if err != nil {
		http.Error(w, "failed to render editor", http.StatusInternalServerError)
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
		session,
	)
	if err != nil {
		http.Error(w, "failed to render editor", http.StatusInternalServerError)
		return
	}

	h.render(w, "zone_template_editor", state, http.StatusOK)
}

func (h *Handler) buildDashboardState(ctx context.Context, lang, zoneQuery string, zonePage int, selectedZone, selectedTemplate string, session auth.Session) (viewData, error) {
	allZones, err := h.zones.ListZones(ctx)
	if err != nil {
		return viewData{}, err
	}

	zoneQuery = strings.TrimSpace(zoneQuery)
	// PowerDNS list zones endpoint has no native pagination parameters,
	// so we paginate server-side after fetching the current zone list.
	filteredZones := filterZones(allZones, zoneQuery)
	pagedZones, resolvedPage, totalPages := paginateZones(filteredZones, zonePage, zonesPerPage)
	if selectedZone == "" && len(pagedZones) > 0 {
		selectedZone = pagedZones[0].Name
	}

	var templates []domain.ZoneTemplate
	if session.User.Role == auth.RoleAdmin {
		templates, err = h.zoneTemplates.ListTemplates(ctx)
		if err != nil {
			return viewData{}, err
		}
		if selectedTemplate == "" && len(templates) > 0 {
			selectedTemplate = templates[0].Name
		}
	}

	data := viewData{
		L:              h.i18n.Catalog(lang),
		Lang:           lang,
		Supported:      h.i18n.Supported(),
		Zones:          pagedZones,
		ZoneQuery:      zoneQuery,
		ZonePage:       resolvedPage,
		ZoneTotal:      len(filteredZones),
		ZoneTotalPages: totalPages,
		ZonePrevPage:   resolvedPage - 1,
		ZoneNextPage:   resolvedPage + 1,
		ZoneHasPrev:    resolvedPage > 1,
		ZoneHasNext:    resolvedPage < totalPages,
		Templates:      templates,
		ZoneRecordForm: recordFormData{
			Type: "A",
			TTL:  3600,
		},
		TemplateRecordForm: recordFormData{
			Type: "A",
			TTL:  3600,
		},
		CurrentUser: &session.User,
		IsAdmin:     session.User.Role == auth.RoleAdmin,
		OIDCEnabled: h.auth.OIDCEnabled(),
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
}

func findRecord(records []domain.Record, name, recordType string) (domain.Record, bool) {
	for _, record := range records {
		if record.Name == name && record.Type == recordType {
			return record, true
		}
	}

	return domain.Record{}, false
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

		if isHXRequest(r) {
			w.Header().Set("HX-Redirect", "/login")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func isHXRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("HX-Request"), "true")
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
	case errors.Is(err, domain.ErrInvalidZone), errors.Is(err, domain.ErrInvalidRec), errors.Is(err, domain.ErrInvalidTemplate):
		status = http.StatusBadRequest
	case errors.Is(err, domain.ErrZoneNotFound), errors.Is(err, domain.ErrTemplateNotFound):
		status = http.StatusNotFound
	case errors.Is(err, domain.ErrZoneExists), errors.Is(err, domain.ErrTemplateExists):
		status = http.StatusConflict
	case errors.Is(err, domain.ErrBackend):
		status = http.StatusBadGateway
	}

	http.Error(w, err.Error(), status)
}
