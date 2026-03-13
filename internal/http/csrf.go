package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/go-pdns-ui/internal/auth"
)

const (
	csrfFieldName       = "csrf_token"
	csrfHeaderName      = "X-CSRF-Token"
	csrfLoginCookieName = "go_pdns_ui_csrf_login"
)

// CSRFManager handles CSRF token generation and validation.
//
// For authenticated routes, the CSRF token is stored in the session
// (Session.CSRFToken) and validated via RequireSessionToken middleware.
//
// For the pre-authentication login form, a stateless double-submit cookie
// pattern is used: SetLoginToken stores a token in a short-lived cookie and
// returns it for embedding as a hidden form field; ValidateLoginToken then
// compares the submitted field value against the cookie.
type CSRFManager struct {
	fieldName       string
	headerName      string
	loginCookieName string
}

// NewCSRFManager creates a CSRFManager with the default field, header, and
// cookie names.
func NewCSRFManager() *CSRFManager {
	return &CSRFManager{
		fieldName:       csrfFieldName,
		headerName:      csrfHeaderName,
		loginCookieName: csrfLoginCookieName,
	}
}

// GenerateToken creates a cryptographically random 32-byte hex-encoded token.
func (c *CSRFManager) GenerateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// tokenFromRequest extracts the submitted CSRF token from a request.
// It checks the X-CSRF-Token header first (preferred for HTMX/AJAX requests),
// then falls back to the csrf_token form field.
func (c *CSRFManager) tokenFromRequest(r *http.Request) string {
	if token := strings.TrimSpace(r.Header.Get(c.headerName)); token != "" {
		return token
	}
	return strings.TrimSpace(r.FormValue(c.fieldName))
}

// validateToken performs a constant-time comparison of two tokens to prevent
// timing-based side-channel attacks.
func (c *CSRFManager) validateToken(submitted, expected string) bool {
	if submitted == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(submitted), []byte(expected)) == 1
}

// isSafeMethod returns true for HTTP methods that must not mutate server state,
// and therefore do not require CSRF protection.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// RequireSessionToken returns an authedHandler middleware that validates the
// CSRF token stored in the authenticated session against the value submitted
// with the request. Safe HTTP methods (GET, HEAD, OPTIONS, TRACE) bypass
// validation. Returns 403 Forbidden on mismatch.
func (c *CSRFManager) RequireSessionToken(next authedHandler) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, session auth.Session) {
		if !isSafeMethod(r.Method) {
			submitted := c.tokenFromRequest(r)
			if !c.validateToken(submitted, session.CSRFToken) {
				http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
				return
			}
		}
		next(w, r, session)
	}
}

// SetLoginToken generates a new CSRF token for the pre-authentication login
// form, stores it in a short-lived HttpOnly cookie restricted to /login, and
// returns the token value for embedding as a hidden form field.
func (c *CSRFManager) SetLoginToken(w http.ResponseWriter) (string, error) {
	token, err := c.GenerateToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     c.loginCookieName,
		Value:    token,
		Path:     "/login",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})
	return token, nil
}

// ValidateLoginToken validates the CSRF token for the login form by comparing
// the submitted form field value against the value stored in the login cookie.
func (c *CSRFManager) ValidateLoginToken(r *http.Request) bool {
	cookie, err := r.Cookie(c.loginCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return false
	}
	submitted := strings.TrimSpace(r.FormValue(c.fieldName))
	return c.validateToken(submitted, cookie.Value)
}

// ClearLoginToken expires the login CSRF cookie after a login attempt,
// regardless of success or failure.
func (c *CSRFManager) ClearLoginToken(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.loginCookieName,
		Value:    "",
		Path:     "/login",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
