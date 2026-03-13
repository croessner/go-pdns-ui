package ui

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
)

type contextKey string

const nonceContextKey contextKey = "csp_nonce"

// SecurityHeaders sets security-relevant HTTP response headers on every
// response and injects a per-request CSP nonce into the request context so
// that templates can emit nonce attributes on inline <script> tags.
//
// The Content-Security-Policy uses a nonce for script-src, eliminating the
// need for 'unsafe-inline' for scripts. Styles still use 'unsafe-inline'
// because DaisyUI/Tailwind inject inline styles at runtime.
//
// The CDN origins for Tailwind and HTMX are allow-listed explicitly so that
// their <script src="..."> tags remain valid even without a nonce attribute.
type SecurityHeaders struct {
	cspTemplate string
}

// NewSecurityHeaders creates a SecurityHeaders instance whose CSP is
// compatible with the HTMX and DaisyUI/Tailwind scripts used in this
// application.
func NewSecurityHeaders() *SecurityHeaders {
	cspTemplate := strings.Join([]string{
		"default-src 'self'",
		"script-src 'nonce-{nonce}' https://cdn.jsdelivr.net https://unpkg.com",
		"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		"frame-ancestors 'none'",
	}, "; ")
	return &SecurityHeaders{cspTemplate: cspTemplate}
}

// generateNonce returns a 16-byte cryptographically random base64url-encoded
// string suitable for use as a CSP nonce value.
func generateNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Apply writes all security headers to w, generating a fresh nonce for this
// request. The nonce is stored in the returned *http.Request's context so
// that handlers and templates can retrieve it via NonceFromContext.
//
// Strict-Transport-Security is only included when secure is true (i.e. the
// connection is over TLS or a trusted proxy reports HTTPS).
func (s *SecurityHeaders) Apply(w http.ResponseWriter, r *http.Request, secure bool) *http.Request {
	nonce, err := generateNonce()
	if err != nil {
		// Fall back to an empty nonce; inline scripts will be blocked by CSP
		// rather than crashing the request.
		nonce = ""
	}

	csp := strings.ReplaceAll(s.cspTemplate, "{nonce}", nonce)

	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	if secure {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	return r.WithContext(context.WithValue(r.Context(), nonceContextKey, nonce))
}

// NonceFromContext retrieves the CSP nonce stored by Apply from a context.
// Returns an empty string if no nonce is present.
func NonceFromContext(ctx context.Context) string {
	v, _ := ctx.Value(nonceContextKey).(string)
	return v
}
