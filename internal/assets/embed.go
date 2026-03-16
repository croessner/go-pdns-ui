package assets

import "embed"

// Files bundles templates and locale JSON catalogs into the binary.
//
//go:embed templates/*.html templates/partials/*.html locales/*.json static/*.js
var Files embed.FS
