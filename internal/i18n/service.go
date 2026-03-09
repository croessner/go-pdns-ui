package i18n

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
)

type Service struct {
	fallback string
	catalogs map[string]map[string]string
}

func NewService(files fs.FS, localeDir, fallbackLang string) (*Service, error) {
	entries, err := fs.ReadDir(files, localeDir)
	if err != nil {
		return nil, fmt.Errorf("read locales directory: %w", err)
	}

	catalogs := make(map[string]map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		lang := strings.TrimSuffix(entry.Name(), ".json")
		lang = normalizeLang(lang)
		if lang == "" {
			continue
		}

		raw, readErr := fs.ReadFile(files, path.Join(localeDir, entry.Name()))
		if readErr != nil {
			return nil, fmt.Errorf("read locale %s: %w", entry.Name(), readErr)
		}

		labels := map[string]string{}
		if unmarshalErr := json.Unmarshal(raw, &labels); unmarshalErr != nil {
			return nil, fmt.Errorf("parse locale %s: %w", entry.Name(), unmarshalErr)
		}

		catalogs[lang] = labels
	}

	fallbackLang = normalizeLang(fallbackLang)
	if fallbackLang == "" {
		fallbackLang = "en"
	}

	if _, ok := catalogs[fallbackLang]; !ok {
		return nil, fmt.Errorf("fallback locale %q not found", fallbackLang)
	}

	return &Service{
		fallback: fallbackLang,
		catalogs: catalogs,
	}, nil
}

func (s *Service) Normalize(lang string) string {
	normalized := normalizeLang(lang)
	if normalized == "" {
		return s.fallback
	}

	if _, ok := s.catalogs[normalized]; ok {
		return normalized
	}

	return s.fallback
}

func (s *Service) Fallback() string {
	return s.fallback
}

func (s *Service) Catalog(lang string) map[string]string {
	lang = s.Normalize(lang)

	fallback := s.catalogs[s.fallback]
	result := make(map[string]string, len(fallback))
	for key, value := range fallback {
		result[key] = value
	}

	if lang == s.fallback {
		return result
	}

	for key, value := range s.catalogs[lang] {
		result[key] = value
	}

	return result
}

func (s *Service) Supported() []string {
	languages := make([]string, 0, len(s.catalogs))
	for lang := range s.catalogs {
		languages = append(languages, lang)
	}

	slices.Sort(languages)
	return languages
}

func normalizeLang(lang string) string {
	lang = strings.TrimSpace(strings.ToLower(lang))
	if lang == "" {
		return ""
	}

	lang = strings.ReplaceAll(lang, "_", "-")
	base, _, _ := strings.Cut(lang, "-")
	return base
}
