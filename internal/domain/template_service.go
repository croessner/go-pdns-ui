package domain

import (
	"context"
	"slices"
	"strings"
	"sync"
)

const (
	TemplateZoneNameToken = "{{ZONE_NAME}}"
	TemplateZoneFQDNToken = "{{ZONE_FQDN}}"
)

type ZoneTemplateService interface {
	ListTemplates(ctx context.Context) ([]ZoneTemplate, error)
	GetTemplate(ctx context.Context, name string) (ZoneTemplate, error)
	CreateTemplate(ctx context.Context, template ZoneTemplate) error
	DeleteTemplate(ctx context.Context, name string) error
	SaveTemplateRecord(ctx context.Context, templateName, oldName, oldType string, record Record) error
	DeleteTemplateRecord(ctx context.Context, templateName, recordName, recordType string) error
}

type InMemoryZoneTemplateService struct {
	mu        sync.RWMutex
	templates map[string]ZoneTemplate
}

func NewInMemoryZoneTemplateService(seed []ZoneTemplate) *InMemoryZoneTemplateService {
	templates := make(map[string]ZoneTemplate, len(seed))
	for _, tpl := range seed {
		normalized, err := normalizeTemplate(tpl)
		if err != nil {
			continue
		}
		templates[normalized.Name] = normalized
	}

	return &InMemoryZoneTemplateService{
		templates: templates,
	}
}

func (s *InMemoryZoneTemplateService) ListTemplates(_ context.Context) ([]ZoneTemplate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]ZoneTemplate, 0, len(s.templates))
	for _, template := range s.templates {
		result = append(result, cloneTemplate(template))
	}

	slices.SortFunc(result, func(a, b ZoneTemplate) int {
		return strings.Compare(a.Name, b.Name)
	})

	return result, nil
}

func (s *InMemoryZoneTemplateService) GetTemplate(_ context.Context, name string) (ZoneTemplate, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ZoneTemplate{}, ErrTemplateNotFound
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	template, exists := s.templates[name]
	if !exists {
		return ZoneTemplate{}, ErrTemplateNotFound
	}

	return cloneTemplate(template), nil
}

func (s *InMemoryZoneTemplateService) CreateTemplate(_ context.Context, template ZoneTemplate) error {
	normalized, err := normalizeTemplate(template)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.templates[normalized.Name]; exists {
		return ErrTemplateExists
	}

	s.templates[normalized.Name] = normalized
	return nil
}

func (s *InMemoryZoneTemplateService) DeleteTemplate(_ context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return ErrTemplateNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.templates[name]; !exists {
		return ErrTemplateNotFound
	}

	delete(s.templates, name)
	return nil
}

func (s *InMemoryZoneTemplateService) SaveTemplateRecord(_ context.Context, templateName, oldName, oldType string, record Record) error {
	templateName = strings.TrimSpace(templateName)
	if templateName == "" {
		return ErrTemplateNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	template, exists := s.templates[templateName]
	if !exists {
		return ErrTemplateNotFound
	}

	normalized, err := normalizeRecord(record)
	if err != nil {
		return err
	}

	oldName = strings.TrimSpace(oldName)
	oldType = strings.ToUpper(strings.TrimSpace(oldType))

	if oldName != "" && oldType != "" && (oldName != normalized.Name || oldType != normalized.Type) {
		template.Records = slices.DeleteFunc(template.Records, func(entry Record) bool {
			return entry.Name == oldName && entry.Type == oldType
		})
	}

	found := false
	for i := range template.Records {
		if template.Records[i].Name == normalized.Name && template.Records[i].Type == normalized.Type {
			template.Records[i] = normalized
			found = true
		}
	}

	if !found {
		template.Records = append(template.Records, normalized)
	}

	sortRecords(template.Records)
	s.templates[templateName] = template
	return nil
}

func (s *InMemoryZoneTemplateService) DeleteTemplateRecord(_ context.Context, templateName, recordName, recordType string) error {
	templateName = strings.TrimSpace(templateName)
	if templateName == "" {
		return ErrTemplateNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	template, exists := s.templates[templateName]
	if !exists {
		return ErrTemplateNotFound
	}

	recordName = strings.TrimSpace(recordName)
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	if recordName == "" || recordType == "" {
		return ErrInvalidRec
	}

	template.Records = slices.DeleteFunc(template.Records, func(entry Record) bool {
		return entry.Name == recordName && entry.Type == recordType
	})

	s.templates[templateName] = template
	return nil
}

func InstantiateTemplateRecords(zoneName string, records []Record) []Record {
	zoneName = strings.TrimSpace(zoneName)
	zoneFQDN := zoneName
	if zoneFQDN != "" && !strings.HasSuffix(zoneFQDN, ".") {
		zoneFQDN += "."
	}

	result := make([]Record, 0, len(records))
	for _, record := range records {
		cloned := record
		cloned.Name = applyTemplateTokens(cloned.Name, zoneName, zoneFQDN)
		cloned.Content = applyTemplateTokens(cloned.Content, zoneName, zoneFQDN)
		cloned = normalizeTemplateRecordContent(cloned)
		result = append(result, cloned)
	}

	return result
}

func normalizeTemplateRecordContent(record Record) Record {
	record.Type = strings.ToUpper(strings.TrimSpace(record.Type))

	switch record.Type {
	case "SOA":
		parts := strings.Fields(record.Content)
		if len(parts) >= 2 {
			parts[0] = ensureTrailingDot(parts[0])
			parts[1] = ensureTrailingDot(parts[1])
			record.Content = strings.Join(parts, " ")
		}
	case "NS":
		record.Content = ensureTrailingDot(record.Content)
	}

	return record
}

func applyTemplateTokens(value, zoneName, zoneFQDN string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}

	value = strings.ReplaceAll(value, TemplateZoneNameToken, zoneName)
	value = strings.ReplaceAll(value, TemplateZoneFQDNToken, zoneFQDN)
	return value
}

func normalizeTemplate(template ZoneTemplate) (ZoneTemplate, error) {
	template.Name = strings.TrimSpace(template.Name)
	if template.Name == "" {
		return ZoneTemplate{}, ErrInvalidTemplate
	}

	if !template.Kind.Valid() {
		return ZoneTemplate{}, ErrInvalidTemplate
	}

	normalizedRecords := make([]Record, 0, len(template.Records))
	for _, record := range template.Records {
		normalized, err := normalizeRecord(record)
		if err != nil {
			return ZoneTemplate{}, err
		}
		normalizedRecords = append(normalizedRecords, normalized)
	}

	sortRecords(normalizedRecords)

	return ZoneTemplate{
		Name:    template.Name,
		Kind:    template.Kind,
		Records: normalizedRecords,
	}, nil
}

func cloneTemplate(template ZoneTemplate) ZoneTemplate {
	cloned := ZoneTemplate{
		Name:    template.Name,
		Kind:    template.Kind,
		Records: make([]Record, len(template.Records)),
	}
	copy(cloned.Records, template.Records)
	return cloned
}

func sortRecords(records []Record) {
	slices.SortFunc(records, func(a, b Record) int {
		if a.Name == b.Name {
			if a.Type == b.Type {
				return strings.Compare(a.Content, b.Content)
			}
			return strings.Compare(a.Type, b.Type)
		}
		return strings.Compare(a.Name, b.Name)
	})
}
