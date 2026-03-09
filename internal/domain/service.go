package domain

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
)

type ZoneService interface {
	ListZones(ctx context.Context) ([]Zone, error)
	GetDraft(ctx context.Context, zoneName string) (Zone, error)
	CreateZone(ctx context.Context, zone Zone) error
	DeleteZone(ctx context.Context, zoneName string) error
	SetDNSSEC(ctx context.Context, zoneName string, enabled bool) error
	SaveRecord(ctx context.Context, zoneName, oldName, oldType string, record Record) error
	DeleteRecord(ctx context.Context, zoneName, recordName, recordType string) error
	Apply(ctx context.Context, zoneName string) error
	ResetDraft(ctx context.Context, zoneName string) error
	IsDraftDirty(ctx context.Context, zoneName string) (bool, error)
}

type DraftZoneService struct {
	repo ZoneRepository

	mu    sync.RWMutex
	draft map[string]Zone
}

func NewDraftZoneService(repo ZoneRepository) *DraftZoneService {
	return &DraftZoneService{
		repo:  repo,
		draft: make(map[string]Zone),
	}
}

func (s *DraftZoneService) ListZones(ctx context.Context) ([]Zone, error) {
	liveZones, err := s.repo.ListZones(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: list zones: %v", ErrBackend, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	liveByName := make(map[string]struct{}, len(liveZones))
	for _, zone := range liveZones {
		liveByName[zone.Name] = struct{}{}
		if _, exists := s.draft[zone.Name]; !exists {
			s.draft[zone.Name] = cloneZone(zone)
		}
	}

	for zoneName := range s.draft {
		if _, exists := liveByName[zoneName]; !exists {
			delete(s.draft, zoneName)
		}
	}

	return liveZones, nil
}

func (s *DraftZoneService) GetDraft(ctx context.Context, zoneName string) (Zone, error) {
	zoneName = strings.TrimSpace(zoneName)
	if zoneName == "" {
		return Zone{}, ErrZoneNotFound
	}

	s.mu.RLock()
	draftZone, exists := s.draft[zoneName]
	s.mu.RUnlock()
	if exists {
		return cloneZone(draftZone), nil
	}

	liveZone, err := s.repo.GetZone(ctx, zoneName)
	if err != nil {
		return Zone{}, err
	}

	s.mu.Lock()
	s.draft[zoneName] = cloneZone(liveZone)
	s.mu.Unlock()

	return cloneZone(liveZone), nil
}

func (s *DraftZoneService) CreateZone(ctx context.Context, zone Zone) error {
	if err := validateZone(zone); err != nil {
		return err
	}

	if len(zone.Records) == 0 {
		zone.Records = defaultRecords(zone.Name)
	}

	if err := s.repo.CreateZone(ctx, zone); err != nil {
		return err
	}

	s.mu.Lock()
	s.draft[zone.Name] = cloneZone(zone)
	s.mu.Unlock()

	return nil
}

func (s *DraftZoneService) DeleteZone(ctx context.Context, zoneName string) error {
	zoneName = strings.TrimSpace(zoneName)
	if zoneName == "" {
		return ErrZoneNotFound
	}

	if err := s.repo.DeleteZone(ctx, zoneName); err != nil {
		return err
	}

	s.mu.Lock()
	delete(s.draft, zoneName)
	s.mu.Unlock()

	return nil
}

func (s *DraftZoneService) SetDNSSEC(ctx context.Context, zoneName string, enabled bool) error {
	zone, err := s.GetDraft(ctx, zoneName)
	if err != nil {
		return err
	}

	zone.DNSSECEnabled = enabled
	s.mu.Lock()
	s.draft[zoneName] = zone
	s.mu.Unlock()

	return nil
}

func (s *DraftZoneService) SaveRecord(ctx context.Context, zoneName, oldName, oldType string, record Record) error {
	zone, err := s.GetDraft(ctx, zoneName)
	if err != nil {
		return err
	}

	normalized, err := normalizeRecord(record)
	if err != nil {
		return err
	}

	oldName = strings.TrimSpace(oldName)
	oldType = strings.ToUpper(strings.TrimSpace(oldType))

	if oldName != "" && oldType != "" && (oldName != normalized.Name || oldType != normalized.Type) {
		zone.Records = slices.DeleteFunc(zone.Records, func(entry Record) bool {
			return entry.Name == oldName && entry.Type == oldType
		})
	}

	found := false
	for i := range zone.Records {
		if zone.Records[i].Name == normalized.Name && zone.Records[i].Type == normalized.Type {
			zone.Records[i] = normalized
			found = true
		}
	}

	if !found {
		zone.Records = append(zone.Records, normalized)
	}

	slices.SortFunc(zone.Records, func(a, b Record) int {
		if a.Name == b.Name {
			return strings.Compare(a.Type, b.Type)
		}
		return strings.Compare(a.Name, b.Name)
	})

	s.mu.Lock()
	s.draft[zoneName] = zone
	s.mu.Unlock()

	return nil
}

func (s *DraftZoneService) DeleteRecord(ctx context.Context, zoneName, recordName, recordType string) error {
	zone, err := s.GetDraft(ctx, zoneName)
	if err != nil {
		return err
	}

	recordName = strings.TrimSpace(recordName)
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	if recordName == "" || recordType == "" {
		return ErrInvalidRec
	}

	zone.Records = slices.DeleteFunc(zone.Records, func(entry Record) bool {
		return entry.Name == recordName && entry.Type == recordType
	})

	s.mu.Lock()
	s.draft[zoneName] = zone
	s.mu.Unlock()

	return nil
}

func (s *DraftZoneService) Apply(ctx context.Context, zoneName string) error {
	draftZone, err := s.GetDraft(ctx, zoneName)
	if err != nil {
		return err
	}

	if err := s.repo.ApplyZone(ctx, draftZone); err != nil {
		return fmt.Errorf("%w: apply zone: %v", ErrBackend, err)
	}

	liveZone, err := s.repo.GetZone(ctx, zoneName)
	if err != nil {
		return fmt.Errorf("%w: refresh zone: %v", ErrBackend, err)
	}

	s.mu.Lock()
	s.draft[zoneName] = cloneZone(liveZone)
	s.mu.Unlock()

	return nil
}

func (s *DraftZoneService) ResetDraft(ctx context.Context, zoneName string) error {
	liveZone, err := s.repo.GetZone(ctx, zoneName)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.draft[zoneName] = cloneZone(liveZone)
	s.mu.Unlock()

	return nil
}

func (s *DraftZoneService) IsDraftDirty(ctx context.Context, zoneName string) (bool, error) {
	draftZone, err := s.GetDraft(ctx, zoneName)
	if err != nil {
		return false, err
	}

	liveZone, err := s.repo.GetZone(ctx, zoneName)
	if err != nil {
		return false, err
	}

	return !zonesEqual(liveZone, draftZone), nil
}

func validateZone(zone Zone) error {
	zone.Name = strings.TrimSpace(zone.Name)
	if zone.Name == "" {
		return ErrInvalidZone
	}

	if !zone.Kind.Valid() {
		return ErrInvalidZone
	}

	switch zone.Kind {
	case ZoneReverseV4:
		if !strings.HasSuffix(zone.Name, ".in-addr.arpa") {
			return fmt.Errorf("%w: reverse-v4 zones must end with .in-addr.arpa", ErrInvalidZone)
		}
	case ZoneReverseV6:
		if !strings.HasSuffix(zone.Name, ".ip6.arpa") {
			return fmt.Errorf("%w: reverse-v6 zones must end with .ip6.arpa", ErrInvalidZone)
		}
	}

	return nil
}

func normalizeRecord(record Record) (Record, error) {
	record.Name = strings.TrimSpace(record.Name)
	record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
	record.Content = strings.TrimSpace(record.Content)

	if record.Name == "" || record.Type == "" || record.Content == "" {
		return Record{}, ErrInvalidRec
	}

	if record.TTL == 0 {
		record.TTL = 3600
	}

	return record, nil
}

func defaultRecords(zoneName string) []Record {
	return []Record{
		{
			Name:    "@",
			Type:    "SOA",
			TTL:     3600,
			Content: "ns1." + zoneName + " hostmaster." + zoneName + " 1 10800 3600 604800 3600",
		},
		{
			Name:    "@",
			Type:    "NS",
			TTL:     3600,
			Content: "ns1." + zoneName + ".",
		},
	}
}

func cloneZone(zone Zone) Zone {
	cloned := Zone{
		Name:          zone.Name,
		Kind:          zone.Kind,
		DNSSECEnabled: zone.DNSSECEnabled,
		Records:       make([]Record, len(zone.Records)),
	}

	copy(cloned.Records, zone.Records)
	return cloned
}

func zonesEqual(a, b Zone) bool {
	if a.Name != b.Name || a.Kind != b.Kind || a.DNSSECEnabled != b.DNSSECEnabled {
		return false
	}

	if len(a.Records) != len(b.Records) {
		return false
	}

	for i := range a.Records {
		if a.Records[i] != b.Records[i] {
			return false
		}
	}

	return true
}
