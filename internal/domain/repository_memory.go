package domain

import (
	"context"
	"slices"
	"strings"
	"sync"
)

type InMemoryZoneRepository struct {
	mu    sync.RWMutex
	zones map[string]Zone
}

func NewInMemoryZoneRepository(seed []Zone) *InMemoryZoneRepository {
	zones := make(map[string]Zone, len(seed))
	for _, zone := range seed {
		if err := validateZone(zone); err != nil {
			continue
		}
		zones[zone.Name] = cloneZone(zone)
	}

	return &InMemoryZoneRepository{zones: zones}
}

func (r *InMemoryZoneRepository) ListZones(_ context.Context) ([]Zone, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Zone, 0, len(r.zones))
	for _, zone := range r.zones {
		result = append(result, cloneZone(zone))
	}

	slices.SortFunc(result, func(a, b Zone) int {
		return strings.Compare(a.Name, b.Name)
	})

	return result, nil
}

func (r *InMemoryZoneRepository) GetZone(_ context.Context, zoneName string) (Zone, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	zone, ok := r.zones[zoneName]
	if !ok {
		return Zone{}, ErrZoneNotFound
	}

	return cloneZone(zone), nil
}

func (r *InMemoryZoneRepository) CreateZone(_ context.Context, zone Zone) error {
	if err := validateZone(zone); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.zones[zone.Name]; exists {
		return ErrZoneExists
	}

	if len(zone.Records) == 0 {
		zone.Records = defaultRecords(zone.Name)
	}

	r.zones[zone.Name] = cloneZone(zone)
	return nil
}

func (r *InMemoryZoneRepository) DeleteZone(_ context.Context, zoneName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.zones[zoneName]; !exists {
		return ErrZoneNotFound
	}

	delete(r.zones, zoneName)
	return nil
}

func (r *InMemoryZoneRepository) ApplyZone(_ context.Context, zone Zone) error {
	if err := validateZone(zone); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.zones[zone.Name]; !exists {
		return ErrZoneNotFound
	}

	r.zones[zone.Name] = cloneZone(zone)
	return nil
}
