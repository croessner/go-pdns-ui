package domain

import (
	"context"
	"errors"
)

var (
	ErrZoneExists   = errors.New("zone already exists")
	ErrZoneNotFound = errors.New("zone not found")
	ErrInvalidZone  = errors.New("invalid zone")
	ErrInvalidRec   = errors.New("invalid record")
	ErrBackend      = errors.New("backend error")
)

type ZoneRepository interface {
	ListZones(ctx context.Context) ([]Zone, error)
	GetZone(ctx context.Context, zoneName string) (Zone, error)
	CreateZone(ctx context.Context, zone Zone) error
	DeleteZone(ctx context.Context, zoneName string) error
	ApplyZone(ctx context.Context, zone Zone) error
}
