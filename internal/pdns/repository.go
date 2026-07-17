package pdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/croessner/go-pdns-ui/internal/domain"
)

type Repository struct {
	client   *Client
	serverID string
	logger   *slog.Logger
	mu       sync.RWMutex
}

func NewRepository(client *Client, serverID string, logger *slog.Logger) *Repository {
	if logger == nil {
		logger = slog.Default()
	}

	return &Repository{
		client:   client,
		serverID: strings.TrimSpace(serverID),
		logger:   logger,
	}
}

func (r *Repository) ListZones(ctx context.Context) ([]domain.Zone, error) {
	var zones []pdnsZone
	path := r.zonesPath()
	if err := r.client.get(ctx, path, &zones); err != nil {
		if isStatusNotFound(err) {
			fallbackServerID, resolveErr := r.discoverServerID(ctx)
			if resolveErr == nil && fallbackServerID != "" && fallbackServerID != r.getServerID() {
				r.logger.Info("pdns_server_id_discovered", "old_server_id", r.getServerID(), "new_server_id", fallbackServerID)
				r.setServerID(fallbackServerID)
				path = r.zonesPath()
				if retryErr := r.client.get(ctx, path, &zones); retryErr != nil {
					return nil, mapRepositoryError(retryErr)
				}
			} else {
				attrs := []any{"server_id", r.getServerID(), "error", err}
				if resolveErr != nil {
					attrs = append(attrs, "discover_error", resolveErr)
				}
				if fallbackServerID != "" {
					attrs = append(attrs, "discovered_server_id", fallbackServerID)
				}
				r.logger.Warn("pdns_list_zones_server_not_found", attrs...)
				return nil, mapRepositoryError(err)
			}
		} else {
			return nil, mapRepositoryError(err)
		}
	}

	result := make([]domain.Zone, 0, len(zones))
	for _, zone := range zones {
		result = append(result, domain.Zone{
			Name:          trimFQDN(zone.Name),
			Kind:          detectZoneKind(zone.Name),
			DNSSECEnabled: zone.DNSSEC,
		})
	}

	slices.SortFunc(result, func(a, b domain.Zone) int {
		return strings.Compare(a.Name, b.Name)
	})

	r.logger.Debug("pdns_list_zones_succeeded", "zone_count", len(result), "server_id", r.getServerID())
	return result, nil
}

func (r *Repository) GetZone(ctx context.Context, zoneName string) (domain.Zone, error) {
	zoneName = strings.TrimSpace(zoneName)
	if zoneName == "" {
		return domain.Zone{}, domain.ErrZoneNotFound
	}

	var zone pdnsZone
	if err := r.client.get(ctx, r.zonePath(zoneName), &zone); err != nil {
		return domain.Zone{}, mapRepositoryError(err)
	}

	return zoneFromPDNS(zone), nil
}

func (r *Repository) CreateZone(ctx context.Context, zone domain.Zone) error {
	if err := validateCreateZone(zone); err != nil {
		return err
	}

	payload := pdnsCreateZoneRequest{
		Name:        ensureFQDN(zone.Name),
		Kind:        "Native",
		DNSSEC:      false,
		Nameservers: zoneNameServers(zone),
	}

	if err := r.client.post(ctx, r.zonesPath(), payload, nil); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusConflict {
			return domain.ErrZoneExists
		}
		return mapRepositoryError(err)
	}

	r.logger.Info("pdns_zone_created", "zone_name", zone.Name, "dnssec_enabled", false, "dnssec_requested", zone.DNSSECEnabled)

	if len(zone.Records) == 0 && !zone.DNSSECEnabled {
		return nil
	}

	return r.ApplyZone(ctx, zone)
}

func (r *Repository) DeleteZone(ctx context.Context, zoneName string) error {
	zoneName = strings.TrimSpace(zoneName)
	if zoneName == "" {
		return domain.ErrZoneNotFound
	}

	if err := r.client.delete(ctx, r.zonePath(zoneName)); err != nil {
		return mapRepositoryError(err)
	}

	r.logger.Info("pdns_zone_deleted", "zone_name", zoneName)
	return nil
}

func (r *Repository) ApplyZone(ctx context.Context, desired domain.Zone) error {
	if err := validateCreateZone(desired); err != nil {
		return err
	}

	current, err := r.GetZone(ctx, desired.Name)
	if err != nil {
		return err
	}

	rrsetChanges := buildRRSetDiff(current, desired)
	if len(rrsetChanges) > 0 {
		payload := pdnsPatchZoneRequest{RRSets: rrsetChanges}
		if err := r.client.patch(ctx, r.zonePath(desired.Name), payload, nil); err != nil {
			return mapRepositoryError(err)
		}
		r.logger.Info("pdns_zone_rrsets_applied", "zone_name", desired.Name, "rrset_change_count", len(rrsetChanges))
	}

	if current.DNSSECEnabled != desired.DNSSECEnabled {
		if desired.DNSSECEnabled {
			return r.enableDNSSECWithSplitKeys(ctx, desired.Name)
		}

		payload := pdnsUpdateZoneRequest{
			Name:   ensureFQDN(desired.Name),
			Kind:   "Native",
			DNSSEC: false,
		}
		if err := r.client.put(ctx, r.zonePath(desired.Name), payload, nil); err != nil {
			return mapRepositoryError(err)
		}
		r.logger.Info("pdns_zone_dnssec_updated", "zone_name", desired.Name, "dnssec_enabled", desired.DNSSECEnabled)
	}

	return nil
}

func (r *Repository) enableDNSSECWithSplitKeys(ctx context.Context, zoneName string) error {
	ksk, err := r.createCryptokey(ctx, zoneName, "ksk")
	if err != nil {
		return err
	}

	zsk, err := r.createCryptokey(ctx, zoneName, "zsk")
	if err != nil {
		r.deleteCryptokeysBestEffort(ctx, zoneName, ksk.ID)
		return err
	}

	if err := r.setCryptokeyState(ctx, zoneName, zsk.ID, true); err != nil {
		r.deleteCryptokeysBestEffort(ctx, zoneName, zsk.ID, ksk.ID)
		return err
	}

	if err := r.setCryptokeyState(ctx, zoneName, ksk.ID, true); err != nil {
		r.deleteCryptokeysBestEffort(ctx, zoneName, zsk.ID, ksk.ID)
		return err
	}
	if err := r.verifySplitCryptokeys(ctx, zoneName, ksk.ID, zsk.ID); err != nil {
		r.deleteCryptokeysBestEffort(ctx, zoneName, zsk.ID, ksk.ID)
		return err
	}

	r.logger.Info("pdns_zone_dnssec_split_keys_created", "zone_name", zoneName, "key_types", "ksk,zsk")
	return nil
}

func (r *Repository) createCryptokey(ctx context.Context, zoneName, keyType string) (pdnsCryptokey, error) {
	payload := pdnsCreateCryptokeyRequest{
		KeyType:   keyType,
		Active:    false,
		Published: true,
	}

	var key pdnsCryptokey
	if err := r.client.post(ctx, r.cryptokeysPath(zoneName), payload, &key); err != nil {
		return pdnsCryptokey{}, fmt.Errorf("create DNSSEC %s: %w", strings.ToUpper(keyType), mapRepositoryError(err))
	}
	if key.ID <= 0 {
		return pdnsCryptokey{}, fmt.Errorf("%w: PowerDNS returned an invalid DNSSEC %s id", domain.ErrBackend, strings.ToUpper(keyType))
	}

	return key, nil
}

func (r *Repository) setCryptokeyState(ctx context.Context, zoneName string, keyID int, active bool) error {
	payload := pdnsUpdateCryptokeyRequest{Active: active, Published: true}
	path := r.cryptokeyPath(zoneName, keyID)
	if err := r.client.put(ctx, path, payload, nil); err != nil {
		return fmt.Errorf("set DNSSEC key state: %w", mapRepositoryError(err))
	}
	return nil
}

func (r *Repository) verifySplitCryptokeys(ctx context.Context, zoneName string, kskID, zskID int) error {
	var keys []pdnsCryptokey
	if err := r.client.get(ctx, r.cryptokeysPath(zoneName), &keys); err != nil {
		return fmt.Errorf("verify DNSSEC key roles: %w", mapRepositoryError(err))
	}

	expected := map[int]string{kskID: "ksk", zskID: "zsk"}
	for _, key := range keys {
		keyType, ok := expected[key.ID]
		if !ok {
			continue
		}
		if !strings.EqualFold(key.KeyType, keyType) || !key.Active || !key.Published {
			return fmt.Errorf("%w: PowerDNS did not activate the generated DNSSEC %s as a separate key", domain.ErrBackend, strings.ToUpper(keyType))
		}
		delete(expected, key.ID)
	}
	if len(expected) != 0 {
		return fmt.Errorf("%w: PowerDNS did not return all generated DNSSEC keys", domain.ErrBackend)
	}

	return nil
}

func (r *Repository) deleteCryptokeysBestEffort(ctx context.Context, zoneName string, keyIDs ...int) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	for _, keyID := range keyIDs {
		if keyID <= 0 {
			continue
		}
		if err := r.setCryptokeyState(cleanupCtx, zoneName, keyID, false); err != nil {
			r.logger.Warn("pdns_zone_dnssec_key_deactivation_failed", "zone_name", zoneName, "error", err)
		}
	}
	for _, keyID := range keyIDs {
		if keyID <= 0 {
			continue
		}
		if err := r.client.delete(cleanupCtx, r.cryptokeyPath(zoneName, keyID)); err != nil {
			r.logger.Warn("pdns_zone_dnssec_key_cleanup_failed", "zone_name", zoneName, "error", err)
		}
	}
}

type pdnsZone struct {
	Name   string      `json:"name"`
	Kind   string      `json:"kind"`
	DNSSEC bool        `json:"dnssec"`
	RRSets []pdnsRRSet `json:"rrsets"`
}

type pdnsRRSet struct {
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	TTL        uint32       `json:"ttl,omitempty"`
	ChangeType string       `json:"changetype,omitempty"`
	Records    []pdnsRecord `json:"records,omitempty"`
}

type pdnsRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type pdnsCreateZoneRequest struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	DNSSEC      bool     `json:"dnssec"`
	Nameservers []string `json:"nameservers,omitempty"`
}

type pdnsPatchZoneRequest struct {
	RRSets []pdnsRRSet `json:"rrsets"`
}

type pdnsUpdateZoneRequest struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	DNSSEC bool   `json:"dnssec"`
}

type pdnsCryptokey struct {
	ID        int    `json:"id"`
	KeyType   string `json:"keytype"`
	Active    bool   `json:"active"`
	Published bool   `json:"published"`
}

type pdnsCreateCryptokeyRequest struct {
	KeyType   string `json:"keytype"`
	Active    bool   `json:"active"`
	Published bool   `json:"published"`
}

type pdnsUpdateCryptokeyRequest struct {
	Active    bool `json:"active"`
	Published bool `json:"published"`
}

type pdnsServer struct {
	ID string `json:"id"`
}

func (r *Repository) zonesPath() string {
	return "/servers/" + url.PathEscape(r.getServerID()) + "/zones"
}

func (r *Repository) zonePath(zoneName string) string {
	return "/servers/" + url.PathEscape(r.getServerID()) + "/zones/" + url.PathEscape(ensureFQDN(zoneName))
}

func (r *Repository) cryptokeysPath(zoneName string) string {
	return r.zonePath(zoneName) + "/cryptokeys"
}

func (r *Repository) cryptokeyPath(zoneName string, keyID int) string {
	return r.cryptokeysPath(zoneName) + "/" + strconv.Itoa(keyID)
}

func validateCreateZone(zone domain.Zone) error {
	if strings.TrimSpace(zone.Name) == "" {
		return domain.ErrInvalidZone
	}

	if !zone.Kind.Valid() {
		return domain.ErrInvalidZone
	}

	return nil
}

func zoneFromPDNS(zone pdnsZone) domain.Zone {
	result := domain.Zone{
		Name:          trimFQDN(zone.Name),
		Kind:          detectZoneKind(zone.Name),
		DNSSECEnabled: zone.DNSSEC,
		Records:       make([]domain.Record, 0, len(zone.RRSets)),
	}

	zoneName := trimFQDN(zone.Name)

	for _, rrset := range zone.RRSets {
		recordName := trimZoneSuffix(rrset.Name, zoneName)
		if len(rrset.Records) == 0 {
			continue
		}

		for _, rr := range rrset.Records {
			result.Records = append(result.Records, domain.Record{
				Name:     recordName,
				Type:     strings.ToUpper(strings.TrimSpace(rrset.Type)),
				TTL:      rrset.TTL,
				Content:  strings.TrimSpace(rr.Content),
				Disabled: rr.Disabled,
			})
		}
	}

	slices.SortFunc(result.Records, func(a, b domain.Record) int {
		if a.Name == b.Name {
			if a.Type == b.Type {
				return strings.Compare(a.Content, b.Content)
			}
			return strings.Compare(a.Type, b.Type)
		}
		return strings.Compare(a.Name, b.Name)
	})

	return result
}

func buildRRSetDiff(current, desired domain.Zone) []pdnsRRSet {
	currentMap := groupRecordsByKey(current.Name, current.Records)
	desiredMap := groupRecordsByKey(desired.Name, desired.Records)

	keys := make([]string, 0, len(currentMap)+len(desiredMap))
	for key := range currentMap {
		keys = append(keys, key)
	}
	for key := range desiredMap {
		if _, exists := currentMap[key]; !exists {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)

	changes := make([]pdnsRRSet, 0, len(keys))
	for _, key := range keys {
		currentRR, hasCurrent := currentMap[key]
		desiredRR, hasDesired := desiredMap[key]

		if hasCurrent && hasDesired && rrsetEqual(currentRR, desiredRR) {
			continue
		}

		if hasDesired {
			desiredRR.ChangeType = "REPLACE"
			changes = append(changes, desiredRR)
			continue
		}

		if hasCurrent {
			changes = append(changes, pdnsRRSet{
				Name:       currentRR.Name,
				Type:       currentRR.Type,
				ChangeType: "DELETE",
				Records:    []pdnsRecord{},
			})
		}
	}

	return changes
}

func groupRecordsByKey(zoneName string, records []domain.Record) map[string]pdnsRRSet {
	result := map[string]pdnsRRSet{}

	for _, record := range records {
		name := toFQDNName(zoneName, record.Name)
		recordType := strings.ToUpper(strings.TrimSpace(record.Type))
		if name == "" || recordType == "" {
			continue
		}

		key := name + "|" + recordType
		entry := result[key]
		entry.Name = name
		entry.Type = recordType
		if record.TTL > 0 {
			entry.TTL = record.TTL
		} else if entry.TTL == 0 {
			entry.TTL = 3600
		}
		entry.Records = append(entry.Records, pdnsRecord{
			Content:  strings.TrimSpace(record.Content),
			Disabled: record.Disabled,
		})

		result[key] = entry
	}

	for key, rrset := range result {
		slices.SortFunc(rrset.Records, func(a, b pdnsRecord) int {
			if a.Content == b.Content {
				if a.Disabled == b.Disabled {
					return 0
				}
				if a.Disabled {
					return 1
				}
				return -1
			}
			return strings.Compare(a.Content, b.Content)
		})
		result[key] = rrset
	}

	return result
}

func rrsetEqual(a, b pdnsRRSet) bool {
	if a.Name != b.Name || a.Type != b.Type || a.TTL != b.TTL {
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

func mapRepositoryError(err error) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err
	}

	switch apiErr.Status {
	case http.StatusNotFound:
		if isZoneResourcePath(apiErr.Path) {
			return domain.ErrZoneNotFound
		}
		return fmt.Errorf("%w: %w", domain.ErrBackend, err)
	case http.StatusConflict:
		return domain.ErrZoneExists
	case http.StatusBadRequest:
		return domain.ErrInvalidZone
	default:
		return fmt.Errorf("%w: %w", domain.ErrBackend, err)
	}
}

func detectZoneKind(zoneName string) domain.ZoneKind {
	name := trimFQDN(zoneName)
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		return domain.ZoneReverseV4
	case strings.HasSuffix(name, ".ip6.arpa"):
		return domain.ZoneReverseV6
	default:
		return domain.ZoneForward
	}
}

func trimZoneSuffix(recordName, zoneName string) string {
	recordName = trimFQDN(recordName)
	zoneName = trimFQDN(zoneName)

	if strings.EqualFold(recordName, zoneName) {
		return "@"
	}

	suffix := "." + zoneName
	if strings.HasSuffix(strings.ToLower(recordName), strings.ToLower(suffix)) {
		return strings.TrimSuffix(recordName, suffix)
	}

	return recordName
}

func toFQDNName(zoneName, recordName string) string {
	zoneName = trimFQDN(zoneName)
	recordName = strings.TrimSpace(recordName)

	switch {
	case recordName == "", recordName == "@":
		return ensureFQDN(zoneName)
	case strings.HasSuffix(recordName, "."):
		return recordName
	case strings.Contains(recordName, ".") && strings.HasSuffix(recordName, zoneName):
		return ensureFQDN(recordName)
	default:
		return ensureFQDN(recordName + "." + zoneName)
	}
}

func zoneNameServers(zone domain.Zone) []string {
	nameservers := make([]string, 0, 2)
	for _, record := range zone.Records {
		if strings.EqualFold(record.Type, "NS") {
			content := strings.TrimSpace(record.Content)
			if content != "" {
				nameservers = append(nameservers, ensureFQDN(content))
			}
		}
	}

	if len(nameservers) == 0 {
		nameservers = append(nameservers, ensureFQDN("ns1."+zone.Name))
	}

	return nameservers
}

func trimFQDN(name string) string {
	return strings.TrimSuffix(strings.TrimSpace(name), ".")
}

func ensureFQDN(name string) string {
	name = trimFQDN(name)
	if name == "" {
		return ""
	}
	return name + "."
}

func (r *Repository) discoverServerID(ctx context.Context) (string, error) {
	var servers []pdnsServer
	if err := r.client.get(ctx, "/servers", &servers); err != nil {
		r.logger.Error("pdns_discover_server_id_failed", "error", err)
		return "", err
	}

	for _, server := range servers {
		if strings.EqualFold(strings.TrimSpace(server.ID), "localhost") {
			serverID := strings.TrimSpace(server.ID)
			r.logger.Debug("pdns_discover_server_id_result", "server_id", serverID)
			return serverID, nil
		}
	}

	for _, server := range servers {
		id := strings.TrimSpace(server.ID)
		if id != "" {
			r.logger.Debug("pdns_discover_server_id_result", "server_id", id)
			return id, nil
		}
	}

	r.logger.Warn("pdns_discover_server_id_empty_result")
	return "", nil
}

func (r *Repository) getServerID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.serverID
}

func (r *Repository) setServerID(serverID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.serverID = strings.TrimSpace(serverID)
}

func isStatusNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}

func isZoneResourcePath(path string) bool {
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	// /servers/{id}/zones/{zone}
	return len(parts) >= 4 && parts[0] == "servers" && parts[2] == "zones"
}
