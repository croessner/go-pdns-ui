package domain

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type TemplateDBConfig struct {
	DSN                 string
	MaxOpenConns        int
	MaxIdleConns        int
	ConnMaxLifetimeSecs int
}

// PostgresZoneTemplateService persists reusable zone templates in PostgreSQL.
// Template records deliberately have their own identity so multiple members of
// the same RRset survive storage and instantiation.
type PostgresZoneTemplateService struct {
	db     *sql.DB
	logger *slog.Logger
}

func NewPostgresZoneTemplateService(
	ctx context.Context,
	cfg TemplateDBConfig,
	seed []ZoneTemplate,
	logger *slog.Logger,
) (*PostgresZoneTemplateService, error) {
	dsn := strings.TrimSpace(cfg.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("template database dsn required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "zone_templates")

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open template database: %w", err)
	}
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetimeSecs > 0 {
		db.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeSecs) * time.Second)
	}

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping template database: %w", err)
	}

	service := &PostgresZoneTemplateService{db: db, logger: logger}
	if err := service.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	seeded, err := service.seed(ctx, seed)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	logger.Info("template_service_initialized", "backend", "postgres", "seeded_template_count", seeded)
	return service, nil
}

func (s *PostgresZoneTemplateService) Close() error {
	return s.db.Close()
}

func (s *PostgresZoneTemplateService) ListTemplates(ctx context.Context) ([]ZoneTemplate, error) {
	return s.queryTemplates(ctx, "")
}

func (s *PostgresZoneTemplateService) GetTemplate(ctx context.Context, name string) (ZoneTemplate, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return ZoneTemplate{}, ErrTemplateNotFound
	}

	templates, err := s.queryTemplates(ctx, name)
	if err != nil {
		return ZoneTemplate{}, err
	}
	if len(templates) == 0 {
		return ZoneTemplate{}, ErrTemplateNotFound
	}
	return templates[0], nil
}

func (s *PostgresZoneTemplateService) CreateTemplate(ctx context.Context, template ZoneTemplate) error {
	normalized, err := normalizeTemplate(template)
	if err != nil {
		return err
	}
	if len(normalized.Records) == 0 {
		normalized.Records = defaultTemplateRecords(normalized.Kind)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin template create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO zone_templates (name, kind, dnssec_enabled) VALUES ($1, $2, $3)`,
		normalized.Name,
		normalized.Kind,
		normalized.DNSSECEnabled,
	); err != nil {
		if isUniqueViolation(err) {
			return ErrTemplateExists
		}
		return fmt.Errorf("insert zone template: %w", err)
	}
	if err = insertTemplateRecords(ctx, tx, normalized); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit template create: %w", err)
	}
	return nil
}

func (s *PostgresZoneTemplateService) DeleteTemplate(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return ErrTemplateNotFound
	}

	result, err := s.db.ExecContext(ctx, `DELETE FROM zone_templates WHERE name = $1`, name)
	if err != nil {
		return fmt.Errorf("delete zone template: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read deleted template count: %w", err)
	}
	if deleted == 0 {
		return ErrTemplateNotFound
	}
	return nil
}

func (s *PostgresZoneTemplateService) SaveTemplateRecord(
	ctx context.Context,
	templateName, oldName, oldType, oldContent string,
	record Record,
) error {
	templateName = strings.TrimSpace(templateName)
	if templateName == "" {
		return ErrTemplateNotFound
	}

	normalized, err := normalizeRecord(record)
	if err != nil {
		return err
	}
	oldName = strings.TrimSpace(oldName)
	oldType = strings.ToUpper(strings.TrimSpace(oldType))
	oldContent = strings.TrimSpace(oldContent)
	if (oldName == "") != (oldType == "") || (oldName == "") != (oldContent == "") {
		return ErrInvalidRec
	}
	if oldName != "" && oldType == "SOA" && (normalized.Name != oldName || normalized.Type != "SOA") {
		return ErrInvalidRec
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin template record save: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	exists, err := lockTemplate(ctx, tx, templateName)
	if err != nil {
		return err
	}
	if !exists {
		return ErrTemplateNotFound
	}

	var oldID int64
	if oldName != "" {
		if err = tx.QueryRowContext(
			ctx,
			`SELECT id FROM zone_template_records
			 WHERE template_name = $1 AND name = $2 AND type = $3 AND content = $4
			 ORDER BY id LIMIT 1 FOR UPDATE`,
			templateName,
			oldName,
			oldType,
			oldContent,
		).Scan(&oldID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrInvalidRec
			}
			return fmt.Errorf("lock template record: %w", err)
		}
	}

	rows, err := tx.QueryContext(
		ctx,
		`SELECT id, ttl, content FROM zone_template_records
		 WHERE template_name = $1 AND name = $2 AND type = $3 FOR UPDATE`,
		templateName,
		normalized.Name,
		normalized.Type,
	)
	if err != nil {
		return fmt.Errorf("lock target template rrset: %w", err)
	}
	for rows.Next() {
		var (
			id      int64
			ttl     int64
			content string
		)
		if err = rows.Scan(&id, &ttl, &content); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan target template rrset: %w", err)
		}
		if id == oldID {
			continue
		}
		if ttl != int64(normalized.TTL) || content == normalized.Content {
			_ = rows.Close()
			return ErrInvalidRec
		}
	}
	if err = rows.Close(); err != nil {
		return fmt.Errorf("close target template rrset: %w", err)
	}
	if err = rows.Err(); err != nil {
		return fmt.Errorf("iterate target template rrset: %w", err)
	}

	if oldID != 0 {
		if _, err = tx.ExecContext(
			ctx,
			`UPDATE zone_template_records
			 SET name = $1, type = $2, ttl = $3, content = $4, disabled = $5
			 WHERE id = $6 AND template_name = $7`,
			normalized.Name,
			normalized.Type,
			normalized.TTL,
			normalized.Content,
			normalized.Disabled,
			oldID,
			templateName,
		); err != nil {
			if isUniqueViolation(err) {
				return ErrInvalidRec
			}
			return fmt.Errorf("update template record: %w", err)
		}
	} else {
		if _, err = tx.ExecContext(
			ctx,
			`INSERT INTO zone_template_records (template_name, name, type, ttl, content, disabled)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			templateName,
			normalized.Name,
			normalized.Type,
			normalized.TTL,
			normalized.Content,
			normalized.Disabled,
		); err != nil {
			if isUniqueViolation(err) {
				return ErrInvalidRec
			}
			return fmt.Errorf("insert template record: %w", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit template record save: %w", err)
	}
	return nil
}

func (s *PostgresZoneTemplateService) DeleteTemplateRecord(
	ctx context.Context,
	templateName, recordName, recordType, recordContent string,
) error {
	templateName = strings.TrimSpace(templateName)
	if templateName == "" {
		return ErrTemplateNotFound
	}
	recordName = strings.TrimSpace(recordName)
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	recordContent = strings.TrimSpace(recordContent)
	if recordName == "" || recordType == "" || recordContent == "" || recordType == "SOA" {
		return ErrInvalidRec
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin template record delete: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	exists, err := lockTemplate(ctx, tx, templateName)
	if err != nil {
		return err
	}
	if !exists {
		return ErrTemplateNotFound
	}
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM zone_template_records
		 WHERE id = (
			 SELECT id FROM zone_template_records
			 WHERE template_name = $1 AND name = $2 AND type = $3 AND content = $4
			 ORDER BY id LIMIT 1
		 )`,
		templateName,
		recordName,
		recordType,
		recordContent,
	)
	if err != nil {
		return fmt.Errorf("delete template record: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read deleted template record count: %w", err)
	}
	if deleted == 0 {
		return ErrInvalidRec
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit template record delete: %w", err)
	}
	return nil
}

func (s *PostgresZoneTemplateService) queryTemplates(ctx context.Context, name string) ([]ZoneTemplate, error) {
	query := `SELECT t.name, t.kind, t.dnssec_enabled,
	                r.name, r.type, r.ttl, r.content, r.disabled
	         FROM zone_templates t
	         LEFT JOIN zone_template_records r ON r.template_name = t.name`
	args := []any{}
	if name != "" {
		query += ` WHERE t.name = $1`
		args = append(args, name)
	}
	query += ` ORDER BY t.name, r.name, r.type, r.content, r.id`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query zone templates: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			s.logger.Warn("template_rows_close_failed", "error", closeErr)
		}
	}()

	result := make([]ZoneTemplate, 0)
	byName := make(map[string]int)
	for rows.Next() {
		var (
			templateName string
			kind         string
			dnssec       bool
			recordName   sql.NullString
			recordType   sql.NullString
			ttl          sql.NullInt64
			content      sql.NullString
			disabled     sql.NullBool
		)
		if err := rows.Scan(
			&templateName,
			&kind,
			&dnssec,
			&recordName,
			&recordType,
			&ttl,
			&content,
			&disabled,
		); err != nil {
			return nil, fmt.Errorf("scan zone template: %w", err)
		}

		index, ok := byName[templateName]
		if !ok {
			index = len(result)
			byName[templateName] = index
			result = append(result, ZoneTemplate{
				Name:          templateName,
				Kind:          ZoneKind(kind),
				DNSSECEnabled: dnssec,
			})
		}
		if !recordName.Valid {
			continue
		}
		if !recordType.Valid || !ttl.Valid || !content.Valid || ttl.Int64 < 1 || ttl.Int64 > int64(^uint32(0)) {
			return nil, fmt.Errorf("invalid persisted template record for %q", templateName)
		}
		result[index].Records = append(result[index].Records, Record{
			Name:     recordName.String,
			Type:     recordType.String,
			TTL:      uint32(ttl.Int64),
			Content:  content.String,
			Disabled: disabled.Valid && disabled.Bool,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate zone templates: %w", err)
	}
	for i := range result {
		normalized, err := normalizeTemplate(result[i])
		if err != nil {
			s.logger.Error("invalid_persisted_template", "template_name", result[i].Name, "error", err)
			return nil, fmt.Errorf("%w: invalid persisted zone template", ErrBackend)
		}
		if normalized.Name != result[i].Name ||
			normalized.Kind != result[i].Kind ||
			normalized.DNSSECEnabled != result[i].DNSSECEnabled ||
			!slices.Equal(normalized.Records, result[i].Records) {
			s.logger.Error("noncanonical_persisted_template", "template_name", result[i].Name)
			return nil, fmt.Errorf("%w: noncanonical persisted zone template", ErrBackend)
		}
		result[i] = normalized
	}
	return result, nil
}

func (s *PostgresZoneTemplateService) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin template schema migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(7145036819254521)`); err != nil {
		return fmt.Errorf("lock template schema migration: %w", err)
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS zone_templates (
			name TEXT PRIMARY KEY,
			kind TEXT NOT NULL CHECK (kind IN ('forward', 'reverse-v4', 'reverse-v6')),
			dnssec_enabled BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS zone_template_records (
			id BIGSERIAL PRIMARY KEY,
			template_name TEXT NOT NULL REFERENCES zone_templates(name) ON DELETE CASCADE,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			ttl BIGINT NOT NULL CHECK (ttl BETWEEN 1 AND 4294967295),
			content TEXT NOT NULL,
			disabled BOOLEAN NOT NULL DEFAULT FALSE
		)`,
		`CREATE INDEX IF NOT EXISTS zone_template_records_template_idx
		 ON zone_template_records(template_name, name, type)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS zone_template_records_member_idx
		 ON zone_template_records(template_name, name, type, content)`,
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate template schema: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit template schema migration: %w", err)
	}
	return nil
}

func (s *PostgresZoneTemplateService) seed(ctx context.Context, templates []ZoneTemplate) (int, error) {
	seeded := 0
	for _, template := range templates {
		normalized, err := normalizeTemplate(template)
		if err != nil {
			return seeded, fmt.Errorf("normalize seed template %q: %w", template.Name, err)
		}
		if len(normalized.Records) == 0 {
			normalized.Records = defaultTemplateRecords(normalized.Kind)
		}

		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return seeded, fmt.Errorf("begin template seed: %w", err)
		}
		result, err := tx.ExecContext(
			ctx,
			`INSERT INTO zone_templates (name, kind, dnssec_enabled)
			 VALUES ($1, $2, $3) ON CONFLICT (name) DO NOTHING`,
			normalized.Name,
			normalized.Kind,
			normalized.DNSSECEnabled,
		)
		if err != nil {
			_ = tx.Rollback()
			return seeded, fmt.Errorf("seed zone template: %w", err)
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			_ = tx.Rollback()
			return seeded, fmt.Errorf("read seeded template count: %w", err)
		}
		if inserted > 0 {
			if err = insertTemplateRecords(ctx, tx, normalized); err != nil {
				_ = tx.Rollback()
				return seeded, err
			}
			seeded++
		}
		if err = tx.Commit(); err != nil {
			return seeded, fmt.Errorf("commit template seed: %w", err)
		}
	}
	return seeded, nil
}

func insertTemplateRecords(ctx context.Context, tx *sql.Tx, template ZoneTemplate) error {
	for _, record := range template.Records {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO zone_template_records (template_name, name, type, ttl, content, disabled)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			template.Name,
			record.Name,
			record.Type,
			record.TTL,
			record.Content,
			record.Disabled,
		); err != nil {
			return fmt.Errorf("insert template records: %w", err)
		}
	}
	return nil
}

func lockTemplate(ctx context.Context, tx *sql.Tx, name string) (bool, error) {
	var marker int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM zone_templates WHERE name = $1 FOR UPDATE`, name).Scan(&marker); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("lock zone template: %w", err)
	}
	return true, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
