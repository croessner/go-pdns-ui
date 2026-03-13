package audit

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// DBConfig holds the connection parameters for the audit database.
type DBConfig struct {
	DSN                 string
	MaxOpenConns        int
	MaxIdleConns        int
	ConnMaxLifetimeSecs int
}

// PostgresService persists audit entries in a PostgreSQL table.
type PostgresService struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewPostgresService opens a connection pool, runs migrations and returns a
// ready-to-use PostgresService. It reuses an existing *sql.DB when provided
// via WithDB, otherwise it opens a new connection from cfg.DSN.
func NewPostgresService(ctx context.Context, cfg DBConfig, logger *slog.Logger) (*PostgresService, error) {
	dsn := strings.TrimSpace(cfg.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("audit database dsn required")
	}

	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "audit")

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open audit database: %w", err)
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
		db.Close()
		return nil, fmt.Errorf("ping audit database: %w", err)
	}

	svc := &PostgresService{db: db, logger: logger}
	if err := svc.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}

	logger.Info("audit_log_initialized")
	return svc, nil
}

// NewPostgresServiceWithDB wraps an existing *sql.DB (shared connection pool).
func NewPostgresServiceWithDB(ctx context.Context, db *sql.DB, logger *slog.Logger) (*PostgresService, error) {
	if db == nil {
		return nil, fmt.Errorf("audit: nil database handle")
	}
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "audit")

	svc := &PostgresService{db: db, logger: logger}
	if err := svc.migrate(ctx); err != nil {
		return nil, err
	}

	logger.Info("audit_log_initialized", "shared_pool", true)
	return svc, nil
}

func (s *PostgresService) Enabled() bool { return true }

func (s *PostgresService) Close() error { return s.db.Close() }

func (s *PostgresService) Log(ctx context.Context, entry Entry) error {
	id, err := randomID()
	if err != nil {
		return fmt.Errorf("audit id: %w", err)
	}

	ts := entry.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO audit_log (id, timestamp, action, username, role, auth_source, target, detail)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, ts, entry.Action, entry.User, entry.Role, entry.AuthSource, entry.Target, entry.Detail,
	)
	if err != nil {
		s.logger.Error("audit_log_write_failed", "action", entry.Action, "error", err)
		return fmt.Errorf("insert audit log: %w", err)
	}

	return nil
}

func (s *PostgresService) Search(ctx context.Context, params SearchParams) (SearchResult, error) {
	limit := params.Limit
	if limit <= 0 {
		limit = 25
	}
	page := params.Page
	if page < 1 {
		page = 1
	}

	where, args := s.buildWhere(params)

	// Count total matching rows.
	var total int
	countQuery := "SELECT COUNT(*) FROM audit_log" + where
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return SearchResult{}, fmt.Errorf("count audit log: %w", err)
	}

	totalPages := (total + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	offset := (page - 1) * limit
	dataQuery := `SELECT id, timestamp, action, username, role, auth_source, target, detail
		FROM audit_log` + where + ` ORDER BY timestamp DESC LIMIT $` + fmt.Sprintf("%d", len(args)+1) + ` OFFSET $` + fmt.Sprintf("%d", len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return SearchResult{}, fmt.Errorf("query audit log: %w", err)
	}
	defer rows.Close()

	entries := make([]Entry, 0)
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &e.User, &e.Role, &e.AuthSource, &e.Target, &e.Detail); err != nil {
			return SearchResult{}, fmt.Errorf("scan audit log: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return SearchResult{}, fmt.Errorf("iterate audit log: %w", err)
	}

	return SearchResult{
		Entries:    entries,
		Total:      total,
		Page:       page,
		TotalPages: totalPages,
	}, nil
}

func (s *PostgresService) Actions(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT action FROM audit_log ORDER BY action`)
	if err != nil {
		return nil, fmt.Errorf("list audit actions: %w", err)
	}
	defer rows.Close()

	var actions []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			return nil, fmt.Errorf("scan audit action: %w", err)
		}
		actions = append(actions, action)
	}
	return actions, rows.Err()
}

// buildWhere constructs a WHERE clause and positional args from SearchParams.
func (s *PostgresService) buildWhere(params SearchParams) (string, []any) {
	var conditions []string
	var args []any
	idx := 1

	if q := strings.TrimSpace(params.Query); q != "" {
		like := "%" + q + "%"
		conditions = append(conditions, fmt.Sprintf(
			"(username ILIKE $%d OR target ILIKE $%d OR detail ILIKE $%d OR action ILIKE $%d)",
			idx, idx+1, idx+2, idx+3,
		))
		args = append(args, like, like, like, like)
		idx += 4
	}

	if a := strings.TrimSpace(params.Action); a != "" {
		conditions = append(conditions, fmt.Sprintf("action = $%d", idx))
		args = append(args, a)
		idx++
	}

	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

func (s *PostgresService) migrate(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			action TEXT NOT NULL,
			username TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL DEFAULT '',
			auth_source TEXT NOT NULL DEFAULT '',
			target TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log (action)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_username ON audit_log (username)`,
	}
	for _, q := range queries {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("migrate audit schema: %w", err)
		}
	}
	return nil
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
