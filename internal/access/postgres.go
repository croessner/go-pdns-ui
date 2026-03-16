package access

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/croessner/go-pdns-ui/internal/auth"
	"github.com/croessner/go-pdns-ui/internal/domain"
)

type PostgresService struct {
	db                 *sql.DB
	logger             *slog.Logger
	oidcAutoCreateMode bool
}

func NewPostgresService(ctx context.Context, cfg DBConfig, logger *slog.Logger) (*PostgresService, error) {
	dsn := strings.TrimSpace(cfg.DSN)
	if dsn == "" {
		return nil, fmt.Errorf("database dsn required for authz mode company: %w", ErrInvalidInput)
	}

	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "access")

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open access database: %w", err)
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
		return nil, fmt.Errorf("ping access database: %w", err)
	}

	oidcAutoCreateMode := true
	if cfg.OIDCAutoCreate != nil {
		oidcAutoCreateMode = *cfg.OIDCAutoCreate
	}

	svc := &PostgresService{
		db:                 db,
		logger:             logger,
		oidcAutoCreateMode: oidcAutoCreateMode,
	}
	if err := svc.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}

	logger.Info("access_control_initialized")

	return svc, nil
}

func (s *PostgresService) Enabled() bool {
	return true
}

func (s *PostgresService) Close() error {
	return s.db.Close()
}

func (s *PostgresService) SyncPrincipal(ctx context.Context, user auth.User) (Principal, error) {
	authSource := strings.TrimSpace(user.AuthSource)
	if authSource == "" {
		authSource = "password"
	}

	subject := strings.TrimSpace(user.Subject)
	if subject == "" {
		subject = strings.TrimSpace(user.Username)
	}
	if subject == "" {
		return Principal{}, ErrInvalidInput
	}

	username := strings.TrimSpace(user.Username)
	if username == "" {
		username = subject
	}

	email := strings.TrimSpace(user.Email)
	role := strings.TrimSpace(string(user.Role))
	if role == "" {
		role = string(auth.RoleViewer)
	}

	principal, err := s.getPrincipalByIdentity(ctx, authSource, subject)
	if err == nil {
		_, err = s.db.ExecContext(
			ctx,
			`UPDATE principals SET username = $1, email = $2, role = $3, updated_at = NOW() WHERE id = $4`,
			username,
			email,
			role,
			principal.ID,
		)
		if err != nil {
			return Principal{}, fmt.Errorf("update principal: %w", err)
		}

		return s.getPrincipalByIdentity(ctx, authSource, subject)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Principal{}, err
	}
	if authSource == "oidc" {
		claimed, claimErr := s.claimOIDCPlaceholderPrincipal(ctx, subject, username, email, role)
		if claimErr != nil {
			return Principal{}, claimErr
		}
		if claimed {
			return s.getPrincipalByIdentity(ctx, authSource, subject)
		}
		if !s.oidcAutoCreateMode {
			return Principal{}, ErrPrincipalNotFound
		}
	}

	id, err := randomID()
	if err != nil {
		return Principal{}, fmt.Errorf("create principal id: %w", err)
	}

	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO principals (id, auth_source, subject, username, email, role) VALUES ($1, $2, $3, $4, $5, $6)`,
		id,
		authSource,
		subject,
		username,
		email,
		role,
	)
	if err != nil {
		// If concurrent insert happened, fetch and continue.
		if !isDuplicateKeyError(err) {
			return Principal{}, fmt.Errorf("insert principal: %w", err)
		}
	}

	return s.getPrincipalByIdentity(ctx, authSource, subject)
}

func (s *PostgresService) FilterZones(ctx context.Context, user auth.User, zones []domain.Zone) ([]domain.Zone, error) {
	if user.Role == auth.RoleAdmin {
		result := make([]domain.Zone, len(zones))
		copy(result, zones)
		return result, nil
	}
	if user.Role == auth.RoleAudit {
		return []domain.Zone{}, nil
	}

	principal, err := s.SyncPrincipal(ctx, user)
	if err != nil {
		return nil, err
	}

	zoneNames, err := s.listAllowedZoneNames(ctx, principal.ID)
	if err != nil {
		return nil, err
	}

	allowed := make(map[string]struct{}, len(zoneNames))
	for _, zoneName := range zoneNames {
		allowed[zoneName] = struct{}{}
	}

	result := make([]domain.Zone, 0, len(zones))
	for _, zone := range zones {
		if _, exists := allowed[zone.Name]; exists {
			result = append(result, zone)
		}
	}

	return result, nil
}

func (s *PostgresService) CanAccessZone(ctx context.Context, user auth.User, zoneName string) (bool, error) {
	zoneName = strings.TrimSpace(zoneName)
	if zoneName == "" {
		return false, ErrInvalidInput
	}

	if user.Role == auth.RoleAdmin {
		return true, nil
	}
	if user.Role == auth.RoleAudit {
		return false, nil
	}

	principal, err := s.SyncPrincipal(ctx, user)
	if err != nil {
		return false, err
	}

	var exists int
	err = s.db.QueryRowContext(
		ctx,
		`SELECT 1
		 FROM zone_company_assignments z
		 JOIN company_memberships m ON m.company_id = z.company_id
		 WHERE m.principal_id = $1 AND z.zone_name = $2
		 LIMIT 1`,
		principal.ID,
		zoneName,
	).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check zone access: %w", err)
	}

	return true, nil
}

func (s *PostgresService) AuthenticatePassword(username, password string) (auth.PasswordPrincipal, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return auth.PasswordPrincipal{}, auth.ErrInvalidCredentials
	}

	var principal auth.PasswordPrincipal
	var role string

	err := s.db.QueryRowContext(
		context.Background(),
		`SELECT p.id, p.subject, p.username, p.email, p.role, c.must_change_password
		 FROM principals p
		 JOIN local_credentials c ON c.principal_id = p.id
		 WHERE p.auth_source = 'password'
		   AND p.username = $1
		   AND c.password_hash = crypt($2, c.password_hash)`,
		username,
		password,
	).Scan(
		&principal.PrincipalID,
		&principal.Subject,
		&principal.Username,
		&principal.Email,
		&role,
		&principal.MustChangePassword,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.PasswordPrincipal{}, auth.ErrInvalidCredentials
	}
	if err != nil {
		return auth.PasswordPrincipal{}, fmt.Errorf("lookup password principal: %w", err)
	}

	principal.Role = auth.Role(strings.TrimSpace(role))
	if principal.Role == "" {
		principal.Role = auth.RoleViewer
	}

	return principal, nil
}

func (s *PostgresService) HasPasswordCredentials(username string) (bool, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return false, ErrInvalidInput
	}

	var exists int
	err := s.db.QueryRowContext(
		context.Background(),
		`SELECT 1
		 FROM principals p
		 JOIN local_credentials c ON c.principal_id = p.id
		 WHERE p.auth_source = 'password' AND p.username = $1
		 LIMIT 1`,
		username,
	).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check password credentials existence: %w", err)
	}

	return true, nil
}

func (s *PostgresService) ChangePassword(principalID, currentPassword, newPassword string) error {
	principalID = strings.TrimSpace(principalID)
	if principalID == "" || currentPassword == "" {
		return auth.ErrInvalidCredentials
	}
	if err := validateLocalPassword(newPassword); err != nil {
		return err
	}

	result, err := s.db.ExecContext(
		context.Background(),
		`UPDATE local_credentials
		 SET password_hash = crypt($3, gen_salt('bf')), must_change_password = FALSE, updated_at = NOW()
		 WHERE principal_id = $1
		   AND password_hash = crypt($2, password_hash)`,
		principalID,
		currentPassword,
		newPassword,
	)
	if err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check password update result: %w", err)
	}
	if affected == 0 {
		return auth.ErrInvalidCredentials
	}

	return nil
}

func (s *PostgresService) ListCompanies(ctx context.Context) ([]Company, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, slug, created_at FROM companies ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list companies: %w", err)
	}
	defer rows.Close()

	result := make([]Company, 0)
	for rows.Next() {
		var company Company
		if err := rows.Scan(&company.ID, &company.Name, &company.Slug, &company.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan company: %w", err)
		}
		result = append(result, company)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate companies: %w", err)
	}

	return result, nil
}

func (s *PostgresService) ListPrincipals(ctx context.Context) ([]Principal, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, auth_source, subject, username, email, role, created_at, updated_at
		 FROM principals
		 ORDER BY username, subject`,
	)
	if err != nil {
		return nil, fmt.Errorf("list principals: %w", err)
	}
	defer rows.Close()

	result := make([]Principal, 0)
	for rows.Next() {
		var principal Principal
		var role string
		if err := rows.Scan(
			&principal.ID,
			&principal.AuthSource,
			&principal.Subject,
			&principal.Username,
			&principal.Email,
			&role,
			&principal.CreatedAt,
			&principal.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan principal: %w", err)
		}
		principal.Role = auth.Role(role)
		result = append(result, principal)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate principals: %w", err)
	}

	return result, nil
}

func (s *PostgresService) ListCompanyMemberships(ctx context.Context) ([]CompanyMembership, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT m.company_id, c.name, m.principal_id, p.username, m.created_at
		 FROM company_memberships m
		 JOIN companies c ON c.id = m.company_id
		 JOIN principals p ON p.id = m.principal_id
		 ORDER BY c.name, p.username`,
	)
	if err != nil {
		return nil, fmt.Errorf("list memberships: %w", err)
	}
	defer rows.Close()

	result := make([]CompanyMembership, 0)
	for rows.Next() {
		var membership CompanyMembership
		if err := rows.Scan(
			&membership.CompanyID,
			&membership.CompanyName,
			&membership.PrincipalID,
			&membership.PrincipalUsername,
			&membership.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan membership: %w", err)
		}
		result = append(result, membership)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate memberships: %w", err)
	}

	return result, nil
}

func (s *PostgresService) ListZoneAssignments(ctx context.Context) ([]ZoneAssignment, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT z.zone_name, z.company_id, c.name, z.created_at
		 FROM zone_company_assignments z
		 JOIN companies c ON c.id = z.company_id
		 ORDER BY z.zone_name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list zone assignments: %w", err)
	}
	defer rows.Close()

	result := make([]ZoneAssignment, 0)
	for rows.Next() {
		var assignment ZoneAssignment
		if err := rows.Scan(
			&assignment.ZoneName,
			&assignment.CompanyID,
			&assignment.CompanyName,
			&assignment.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan zone assignment: %w", err)
		}
		result = append(result, assignment)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate zone assignments: %w", err)
	}

	return result, nil
}

func (s *PostgresService) CreatePrincipal(ctx context.Context, authSource, subject, username, email string) (Principal, error) {
	authSource = strings.ToLower(strings.TrimSpace(authSource))
	if authSource == "" {
		authSource = "oidc"
	}
	if authSource != "oidc" {
		return Principal{}, ErrInvalidInput
	}

	subject = strings.TrimSpace(subject)
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	if subject == "" {
		subject = username
	}
	if username == "" {
		username = subject
	}
	if subject == "" {
		return Principal{}, ErrInvalidInput
	}

	id, err := randomID()
	if err != nil {
		return Principal{}, fmt.Errorf("create principal id: %w", err)
	}

	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO principals (id, auth_source, subject, username, email, role)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (auth_source, subject)
		 DO UPDATE SET username = EXCLUDED.username, email = EXCLUDED.email, updated_at = NOW()`,
		id,
		authSource,
		subject,
		username,
		email,
		string(auth.RoleViewer),
	)
	if err != nil {
		return Principal{}, fmt.Errorf("upsert principal: %w", err)
	}

	return s.getPrincipalByIdentity(ctx, authSource, subject)
}

func (s *PostgresService) CreatePasswordPrincipal(ctx context.Context, username, email, password string, mustChangePassword bool) (Principal, error) {
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	password = strings.TrimSpace(password)
	if username == "" {
		return Principal{}, ErrInvalidInput
	}
	if err := validateLocalPassword(password); err != nil {
		return Principal{}, ErrInvalidInput
	}

	subject := "local:" + username
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Principal{}, fmt.Errorf("start create password principal transaction: %w", err)
	}
	defer tx.Rollback()

	insertID, err := randomID()
	if err != nil {
		return Principal{}, fmt.Errorf("create principal id: %w", err)
	}

	var principalID string
	err = tx.QueryRowContext(
		ctx,
		`INSERT INTO principals (id, auth_source, subject, username, email, role)
		 VALUES ($1, 'password', $2, $3, $4, $5)
		 ON CONFLICT (auth_source, subject)
		 DO UPDATE SET username = EXCLUDED.username, email = EXCLUDED.email, updated_at = NOW()
		 RETURNING id`,
		insertID,
		subject,
		username,
		email,
		string(auth.RoleUser),
	).Scan(&principalID)
	if err != nil {
		return Principal{}, fmt.Errorf("upsert password principal: %w", err)
	}

	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO local_credentials (principal_id, password_hash, must_change_password)
		 VALUES ($1, crypt($2, gen_salt('bf')), $3)
		 ON CONFLICT (principal_id)
		 DO UPDATE
		 SET password_hash = crypt($2, gen_salt('bf')), must_change_password = EXCLUDED.must_change_password, updated_at = NOW()`,
		principalID,
		password,
		mustChangePassword,
	)
	if err != nil {
		return Principal{}, fmt.Errorf("upsert password credentials: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Principal{}, fmt.Errorf("commit password principal transaction: %w", err)
	}

	return s.getPrincipalByIdentity(ctx, "password", subject)
}

func (s *PostgresService) UpdatePrincipal(ctx context.Context, principalID, username, email string) error {
	principalID = strings.TrimSpace(principalID)
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	if principalID == "" || username == "" {
		return ErrInvalidInput
	}

	var authSource string
	if err := s.db.QueryRowContext(ctx, `SELECT auth_source FROM principals WHERE id = $1`, principalID).Scan(&authSource); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPrincipalNotFound
		}
		return fmt.Errorf("load principal for update: %w", err)
	}
	if authSource != "password" {
		return ErrInvalidInput
	}

	var duplicate int
	err := s.db.QueryRowContext(
		ctx,
		`SELECT 1
		 FROM principals
		 WHERE auth_source = $1 AND username = $2 AND id <> $3
		 LIMIT 1`,
		authSource,
		username,
		principalID,
	).Scan(&duplicate)
	if err == nil {
		return ErrInvalidInput
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check principal username uniqueness: %w", err)
	}

	result, err := s.db.ExecContext(
		ctx,
		`UPDATE principals
		 SET username = $2, email = $3, updated_at = NOW()
		 WHERE id = $1`,
		principalID,
		username,
		email,
	)
	if err != nil {
		return fmt.Errorf("update principal: %w", err)
	}

	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrPrincipalNotFound
	}

	return nil
}

func (s *PostgresService) ResetPrincipalPassword(ctx context.Context, principalID, password string, mustChangePassword bool) error {
	principalID = strings.TrimSpace(principalID)
	password = strings.TrimSpace(password)
	if principalID == "" {
		return ErrInvalidInput
	}
	if err := validateLocalPassword(password); err != nil {
		return ErrInvalidInput
	}

	var authSource string
	if err := s.db.QueryRowContext(ctx, `SELECT auth_source FROM principals WHERE id = $1`, principalID).Scan(&authSource); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPrincipalNotFound
		}
		return fmt.Errorf("load principal for password reset: %w", err)
	}
	if authSource != "password" {
		return ErrInvalidInput
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO local_credentials (principal_id, password_hash, must_change_password)
		 VALUES ($1, crypt($2, gen_salt('bf')), $3)
		 ON CONFLICT (principal_id)
		 DO UPDATE
		 SET password_hash = crypt($2, gen_salt('bf')), must_change_password = EXCLUDED.must_change_password, updated_at = NOW()`,
		principalID,
		password,
		mustChangePassword,
	)
	if err != nil {
		return fmt.Errorf("reset principal password: %w", err)
	}

	return nil
}

func (s *PostgresService) CreateCompany(ctx context.Context, name string) (Company, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Company{}, ErrInvalidInput
	}

	slug := slugify(name)
	if slug == "" {
		return Company{}, ErrInvalidInput
	}

	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM companies WHERE name = $1 OR slug = $2 LIMIT 1`, name, slug).Scan(&exists)
	if err == nil {
		return Company{}, ErrCompanyExists
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Company{}, fmt.Errorf("check company uniqueness: %w", err)
	}

	id, err := randomID()
	if err != nil {
		return Company{}, fmt.Errorf("create company id: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `INSERT INTO companies (id, name, slug) VALUES ($1, $2, $3)`, id, name, slug)
	if err != nil {
		if isDuplicateKeyError(err) {
			return Company{}, ErrCompanyExists
		}
		return Company{}, fmt.Errorf("insert company: %w", err)
	}

	var company Company
	if err := s.db.QueryRowContext(ctx, `SELECT id, name, slug, created_at FROM companies WHERE id = $1`, id).Scan(
		&company.ID,
		&company.Name,
		&company.Slug,
		&company.CreatedAt,
	); err != nil {
		return Company{}, fmt.Errorf("load created company: %w", err)
	}

	return company, nil
}

func (s *PostgresService) DeletePrincipal(ctx context.Context, principalID string) error {
	principalID = strings.TrimSpace(principalID)
	if principalID == "" {
		return ErrInvalidInput
	}

	var authSource string
	if err := s.db.QueryRowContext(ctx, `SELECT auth_source FROM principals WHERE id = $1`, principalID).Scan(&authSource); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPrincipalNotFound
		}
		return fmt.Errorf("load principal for delete: %w", err)
	}
	if authSource != "password" {
		return ErrInvalidInput
	}

	result, err := s.db.ExecContext(ctx, `DELETE FROM principals WHERE id = $1`, principalID)
	if err != nil {
		return fmt.Errorf("delete principal: %w", err)
	}

	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrPrincipalNotFound
	}

	return nil
}

func (s *PostgresService) DeleteCompany(ctx context.Context, companyID string) error {
	companyID = strings.TrimSpace(companyID)
	if companyID == "" {
		return ErrInvalidInput
	}

	result, err := s.db.ExecContext(ctx, `DELETE FROM companies WHERE id = $1`, companyID)
	if err != nil {
		return fmt.Errorf("delete company: %w", err)
	}

	affected, err := result.RowsAffected()
	if err == nil && affected == 0 {
		return ErrCompanyNotFound
	}

	return nil
}

func (s *PostgresService) SetMembership(ctx context.Context, companyID, principalID string, member bool) error {
	companyID = strings.TrimSpace(companyID)
	principalID = strings.TrimSpace(principalID)
	if companyID == "" || principalID == "" {
		return ErrInvalidInput
	}

	if exists, err := s.existsCompany(ctx, companyID); err != nil {
		return err
	} else if !exists {
		return ErrCompanyNotFound
	}

	if exists, err := s.existsPrincipal(ctx, principalID); err != nil {
		return err
	} else if !exists {
		return ErrPrincipalNotFound
	}

	if member {
		_, err := s.db.ExecContext(
			ctx,
			`INSERT INTO company_memberships (company_id, principal_id) VALUES ($1, $2)
			 ON CONFLICT (company_id, principal_id) DO NOTHING`,
			companyID,
			principalID,
		)
		if err != nil {
			return fmt.Errorf("add company membership: %w", err)
		}
		return nil
	}

	_, err := s.db.ExecContext(ctx, `DELETE FROM company_memberships WHERE company_id = $1 AND principal_id = $2`, companyID, principalID)
	if err != nil {
		return fmt.Errorf("remove company membership: %w", err)
	}

	return nil
}

func (s *PostgresService) AssignZoneToCompany(ctx context.Context, zoneName, companyID string) error {
	zoneName = strings.TrimSpace(zoneName)
	companyID = strings.TrimSpace(companyID)
	if zoneName == "" || companyID == "" {
		return ErrInvalidInput
	}

	if exists, err := s.existsCompany(ctx, companyID); err != nil {
		return err
	} else if !exists {
		return ErrCompanyNotFound
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO zone_company_assignments (zone_name, company_id) VALUES ($1, $2)
		 ON CONFLICT (zone_name) DO UPDATE SET company_id = EXCLUDED.company_id, created_at = NOW()`,
		zoneName,
		companyID,
	)
	if err != nil {
		return fmt.Errorf("assign zone to company: %w", err)
	}

	return nil
}

func (s *PostgresService) UnassignZone(ctx context.Context, zoneName string) error {
	zoneName = strings.TrimSpace(zoneName)
	if zoneName == "" {
		return ErrInvalidInput
	}

	_, err := s.db.ExecContext(ctx, `DELETE FROM zone_company_assignments WHERE zone_name = $1`, zoneName)
	if err != nil {
		return fmt.Errorf("clear zone assignment: %w", err)
	}

	return nil
}

func (s *PostgresService) migrate(ctx context.Context) error {
	queries := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`CREATE TABLE IF NOT EXISTS principals (
			id TEXT PRIMARY KEY,
			auth_source TEXT NOT NULL,
			subject TEXT NOT NULL,
			username TEXT NOT NULL,
			email TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL CHECK (role IN ('admin', 'user', 'audit', 'viewer')),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (auth_source, subject)
		)`,
		`CREATE TABLE IF NOT EXISTS companies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			slug TEXT NOT NULL UNIQUE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS company_memberships (
			company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
			principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (company_id, principal_id)
		)`,
		`CREATE TABLE IF NOT EXISTS local_credentials (
			principal_id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
			password_hash TEXT NOT NULL,
			must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS zone_company_assignments (
			zone_name TEXT PRIMARY KEY,
			company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_company_memberships_principal ON company_memberships (principal_id)`,
		`CREATE INDEX IF NOT EXISTS idx_zone_assignments_company ON zone_company_assignments (company_id)`,
		`DO $$
		BEGIN
			IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'principals') THEN
				BEGIN
					ALTER TABLE principals DROP CONSTRAINT IF EXISTS principals_role_check;
				EXCEPTION WHEN undefined_table THEN
					NULL;
				END;
				ALTER TABLE principals
					ADD CONSTRAINT principals_role_check CHECK (role IN ('admin', 'user', 'audit', 'viewer'));
			END IF;
		END
		$$`,
	}

	for _, query := range queries {
		if _, err := s.db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("migrate access schema: %w", err)
		}
	}

	return nil
}

func (s *PostgresService) getPrincipalByIdentity(ctx context.Context, authSource, subject string) (Principal, error) {
	var principal Principal
	var role string

	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, auth_source, subject, username, email, role, created_at, updated_at
		 FROM principals
		 WHERE auth_source = $1 AND subject = $2`,
		authSource,
		subject,
	).Scan(
		&principal.ID,
		&principal.AuthSource,
		&principal.Subject,
		&principal.Username,
		&principal.Email,
		&role,
		&principal.CreatedAt,
		&principal.UpdatedAt,
	)
	if err != nil {
		return Principal{}, err
	}

	principal.Role = auth.Role(role)
	return principal, nil
}

func (s *PostgresService) claimOIDCPlaceholderPrincipal(ctx context.Context, subject, username, email, role string) (bool, error) {
	subject = strings.TrimSpace(subject)
	username = strings.TrimSpace(username)
	if subject == "" || username == "" || subject == username {
		return false, nil
	}

	var principalID string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id
		 FROM principals
		 WHERE auth_source = 'oidc' AND subject = $1
		 LIMIT 1`,
		username,
	).Scan(&principalID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("find oidc placeholder principal: %w", err)
	}

	_, err = s.db.ExecContext(
		ctx,
		`UPDATE principals
		 SET subject = $1, username = $2, email = $3, role = $4, updated_at = NOW()
		 WHERE id = $5`,
		subject,
		username,
		email,
		role,
		principalID,
	)
	if err != nil {
		if isDuplicateKeyError(err) {
			return false, nil
		}
		return false, fmt.Errorf("claim oidc placeholder principal: %w", err)
	}

	return true, nil
}

func (s *PostgresService) listAllowedZoneNames(ctx context.Context, principalID string) ([]string, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT DISTINCT z.zone_name
		 FROM zone_company_assignments z
		 JOIN company_memberships m ON m.company_id = z.company_id
		 WHERE m.principal_id = $1`,
		principalID,
	)
	if err != nil {
		return nil, fmt.Errorf("list allowed zones: %w", err)
	}
	defer rows.Close()

	result := make([]string, 0)
	for rows.Next() {
		var zoneName string
		if err := rows.Scan(&zoneName); err != nil {
			return nil, fmt.Errorf("scan allowed zone: %w", err)
		}
		result = append(result, zoneName)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate allowed zones: %w", err)
	}

	return result, nil
}

func (s *PostgresService) existsCompany(ctx context.Context, companyID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM companies WHERE id = $1`, companyID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check company existence: %w", err)
	}

	return true, nil
}

func (s *PostgresService) existsPrincipal(ctx context.Context, principalID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM principals WHERE id = $1`, principalID).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check principal existence: %w", err)
	}

	return true, nil
}

func validateLocalPassword(password string) error {
	if len(strings.TrimSpace(password)) < 8 {
		return auth.ErrInvalidPassword
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

var slugPattern = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = slugPattern.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	return value
}

func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique constraint")
}
