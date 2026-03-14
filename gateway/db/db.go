package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

type User struct {
	ID           string
	Username     string
	PasswordHash string
	Role         string
	IsActive     bool
}

type Policy struct {
	ID                   string
	Name                 string
	UserRole             string
	AllowedHoursStart    int
	AllowedHoursEnd      int
	RequireTrustedDevice bool
	AllowedResources     []string
}

type Session struct {
	ID        string
	UserID    string
	TokenID   string
	ClientIP  string
	ExpiresAt time.Time
	Revoked   bool
}

func New(dsn string) (*Store, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, username, password_hash, role, is_active FROM users WHERE username = $1`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.IsActive)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return &u, err
}

func (s *Store) GetPolicyByRole(ctx context.Context, role string) (*Policy, error) {
	var p Policy
	var resources []string
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, user_role, allowed_hours_start, allowed_hours_end, require_trusted_device, allowed_resources
		 FROM policies WHERE user_role = $1 LIMIT 1`,
		role,
	).Scan(&p.ID, &p.Name, &p.UserRole, &p.AllowedHoursStart, &p.AllowedHoursEnd, &p.RequireTrustedDevice, &resources)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	p.AllowedResources = resources
	return &p, err
}

func (s *Store) GetPolicyForRole(ctx context.Context, role string) (*Policy, error) {
	var p Policy
	var resources []string
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, user_role, allowed_hours_start, allowed_hours_end, require_trusted_device, allowed_resources
		 FROM policies WHERE user_role = $1 LIMIT 1`,
		role,
	).Scan(&p.ID, &p.Name, &p.UserRole, &p.AllowedHoursStart, &p.AllowedHoursEnd, &p.RequireTrustedDevice, &resources)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	p.AllowedResources = resources
	return &p, err
}

func (s *Store) CreateSession(ctx context.Context, userID, tokenID, clientIP string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (user_id, token_id, client_ip, expires_at) VALUES ($1, $2, $3, $4)`,
		userID, tokenID, clientIP, expiresAt,
	)
	return err
}

func (s *Store) RevokeSession(ctx context.Context, tokenID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked = TRUE, revoked_at = NOW() WHERE token_id = $1`,
		tokenID,
	)
	return err
}

func (s *Store) UpdateLastLogin(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET last_login = NOW() WHERE id = $1`,
		userID,
	)
	return err
}

func (s *Store) WriteAuditLog(ctx context.Context, userID, username, action, resource, clientIP, status, detail string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_log (user_id, username, action, resource, client_ip, status, detail)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		nullableUUID(userID), username, action, resource, clientIP, status, detail,
	)
	return err
}

func (s *Store) CountActiveSessions(ctx context.Context) (int64, error) {
	var count int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sessions WHERE revoked = FALSE AND expires_at > NOW()`,
	).Scan(&count)
	return count, err
}

func nullableUUID(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
