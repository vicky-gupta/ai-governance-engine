package registry

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store reads and writes the registry in Postgres.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// CreateSystem registers a new AI system.
func (s *Store) CreateSystem(ctx context.Context, sys System) (System, error) {
	err := s.pool.QueryRow(ctx, `
		INSERT INTO ai_systems (name, owner, purpose, risk_tier)
		VALUES ($1, $2, $3, $4)
		RETURNING id::text, status, created_at`,
		sys.Name, sys.Owner, sys.Purpose, sys.RiskTier,
	).Scan(&sys.ID, &sys.Status, &sys.CreatedAt)
	if isCode(err, "23505") { // unique_violation
		return System{}, ErrDuplicate
	}
	return sys, err
}

// ListSystems returns all AI systems, oldest first.
func (s *Store) ListSystems(ctx context.Context) ([]System, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, name, owner, purpose, risk_tier, status, created_at
		FROM ai_systems ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	systems := []System{}
	for rows.Next() {
		var sys System
		if err := rows.Scan(&sys.ID, &sys.Name, &sys.Owner, &sys.Purpose,
			&sys.RiskTier, &sys.Status, &sys.CreatedAt); err != nil {
			return nil, err
		}
		systems = append(systems, sys)
	}
	return systems, rows.Err()
}

// CreateKey issues a new API key for an AI system. The returned string is
// the only time the full key is available.
func (s *Store) CreateKey(ctx context.Context, systemID string) (string, Key, error) {
	plain, prefix, hash, err := NewKey()
	if err != nil {
		return "", Key{}, err
	}
	k := Key{SystemID: systemID, Prefix: prefix}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO api_keys (ai_system_id, prefix, key_hash)
		VALUES ($1, $2, $3)
		RETURNING id::text, created_at`,
		systemID, prefix, hash,
	).Scan(&k.ID, &k.CreatedAt)
	// 23503 = the AI system doesn't exist, 22P02 = the ID isn't a valid UUID
	if isCode(err, "23503") || isCode(err, "22P02") {
		return "", Key{}, ErrNotFound
	}
	if err != nil {
		return "", Key{}, err
	}
	return plain, k, nil
}

// RevokeKey disables a key. The row is kept for the audit trail.
func (s *Store) RevokeKey(ctx context.Context, keyID string) error {
	tag, err := s.pool.Exec(ctx,
		"UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", keyID)
	if isCode(err, "22P02") {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SystemByKey finds the AI system that owns an active key.
func (s *Store) SystemByKey(ctx context.Context, key string) (System, error) {
	var sys System
	err := s.pool.QueryRow(ctx, `
		SELECT s.id::text, s.name, s.owner, s.purpose, s.risk_tier, s.status, s.created_at
		FROM api_keys k
		JOIN ai_systems s ON s.id = k.ai_system_id
		WHERE k.key_hash = $1 AND k.revoked_at IS NULL`,
		HashKey(key),
	).Scan(&sys.ID, &sys.Name, &sys.Owner, &sys.Purpose, &sys.RiskTier, &sys.Status, &sys.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return System{}, ErrNotFound
	}
	return sys, err
}

// isCode reports whether err is a Postgres error with the given code.
func isCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
