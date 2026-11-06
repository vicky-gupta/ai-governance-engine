package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store writes and reads the audit log in Postgres.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// appendLockID serialises writers. Every entry needs the hash of the one
// before it, so two writers must never read the same "latest" entry.
const appendLockID = 727275

const columns = `id, created_at, request_id, ai_system_id, ai_system_name, model, action,
	check_name, reason, trace, request_hash, forwarded_hash, prev_hash, hash, provider, region`

// Record appends an entry to the end of the chain.
func (s *Store) Record(ctx context.Context, e Entry) error {
	_, err := s.Append(ctx, e)
	return err
}

// Append adds e to the chain and returns it with ID, time and hashes set.
func (s *Store) Append(ctx context.Context, e Entry) (Entry, error) {
	if len(e.Trace) == 0 {
		e.Trace = json.RawMessage("[]")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Entry{}, err
	}
	defer tx.Rollback(ctx) // does nothing once Commit has succeeded

	// Held until the transaction ends, across every gateway instance.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", appendLockID); err != nil {
		return Entry{}, err
	}

	err = tx.QueryRow(ctx, "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&e.PrevHash)
	if errors.Is(err, pgx.ErrNoRows) {
		e.PrevHash = GenesisHash
	} else if err != nil {
		return Entry{}, err
	}

	// Postgres stores microseconds, so drop the nanoseconds now: the time
	// we hash must be exactly the time we read back later.
	e.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	e.Hash = e.ComputeHash()

	err = tx.QueryRow(ctx, `
		INSERT INTO audit_log (created_at, request_id, ai_system_id, ai_system_name, model, action,
			check_name, reason, trace, request_hash, forwarded_hash, prev_hash, hash, provider, region)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING id`,
		e.CreatedAt, e.RequestID, e.SystemID, e.SystemName, e.Model, e.Action,
		e.Check, e.Reason, e.Trace, e.RequestHash, e.ForwardedHash, e.PrevHash, e.Hash, e.Provider, e.Region,
	).Scan(&e.ID)
	if err != nil {
		return Entry{}, err
	}
	return e, tx.Commit(ctx)
}

// List returns the most recent entries, newest first.
func (s *Store) List(ctx context.Context, limit int) ([]Entry, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT "+columns+" FROM audit_log ORDER BY id DESC LIMIT $1", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := []Entry{}
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// VerifyResult reports whether the chain is intact.
type VerifyResult struct {
	OK       bool   `json:"ok"`
	Checked  int    `json:"checked"`
	BrokenAt int64  `json:"broken_at,omitempty"` // ID of the first bad entry
	Problem  string `json:"problem,omitempty"`
}

// Verify walks the whole chain from the first entry and recomputes every
// hash. It stops at the first entry that doesn't match.
func (s *Store) Verify(ctx context.Context) (VerifyResult, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+columns+" FROM audit_log ORDER BY id")
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()

	res := VerifyResult{OK: true}
	prev := GenesisHash
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return VerifyResult{}, err
		}
		res.Checked++

		if e.PrevHash != prev {
			return VerifyResult{OK: false, Checked: res.Checked, BrokenAt: e.ID,
				Problem: "link broken: an entry before this one was changed, removed or reordered"}, nil
		}
		if e.ComputeHash() != e.Hash {
			return VerifyResult{OK: false, Checked: res.Checked, BrokenAt: e.ID,
				Problem: "contents changed: this entry no longer matches its hash"}, nil
		}
		prev = e.Hash
	}
	return res, rows.Err()
}

func scanEntry(row pgx.Row) (Entry, error) {
	var e Entry
	err := row.Scan(&e.ID, &e.CreatedAt, &e.RequestID, &e.SystemID, &e.SystemName, &e.Model,
		&e.Action, &e.Check, &e.Reason, &e.Trace, &e.RequestHash, &e.ForwardedHash, &e.PrevHash, &e.Hash,
		&e.Provider, &e.Region)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: %w", err)
	}
	return e, nil
}
