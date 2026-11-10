package vault

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
)

// Store keeps encrypted values in Postgres.
type Store struct {
	pool *pgxpool.Pool
	keys *Keys
}

func NewStore(pool *pgxpool.Pool, keys *Keys) *Store {
	return &Store{pool: pool, keys: keys}
}

// Value is one decrypted entry.
type Value struct {
	Token string   `json:"token"`
	Kind  pii.Kind `json:"kind"`
	Value string   `json:"value"`
}

// bindTo ties a ciphertext to its row, so it only decrypts there.
func bindTo(requestID, token string) string {
	return requestID + "|" + token
}

// Save stores the replacements made in one request.
func (s *Store) Save(ctx context.Context, requestID string, reps []pii.Replacement) error {
	if len(reps) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, r := range reps {
		sealed, err := s.keys.Encrypt(r.Value, bindTo(requestID, r.Token))
		if err != nil {
			return err
		}
		batch.Queue(`INSERT INTO pii_vault (request_id, token, kind, fingerprint, ciphertext)
			VALUES ($1, $2, $3, $4, $5)`,
			requestID, r.Token, string(r.Kind), s.keys.Fingerprint(r.Kind, r.Value), sealed)
	}
	// One round trip for all rows, in one implicit transaction.
	return s.pool.SendBatch(ctx, batch).Close()
}

// Reveal decrypts every value stored for one request.
func (s *Store) Reveal(ctx context.Context, requestID string) ([]Value, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT token, kind, ciphertext FROM pii_vault WHERE request_id = $1 ORDER BY id", requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	values := []Value{}
	for rows.Next() {
		var v Value
		var sealed []byte
		if err := rows.Scan(&v.Token, &v.Kind, &sealed); err != nil {
			return nil, err
		}
		if v.Value, err = s.keys.Decrypt(sealed, bindTo(requestID, v.Token)); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

// EraseValue deletes every stored copy of one value, across all requests,
// and reports how many rows were deleted.
func (s *Store) EraseValue(ctx context.Context, kind pii.Kind, value string) (int64, error) {
	tag, err := s.pool.Exec(ctx, "DELETE FROM pii_vault WHERE fingerprint = $1",
		s.keys.Fingerprint(kind, value))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
