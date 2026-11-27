package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/vault"
)

// Store keeps reviewers and approvals in Postgres.
type Store struct {
	pool *pgxpool.Pool
	keys *vault.Keys
	ttl  time.Duration // how long an approval stays valid
}

func NewStore(pool *pgxpool.Pool, keys *vault.Keys, ttl time.Duration) *Store {
	return &Store{pool: pool, keys: keys, ttl: ttl}
}

// Open stores a held request for review. The content is encrypted: it is
// redacted, but free text can still hold things the detectors missed.
func (s *Store) Open(ctx context.Context, h pipeline.Held) (string, error) {
	return s.open(ctx, KindRequest, h, nil, "")
}

// OpenToolCalls stores held tool calls for review, together with the
// model's answer that contains them (encrypted, like the content).
func (s *Store) OpenToolCalls(ctx context.Context, h pipeline.Held, response []byte, contentType string) (string, error) {
	return s.open(ctx, KindToolCalls, h, response, contentType)
}

func (s *Store) open(ctx context.Context, kind Kind, h pipeline.Held, response []byte, contentType string) (string, error) {
	plain, err := json.Marshal(Content{
		SystemName: h.SystemName, Model: h.Model, Reason: h.Reason,
		Messages: h.Messages, ToolCalls: h.ToolCalls,
	})
	if err != nil {
		return "", err
	}
	sealed, err := s.keys.Encrypt(string(plain), contentContext(h.RequestID))
	if err != nil {
		return "", fmt.Errorf("approval: encrypt: %w", err)
	}
	var sealedResponse []byte
	if response != nil {
		sealedResponse, err = s.keys.Encrypt(string(response), responseContext(h.RequestID))
		if err != nil {
			return "", fmt.Errorf("approval: encrypt: %w", err)
		}
	}
	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO approvals (kind, request_id, ai_system_id, request_hash, content, content_hash,
			held_response, response_type, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + $9 * interval '1 second')
		RETURNING id::text`,
		kind, h.RequestID, h.SystemID, h.RequestHash, sealed, sha256Hex(plain),
		sealedResponse, contentType, s.ttl.Seconds(),
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("approval: open: %w", err)
	}
	return id, nil
}

// Get returns one approval and the content the reviewer sees.
func (s *Store) Get(ctx context.Context, id string) (Approval, Content, error) {
	var a Approval
	var sealed []byte
	err := s.pool.QueryRow(ctx, selectApproval+" WHERE a.id = $1", id).Scan(append(a.fields(), &sealed)...)
	if errors.Is(err, pgx.ErrNoRows) || isCode(err, "22P02") {
		return Approval{}, Content{}, ErrNotFound
	}
	if err != nil {
		return Approval{}, Content{}, fmt.Errorf("approval: get: %w", err)
	}
	plain, err := s.keys.Decrypt(sealed, contentContext(a.RequestID))
	if err != nil {
		return Approval{}, Content{}, fmt.Errorf("approval: decrypt: %w", err)
	}
	var c Content
	if err := json.Unmarshal([]byte(plain), &c); err != nil {
		return Approval{}, Content{}, fmt.Errorf("approval: content: %w", err)
	}
	return a, c, nil
}

// List returns approvals with the given status, newest first. Pending
// means pending and not expired: those are the ones waiting for someone.
func (s *Store) List(ctx context.Context, status Status) ([]Approval, error) {
	where := " WHERE a.status = $1"
	if status == Pending {
		where += " AND a.expires_at > now()"
	}
	rows, err := s.pool.Query(ctx, selectApproval+where+" ORDER BY a.created_at DESC LIMIT 200", status)
	if err != nil {
		return nil, fmt.Errorf("approval: list: %w", err)
	}
	defer rows.Close()
	out := []Approval{}
	for rows.Next() {
		var a Approval
		var sealed []byte
		if err := rows.Scan(append(a.fields(), &sealed)...); err != nil {
			return nil, fmt.Errorf("approval: list: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountPending returns how many approvals wait for a reviewer and can
// still be decided (not expired). It is the same set List(Pending) shows.
func (s *Store) CountPending(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		"SELECT count(*) FROM approvals WHERE status = 'pending' AND expires_at > now()").Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("approval: count pending: %w", err)
	}
	return n, nil
}

// Decide approves or rejects a pending approval. seenHash must be the
// content_hash of what the reviewer looked at, which proves the decision
// is about that content.
//
// The conditions are in the UPDATE itself, so two reviewers deciding at
// the same moment can't both succeed: the second finds it no longer
// pending.
func (s *Store) Decide(ctx context.Context, id, reviewerID string, approve bool, seenHash, note string) (Approval, error) {
	status := Rejected
	if approve {
		status = Approved
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE approvals
		SET status = $3, decided_by = $2, decided_at = now(), note = $5
		WHERE id = $1 AND status = 'pending' AND expires_at > now() AND content_hash = $4`,
		id, reviewerID, status, seenHash, note)
	if isCode(err, "22P02") {
		return Approval{}, ErrNotFound
	}
	if err != nil {
		return Approval{}, fmt.Errorf("approval: decide: %w", err)
	}
	if tag.RowsAffected() == 0 {
		a, _, err := s.Get(ctx, id)
		switch {
		case err != nil:
			return Approval{}, err
		case a.Status != Pending:
			return Approval{}, ErrNotPending
		case a.Expired:
			return Approval{}, ErrExpired
		default:
			return Approval{}, ErrStaleView
		}
	}
	a, _, err := s.Get(ctx, id)
	return a, err
}

// Use implements pipeline.Approvals: it lets an approved request through
// once. All conditions are checked in one UPDATE, so of two identical
// requests sent at the same moment, only one gets through.
func (s *Store) Use(ctx context.Context, id, systemID, requestHash, requestID string) (string, error) {
	var reviewer string
	err := s.pool.QueryRow(ctx, `
		UPDATE approvals a
		SET status = 'used', used_at = now(), used_by_request_id = $4
		FROM reviewers r
		WHERE a.id = $1 AND a.kind = 'request' AND a.ai_system_id = $2 AND a.status = 'approved'
		  AND a.expires_at > now() AND a.request_hash = $3 AND r.id = a.decided_by
		RETURNING r.name`,
		id, systemID, requestHash, requestID).Scan(&reviewer)
	if err == nil {
		return reviewer, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) && !isCode(err, "22P02") {
		return "", fmt.Errorf("approval: use: %w", err)
	}

	a, err := s.usable(ctx, id, systemID, requestHash, "")
	if err != nil {
		return "", err
	}
	if a.Kind == KindToolCalls {
		// Approved tool calls for this very request: the request got through
		// before, or there would be no tool calls. Let it through again; the
		// tool guard uses up the approval and gives back the approved answer.
		return a.DecidedBy, nil
	}
	return "", ErrWrongRequest // unreachable: a usable request approval would have matched
}

// UseToolCalls lets the approved answer of an approved tool-call approval
// be given back once, and returns it with its content type and the
// reviewer's name. The stored answer is deleted as it is handed out: it
// is not needed any more.
func (s *Store) UseToolCalls(ctx context.Context, id, systemID, requestHash, requestID string) (string, []byte, string, error) {
	var reviewer, responseType, requestOfApproval string
	var sealed []byte
	err := s.pool.QueryRow(ctx, `
		WITH target AS (
			SELECT id, request_id, held_response FROM approvals
			WHERE id = $1 AND kind = 'tool_calls' AND ai_system_id = $2 AND status = 'approved'
			  AND expires_at > now() AND request_hash = $3
			FOR UPDATE
		)
		UPDATE approvals a
		SET status = 'used', used_at = now(), used_by_request_id = $4, held_response = NULL
		FROM target, reviewers r
		WHERE a.id = target.id AND r.id = a.decided_by
		RETURNING r.name, target.request_id, target.held_response, a.response_type`,
		id, systemID, requestHash, requestID).Scan(&reviewer, &requestOfApproval, &sealed, &responseType)
	if err == nil {
		plain, err := s.keys.Decrypt(sealed, responseContext(requestOfApproval))
		if err != nil {
			return "", nil, "", fmt.Errorf("approval: decrypt: %w", err)
		}
		return reviewer, []byte(plain), responseType, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) && !isCode(err, "22P02") {
		return "", nil, "", fmt.Errorf("approval: use: %w", err)
	}

	if _, err := s.usable(ctx, id, systemID, requestHash, KindToolCalls); err != nil {
		return "", nil, "", err
	}
	return "", nil, "", ErrWrongRequest // unreachable: a usable tool approval would have matched
}

// usable explains why an approval can't be used right now, or returns it
// if it could be (approved, not expired, this system, this request).
//
// With a kind, an approval of another kind is ErrOtherKind, whatever its
// status: it is not the caller's business. This has to be checked before
// the status. Otherwise a request approval the pipeline has just used
// would look "already used" to the tool guard, which then refuses the
// very request that was approved.
func (s *Store) usable(ctx context.Context, id, systemID, requestHash string, kind Kind) (Approval, error) {
	a, _, err := s.Get(ctx, id)
	switch {
	case errors.Is(err, ErrNotFound) || (err == nil && a.SystemID != systemID):
		return Approval{}, ErrNotFound // another system's approval: don't reveal it exists
	case err != nil:
		return Approval{}, err
	case kind != "" && a.Kind != kind:
		return Approval{}, pipeline.ErrOtherKind
	case a.Status == Used:
		return Approval{}, ErrAlreadyUsed
	case a.Status == Rejected:
		return Approval{}, fmt.Errorf("%w by %s", ErrRejected, a.DecidedBy)
	case a.Expired:
		return Approval{}, ErrExpired
	case a.Status == Pending:
		return Approval{}, ErrPending
	case a.RequestHash != requestHash:
		return Approval{}, ErrWrongRequest
	}
	return a, nil
}

const selectApproval = `
	SELECT a.id::text, a.kind, a.request_id, a.request_hash, a.ai_system_id::text, a.status,
		a.expires_at <= now() AND a.status IN ('pending', 'approved'),
		a.content_hash, a.created_at, a.expires_at,
		COALESCE(r.name, ''), a.decided_at, a.note, a.used_at, COALESCE(a.used_by_request_id, ''),
		a.content
	FROM approvals a LEFT JOIN reviewers r ON r.id = a.decided_by`

// fields lists where each column of selectApproval goes, in order.
func (a *Approval) fields() []any {
	return []any{&a.ID, &a.Kind, &a.RequestID, &a.RequestHash, &a.SystemID, &a.Status, &a.Expired, &a.ContentHash,
		&a.CreatedAt, &a.ExpiresAt, &a.DecidedBy, &a.DecidedAt, &a.Note, &a.UsedAt, &a.UsedByRequestID}
}

// CreateReviewer adds a reviewer and returns their token. The token is
// shown once; only its hash is stored.
func (s *Store) CreateReviewer(ctx context.Context, name string) (Reviewer, string, error) {
	token, hash, err := newToken()
	if err != nil {
		return Reviewer{}, "", err
	}
	rv := Reviewer{Name: name, TokenPrefix: token[:12]}
	err = s.pool.QueryRow(ctx, `
		INSERT INTO reviewers (name, token_hash, token_prefix) VALUES ($1, $2, $3)
		RETURNING id::text, created_at`,
		name, hash, rv.TokenPrefix).Scan(&rv.ID, &rv.CreatedAt)
	if isCode(err, "23505") {
		return Reviewer{}, "", ErrDuplicate
	}
	if err != nil {
		return Reviewer{}, "", fmt.Errorf("approval: create reviewer: %w", err)
	}
	return rv, token, nil
}

// ListReviewers returns all reviewers, including revoked ones.
func (s *Store) ListReviewers(ctx context.Context) ([]Reviewer, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT id::text, name, token_prefix, created_at, revoked_at FROM reviewers ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("approval: list reviewers: %w", err)
	}
	defer rows.Close()
	out := []Reviewer{}
	for rows.Next() {
		var rv Reviewer
		if err := rows.Scan(&rv.ID, &rv.Name, &rv.TokenPrefix, &rv.CreatedAt, &rv.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, rv)
	}
	return out, rows.Err()
}

// RevokeReviewer stops a reviewer's token from working. Their past
// decisions stay, with their name.
func (s *Store) RevokeReviewer(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		"UPDATE reviewers SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", id)
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

// ReviewerByToken finds the active reviewer a token belongs to.
func (s *Store) ReviewerByToken(ctx context.Context, token string) (Reviewer, error) {
	var rv Reviewer
	err := s.pool.QueryRow(ctx, `
		SELECT id::text, name, token_prefix, created_at FROM reviewers
		WHERE token_hash = $1 AND revoked_at IS NULL`,
		hashToken(token)).Scan(&rv.ID, &rv.Name, &rv.TokenPrefix, &rv.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Reviewer{}, ErrNotFound
	}
	return rv, err
}

// responseContext binds a held answer to its request in the same way.
func responseContext(requestID string) string { return "approval-response|" + requestID }

// contentContext binds the encrypted content to its request, so a sealed
// value copied to another row can't be decrypted there.
func contentContext(requestID string) string { return "approval|" + requestID }

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func isCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
