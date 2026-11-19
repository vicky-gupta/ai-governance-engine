package usage

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store keeps usage records in Postgres.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Record saves one request's usage. Recording the same request twice is
// a no-op, so a retry can never count tokens twice.
func (s *Store) Record(ctx context.Context, r Record) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO usage_records
			(request_id, ai_system_id, model, provider, prompt_tokens, completion_tokens, total_tokens)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (request_id) DO NOTHING`,
		r.RequestID, r.SystemID, r.Model, r.Provider, r.PromptTokens, r.CompletionTokens, r.TotalTokens)
	if err != nil {
		return fmt.Errorf("usage: record: %w", err)
	}
	return nil
}

// UsedThisMonth returns the tokens a system has used since the start of
// now's calendar month (UTC).
func (s *Store) UsedThisMonth(ctx context.Context, systemID string, now time.Time) (int64, error) {
	var used int64
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(sum(total_tokens), 0)::bigint FROM usage_records
		WHERE ai_system_id = $1 AND created_at >= $2`,
		systemID, MonthStart(now)).Scan(&used)
	if err != nil {
		return 0, fmt.Errorf("usage: used this month: %w", err)
	}
	return used, nil
}

// SystemUsage is one AI system's usage for a month.
type SystemUsage struct {
	SystemID           string `json:"ai_system_id"`
	SystemName         string `json:"ai_system_name"`
	Requests           int64  `json:"requests"`
	PromptTokens       int64  `json:"prompt_tokens"`
	CompletionTokens   int64  `json:"completion_tokens"`
	TotalTokens        int64  `json:"total_tokens"`
	MonthlyTokenBudget *int64 `json:"monthly_token_budget"`
}

// Summary returns every AI system's usage in the month that contains
// month, including systems that used nothing.
func (s *Store) Summary(ctx context.Context, month time.Time) ([]SystemUsage, error) {
	from := MonthStart(month)
	rows, err := s.pool.Query(ctx, `
		SELECT s.id::text, s.name,
			count(u.id),
			COALESCE(sum(u.prompt_tokens), 0)::bigint,
			COALESCE(sum(u.completion_tokens), 0)::bigint,
			COALESCE(sum(u.total_tokens), 0)::bigint,
			s.monthly_token_budget
		FROM ai_systems s
		LEFT JOIN usage_records u
			ON u.ai_system_id = s.id AND u.created_at >= $1 AND u.created_at < $2
		GROUP BY s.id, s.name, s.monthly_token_budget
		ORDER BY 6 DESC, s.name`,
		from, from.AddDate(0, 1, 0))
	if err != nil {
		return nil, fmt.Errorf("usage: summary: %w", err)
	}
	defer rows.Close()

	out := []SystemUsage{}
	for rows.Next() {
		var u SystemUsage
		if err := rows.Scan(&u.SystemID, &u.SystemName, &u.Requests, &u.PromptTokens,
			&u.CompletionTokens, &u.TotalTokens, &u.MonthlyTokenBudget); err != nil {
			return nil, fmt.Errorf("usage: summary: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
