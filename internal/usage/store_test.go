package usage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vicky-gupta/ai-governance-engine/internal/db"
)

func testStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping database test")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "TRUNCATE usage_records"); err != nil {
		t.Fatal(err)
	}
	return NewStore(pool), pool
}

// newSystem inserts an AI system directly and returns its ID.
func newSystem(t *testing.T, pool *pgxpool.Pool, name string, budget *int64) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(), `
		INSERT INTO ai_systems (name, owner, purpose, risk_tier, monthly_token_budget)
		VALUES ($1 || '-' || gen_random_uuid()::text, 'x', 'x', 'minimal', $2) RETURNING id::text`,
		name, budget).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRecordAndUsedThisMonth(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()
	sys := newSystem(t, pool, "metered-bot", nil)
	now := time.Now()

	for i, total := range []int64{100, 250} {
		r := Record{RequestID: sys + "-" + string(rune('a'+i)), SystemID: sys, Model: "m", Provider: "groq",
			Usage: Usage{PromptTokens: 10, CompletionTokens: total - 10, TotalTokens: total}}
		if err := s.Record(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	// The same request recorded again must not count twice.
	if err := s.Record(ctx, Record{RequestID: sys + "-a", SystemID: sys, Model: "m", Provider: "groq",
		Usage: Usage{TotalTokens: 100}}); err != nil {
		t.Fatal(err)
	}
	// Usage from last month doesn't count against this month's budget.
	if _, err := pool.Exec(ctx, `
		INSERT INTO usage_records (request_id, ai_system_id, model, provider,
			prompt_tokens, completion_tokens, total_tokens, created_at)
		VALUES ($1, $2, 'm', 'groq', 0, 0, 9999, $3)`,
		sys+"-old", sys, MonthStart(now).Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}

	used, err := s.UsedThisMonth(ctx, sys, now)
	if err != nil || used != 350 {
		t.Errorf("UsedThisMonth = %d, %v; want 350", used, err)
	}
	if used, _ := s.UsedThisMonth(ctx, newSystem(t, pool, "idle-bot", nil), now); used != 0 {
		t.Errorf("unused system: %d, want 0", used)
	}
}

func TestSummary(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()
	budget := int64(1000)
	busy := newSystem(t, pool, "busy-bot", &budget)
	idle := newSystem(t, pool, "idle-bot", nil)
	for _, id := range []string{"r1", "r2", "r3"} {
		if err := s.Record(ctx, Record{RequestID: busy + id, SystemID: busy, Model: "m", Provider: "groq",
			Usage: Usage{PromptTokens: 1, CompletionTokens: 2, TotalTokens: 3}}); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := s.Summary(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]SystemUsage{}
	for _, r := range rows {
		found[r.SystemID] = r
	}
	if b := found[busy]; b.Requests != 3 || b.TotalTokens != 9 || b.MonthlyTokenBudget == nil || *b.MonthlyTokenBudget != 1000 {
		t.Errorf("busy-bot = %+v, want 3 requests, 9 tokens, budget 1000", b)
	}
	if i, ok := found[idle]; !ok || i.Requests != 0 || i.TotalTokens != 0 {
		t.Errorf("idle-bot = %+v (listed: %v), want listed with zero usage", i, ok)
	}

	// Last month: nothing.
	rows, _ = s.Summary(ctx, MonthStart(time.Now()).AddDate(0, -1, 0))
	for _, r := range rows {
		if r.SystemID == busy && r.TotalTokens != 0 {
			t.Errorf("last month shows %d tokens for busy-bot, want 0", r.TotalTokens)
		}
	}
}
