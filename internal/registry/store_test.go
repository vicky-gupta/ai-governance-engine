package registry

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/db"
)

// testStore connects to the database in TEST_DATABASE_URL, applies the
// migrations and empties the tables. Without that variable, the test is
// skipped, so `go test ./...` still works with no database running.
func testStore(t *testing.T) *Store {
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
	if _, err := pool.Exec(ctx, "TRUNCATE ai_systems CASCADE"); err != nil {
		t.Fatal(err)
	}
	return NewStore(pool)
}

func TestKeyLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	sys, err := s.CreateSystem(ctx, System{
		Name: "loan-agent", Owner: "credit-team", Purpose: "creditworthiness assessment", RiskTier: RiskHigh,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sys.ID == "" || sys.Status != "active" {
		t.Fatalf("unexpected system: %+v", sys)
	}

	if _, err := s.CreateSystem(ctx, System{Name: "loan-agent", Owner: "x", Purpose: "x", RiskTier: RiskMinimal}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate name: err = %v, want ErrDuplicate", err)
	}

	plain, key, err := s.CreateKey(ctx, sys.ID)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.SystemByKey(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "loan-agent" || got.RiskTier != RiskHigh {
		t.Errorf("SystemByKey returned %+v", got)
	}

	if _, err := s.SystemByKey(ctx, "aigov_wrong"); !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong key: err = %v, want ErrNotFound", err)
	}

	if err := s.RevokeKey(ctx, key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SystemByKey(ctx, plain); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked key: err = %v, want ErrNotFound", err)
	}
	if err := s.RevokeKey(ctx, key.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking twice: err = %v, want ErrNotFound", err)
	}
}

func TestCreateKeyUnknownSystem(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, id := range []string{"00000000-0000-0000-0000-000000000000", "not-a-uuid"} {
		if _, _, err := s.CreateKey(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("CreateKey(%q): err = %v, want ErrNotFound", id, err)
		}
	}
}
