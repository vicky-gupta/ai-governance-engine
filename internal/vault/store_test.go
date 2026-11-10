package vault

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vicky-gupta/ai-governance-engine/internal/db"
	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
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
	if _, err := pool.Exec(ctx, "TRUNCATE pii_vault"); err != nil {
		t.Fatal(err)
	}
	return NewStore(pool, testKeys(t, 1)), pool
}

func TestSaveRevealErase(t *testing.T) {
	s, pool := testStore(t)
	ctx := context.Background()

	iban := pii.Replacement{Token: "[IBAN_1]", Kind: pii.IBAN, Value: "DE89 3704 0044 0532 0130 00"}
	email := pii.Replacement{Token: "[EMAIL_1]", Kind: pii.Email, Value: "anna@example.com"}
	if err := s.Save(ctx, "req-1", []pii.Replacement{iban, email}); err != nil {
		t.Fatal(err)
	}
	// The same IBAN, written differently, in a second request.
	if err := s.Save(ctx, "req-2", []pii.Replacement{{Token: "[IBAN_1]", Kind: pii.IBAN, Value: "DE89370400440532013000"}}); err != nil {
		t.Fatal(err)
	}

	got, err := s.Reveal(ctx, "req-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Value != iban.Value || got[1].Value != email.Value {
		t.Fatalf("Reveal = %+v", got)
	}

	// Nothing readable is stored in the database itself.
	var raw string
	pool.QueryRow(ctx, "SELECT string_agg(encode(ciphertext, 'escape'), '') FROM pii_vault").Scan(&raw)
	if strings.Contains(raw, "anna") || strings.Contains(raw, "3704") {
		t.Error("plaintext found in the vault table")
	}

	// Erasing the IBAN removes it from both requests, and nothing else.
	n, err := s.EraseValue(ctx, pii.IBAN, "de89 3704 0044 0532 0130 00")
	if err != nil || n != 2 {
		t.Fatalf("EraseValue = %d, %v; want 2 rows", n, err)
	}
	got, _ = s.Reveal(ctx, "req-1")
	if len(got) != 1 || got[0].Kind != pii.Email {
		t.Errorf("after erasure req-1 = %+v, want only the email", got)
	}
	if got, _ := s.Reveal(ctx, "req-2"); len(got) != 0 {
		t.Errorf("after erasure req-2 = %+v, want nothing", got)
	}

	if n, _ := s.EraseValue(ctx, pii.IBAN, iban.Value); n != 0 {
		t.Errorf("erasing again deleted %d rows, want 0", n)
	}
}

func TestSaveNothing(t *testing.T) {
	s, _ := testStore(t)
	if err := s.Save(context.Background(), "req-1", nil); err != nil {
		t.Error(err)
	}
}
