package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vicky-gupta/ai-governance-engine/internal/db"
)

// testStore connects to TEST_DATABASE_URL and empties the audit log.
// The table is append-only, so the trigger is switched off briefly to
// clear it. Only a table owner can do that, which is the point.
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
	mustExec(t, pool, "ALTER TABLE audit_log DISABLE TRIGGER USER")
	mustExec(t, pool, "TRUNCATE audit_log RESTART IDENTITY")
	mustExec(t, pool, "ALTER TABLE audit_log ENABLE TRIGGER USER")
	return NewStore(pool), pool
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql); err != nil {
		t.Fatal(err)
	}
}

func appendN(t *testing.T, s *Store, n int) []Entry {
	t.Helper()
	var out []Entry
	for i := 0; i < n; i++ {
		e, err := s.Append(context.Background(), Entry{
			RequestID: fmt.Sprintf("req-%d", i), SystemID: "sys-1", SystemName: "support-bot",
			Model: "llama", Action: "allow", RequestHash: HashBytes([]byte("x")),
			Trace: json.RawMessage(`[{"check":"max_tokens","action":"allow","duration_ns":1200}]`),
		})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestChainLinksAndVerifies(t *testing.T) {
	s, _ := testStore(t)
	entries := appendN(t, s, 3)

	if entries[0].PrevHash != GenesisHash {
		t.Error("first entry should point at the genesis hash")
	}
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevHash != entries[i-1].Hash {
			t.Errorf("entry %d does not link to entry %d", i, i-1)
		}
	}

	res, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Checked != 3 {
		t.Errorf("verify = %+v, want ok with 3 checked", res)
	}
}

func TestDatabaseRefusesChanges(t *testing.T) {
	s, pool := testStore(t)
	appendN(t, s, 1)
	ctx := context.Background()
	for _, sql := range []string{
		"UPDATE audit_log SET action = 'block'",
		"DELETE FROM audit_log",
		"TRUNCATE audit_log",
	} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Errorf("%q succeeded; the table should be append-only", sql)
		}
	}
}

func TestVerifyFindsTampering(t *testing.T) {
	cases := map[string]struct {
		sql      string
		brokenAt int64
	}{
		// Someone rewrites history: a blocked request now looks allowed.
		"edited entry": {"UPDATE audit_log SET reason = 'nothing to see' WHERE id = 2", 2},
		// Someone deletes an entry: the next one no longer links up.
		"deleted entry": {"DELETE FROM audit_log WHERE id = 2", 3},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, pool := testStore(t)
			appendN(t, s, 4)

			// Simulate an attacker with admin rights who disables the trigger.
			mustExec(t, pool, "ALTER TABLE audit_log DISABLE TRIGGER USER")
			mustExec(t, pool, tc.sql)
			mustExec(t, pool, "ALTER TABLE audit_log ENABLE TRIGGER USER")

			res, err := s.Verify(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if res.OK || res.BrokenAt != tc.brokenAt {
				t.Errorf("verify = %+v, want broken at %d", res, tc.brokenAt)
			}
		})
	}
}

func TestConcurrentAppendsKeepOneChain(t *testing.T) {
	s, _ := testStore(t)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Append(context.Background(), Entry{
				RequestID: fmt.Sprintf("req-%d", i), SystemID: "s", SystemName: "s",
				Model: "m", Action: "allow", RequestHash: "h",
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	res, err := s.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Checked != 20 {
		t.Errorf("verify = %+v, want ok with 20 checked", res)
	}
}
