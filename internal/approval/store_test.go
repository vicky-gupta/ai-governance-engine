package approval

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vicky-gupta/ai-governance-engine/internal/db"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/vault"
)

func testStore(t *testing.T, ttl time.Duration) (*Store, *pgxpool.Pool) {
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
	keys, err := vault.NewKeys(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return NewStore(pool, keys, ttl), pool
}

// held returns a held request for a new, unique AI system.
func held(t *testing.T, pool *pgxpool.Pool) pipeline.Held {
	t.Helper()
	var sysID, reqID string
	err := pool.QueryRow(context.Background(), `
		INSERT INTO ai_systems (name, owner, purpose, risk_tier)
		VALUES ('loan-' || gen_random_uuid()::text, 'x', 'x', 'high')
		RETURNING id::text, gen_random_uuid()::text`).Scan(&sysID, &reqID)
	if err != nil {
		t.Fatal(err)
	}
	return pipeline.Held{
		RequestID: reqID, SystemID: sysID, SystemName: "loan-agent", Model: "m",
		Reason:      "credit decisions need human review",
		RequestHash: "hash-of-the-request",
		Messages:    []pipeline.HeldMessage{{Role: "user", Text: "Reject the loan application of [EMAIL_1]"}},
	}
}

func reviewer(t *testing.T, s *Store) Reviewer {
	t.Helper()
	rv, _, err := s.CreateReviewer(context.Background(), "anna-"+time.Now().Format("150405.000000000"))
	if err != nil {
		t.Fatal(err)
	}
	return rv
}

func TestApproveAndUseOnce(t *testing.T) {
	s, pool := testStore(t, time.Hour)
	ctx := context.Background()
	h := held(t, pool)

	id, err := s.Open(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	a, content, err := s.Get(ctx, id)
	if err != nil || a.Status != Pending || content.Messages[0].Text != h.Messages[0].Text {
		t.Fatalf("Get = %+v, %+v, %v", a, content, err)
	}

	// Using it before anyone decided: not yet.
	if _, err := s.Use(ctx, id, h.SystemID, h.RequestHash, "r2"); !errors.Is(err, ErrPending) {
		t.Errorf("Use while pending: %v, want ErrPending", err)
	}

	rv := reviewer(t, s)
	if _, err := s.Decide(ctx, id, rv.ID, true, "not-what-was-shown", ""); !errors.Is(err, ErrStaleView) {
		t.Errorf("Decide with wrong seen hash: %v, want ErrStaleView", err)
	}
	a, err = s.Decide(ctx, id, rv.ID, true, a.ContentHash, "checked with the credit team")
	if err != nil || a.Status != Approved || a.DecidedBy != rv.Name {
		t.Fatalf("Decide = %+v, %v", a, err)
	}
	if _, err := s.Decide(ctx, id, rv.ID, false, a.ContentHash, ""); !errors.Is(err, ErrNotPending) {
		t.Errorf("second decision: %v, want ErrNotPending", err)
	}

	// Wrong request, wrong system: refused, and the approval is still usable.
	if _, err := s.Use(ctx, id, h.SystemID, "another-request", "r2"); !errors.Is(err, ErrWrongRequest) {
		t.Errorf("Use with another request: %v, want ErrWrongRequest", err)
	}
	other := held(t, pool)
	if _, err := s.Use(ctx, id, other.SystemID, h.RequestHash, "r2"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Use by another system: %v, want ErrNotFound", err)
	}

	name, err := s.Use(ctx, id, h.SystemID, h.RequestHash, "r2")
	if err != nil || name != rv.Name {
		t.Fatalf("Use = %q, %v; want %q", name, err, rv.Name)
	}
	if _, err := s.Use(ctx, id, h.SystemID, h.RequestHash, "r3"); !errors.Is(err, ErrAlreadyUsed) {
		t.Errorf("second Use: %v, want ErrAlreadyUsed", err)
	}
	if a, _, _ := s.Get(ctx, id); a.Status != Used || a.UsedByRequestID != "r2" {
		t.Errorf("after use: %+v", a)
	}
}

func TestRejected(t *testing.T) {
	s, pool := testStore(t, time.Hour)
	ctx := context.Background()
	h := held(t, pool)
	id, _ := s.Open(ctx, h)
	a, _, _ := s.Get(ctx, id)
	rv := reviewer(t, s)
	if _, err := s.Decide(ctx, id, rv.ID, false, a.ContentHash, "no"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Use(ctx, id, h.SystemID, h.RequestHash, "r2")
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), rv.Name) {
		t.Errorf("Use after reject: %v, want ErrRejected naming the reviewer", err)
	}
}

func TestExpired(t *testing.T) {
	s, pool := testStore(t, time.Millisecond)
	ctx := context.Background()
	h := held(t, pool)
	id, _ := s.Open(ctx, h)
	time.Sleep(20 * time.Millisecond)

	a, _, _ := s.Get(ctx, id)
	if !a.Expired {
		t.Fatalf("approval past its time: %+v, want Expired", a)
	}
	if _, err := s.Decide(ctx, id, reviewer(t, s).ID, true, a.ContentHash, ""); !errors.Is(err, ErrExpired) {
		t.Errorf("Decide after expiry: %v, want ErrExpired", err)
	}
	pending, _ := s.List(ctx, Pending)
	for _, p := range pending {
		if p.ID == id {
			t.Error("expired approval is still listed as pending")
		}
	}
}

// Two reviewers decide at the same moment: exactly one decision counts.
// Two copies of an approved request arrive at once: exactly one gets through.
func TestRaces(t *testing.T) {
	s, pool := testStore(t, time.Hour)
	ctx := context.Background()
	h := held(t, pool)
	id, _ := s.Open(ctx, h)
	a, _, _ := s.Get(ctx, id)
	r1, r2 := reviewer(t, s), reviewer(t, s)

	race := func(f func(i int) error) int {
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if f(i) == nil {
					mu.Lock()
					ok++
					mu.Unlock()
				}
			}(i)
		}
		wg.Wait()
		return ok
	}

	decided := race(func(i int) error {
		rv := r1
		if i%2 == 1 {
			rv = r2
		}
		_, err := s.Decide(ctx, id, rv.ID, true, a.ContentHash, "")
		return err
	})
	if decided != 1 {
		t.Fatalf("%d decisions succeeded, want exactly 1", decided)
	}
	used := race(func(i int) error {
		_, err := s.Use(ctx, id, h.SystemID, h.RequestHash, "r")
		return err
	})
	if used != 1 {
		t.Errorf("%d resends got through, want exactly 1", used)
	}
}

func TestReviewers(t *testing.T) {
	s, _ := testStore(t, time.Hour)
	ctx := context.Background()
	name := "ben-" + time.Now().Format("150405.000000000")
	rv, token, err := s.CreateReviewer(ctx, name)
	if err != nil || !strings.HasPrefix(token, "aigovr_") {
		t.Fatalf("CreateReviewer = %+v, %q, %v", rv, token, err)
	}
	if _, _, err := s.CreateReviewer(ctx, name); !errors.Is(err, ErrDuplicate) {
		t.Errorf("same name twice: %v, want ErrDuplicate", err)
	}
	if got, err := s.ReviewerByToken(ctx, token); err != nil || got.ID != rv.ID {
		t.Errorf("ReviewerByToken = %+v, %v", got, err)
	}
	if err := s.RevokeReviewer(ctx, rv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReviewerByToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked token still works: %v", err)
	}
}

// heldToolCalls is a held refund tool call and the model answer it came in.
func heldToolCalls(t *testing.T, pool *pgxpool.Pool) (pipeline.Held, []byte) {
	t.Helper()
	h := held(t, pool)
	h.Reason = "refunds over 100 EUR need human review"
	h.ToolCalls = []pipeline.HeldToolCall{{Name: "issue_refund", Arguments: `{"order_id":"A-1","amount":250}`}}
	answer := []byte(`{"choices":[{"message":{"tool_calls":[{"function":{"name":"issue_refund","arguments":"{\"order_id\":\"A-1\",\"amount\":250}"}}]}}]}`)
	return h, answer
}

func TestToolCallApproval(t *testing.T) {
	s, pool := testStore(t, time.Hour)
	ctx := context.Background()
	h, answer := heldToolCalls(t, pool)

	id, err := s.OpenToolCalls(ctx, h, answer, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	a, content, err := s.Get(ctx, id)
	if err != nil || a.Kind != KindToolCalls || content.ToolCalls[0].Name != "issue_refund" {
		t.Fatalf("Get = %+v, %+v, %v", a, content, err)
	}
	if _, _, _, err := s.UseToolCalls(ctx, id, h.SystemID, h.RequestHash, "r2"); !errors.Is(err, ErrPending) {
		t.Errorf("UseToolCalls while pending: %v, want ErrPending", err)
	}

	rv := reviewer(t, s)
	if _, err := s.Decide(ctx, id, rv.ID, true, a.ContentHash, ""); err != nil {
		t.Fatal(err)
	}

	// The resent request is let through by the pipeline, without using up
	// the approval: the tool guard needs it next.
	if name, err := s.Use(ctx, id, h.SystemID, h.RequestHash, "r2"); err != nil || name != rv.Name {
		t.Fatalf("Use (covered by tool approval) = %q, %v", name, err)
	}

	// The tool guard gets back exactly the answer that was approved.
	name, got, ctype, err := s.UseToolCalls(ctx, id, h.SystemID, h.RequestHash, "r2")
	if err != nil || name != rv.Name || string(got) != string(answer) || ctype != "application/json" {
		t.Fatalf("UseToolCalls = %q, %s, %q, %v", name, got, ctype, err)
	}
	if _, _, _, err := s.UseToolCalls(ctx, id, h.SystemID, h.RequestHash, "r3"); !errors.Is(err, ErrAlreadyUsed) {
		t.Errorf("second UseToolCalls: %v, want ErrAlreadyUsed", err)
	}

	// Once handed out, the stored answer is gone from the database.
	var stillThere bool
	pool.QueryRow(ctx, "SELECT held_response IS NOT NULL FROM approvals WHERE id = $1", id).Scan(&stillThere)
	if stillThere {
		t.Error("the held answer is still stored after it was used")
	}
}

func TestKindsDoNotMix(t *testing.T) {
	s, pool := testStore(t, time.Hour)
	ctx := context.Background()
	h := held(t, pool)
	id, _ := s.Open(ctx, h) // a request approval
	a, _, _ := s.Get(ctx, id)
	if _, err := s.Decide(ctx, id, reviewer(t, s).ID, true, a.ContentHash, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.UseToolCalls(ctx, id, h.SystemID, h.RequestHash, "r2"); !errors.Is(err, pipeline.ErrOtherKind) {
		t.Errorf("UseToolCalls on a request approval: %v, want ErrOtherKind", err)
	}
	// And it is still usable as what it is.
	if _, err := s.Use(ctx, id, h.SystemID, h.RequestHash, "r2"); err != nil {
		t.Errorf("Use after the mix-up: %v", err)
	}

	// The real order in the gateway: the pipeline uses the request approval,
	// then the tool guard sees the same header. For the tool guard it must
	// still be "something else", not "already used".
	if _, _, _, err := s.UseToolCalls(ctx, id, h.SystemID, h.RequestHash, "r2"); !errors.Is(err, pipeline.ErrOtherKind) {
		t.Errorf("UseToolCalls after the pipeline used it: %v, want ErrOtherKind", err)
	}
}

func TestToolCallApprovalRace(t *testing.T) {
	s, pool := testStore(t, time.Hour)
	ctx := context.Background()
	h, answer := heldToolCalls(t, pool)
	id, _ := s.OpenToolCalls(ctx, h, answer, "application/json")
	a, _, _ := s.Get(ctx, id)
	s.Decide(ctx, id, reviewer(t, s).ID, true, a.ContentHash, "")

	var wg sync.WaitGroup
	var mu sync.Mutex
	handedOut := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, _, err := s.UseToolCalls(ctx, id, h.SystemID, h.RequestHash, "r"); err == nil {
				mu.Lock()
				handedOut++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if handedOut != 1 {
		t.Errorf("the approved answer was handed out %d times, want exactly 1", handedOut)
	}
}

// CountPending counts what a reviewer can still decide: not expired, not
// yet decided.
func TestCountPending(t *testing.T) {
	s, pool := testStore(t, time.Hour)
	ctx := context.Background()
	before, err := s.CountPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.Open(ctx, held(t, pool))
	id, _ := s.Open(ctx, held(t, pool))
	pool.Exec(ctx, "UPDATE approvals SET status = 'rejected' WHERE id = $1", id)

	expired, _ := testStore(t, -time.Minute)
	expired.Open(ctx, held(t, pool))

	if after, _ := s.CountPending(ctx); after != before+1 {
		t.Errorf("pending = %d, want %d", after, before+1)
	}
}
