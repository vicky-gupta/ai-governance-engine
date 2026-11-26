package report

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vicky-gupta/ai-governance-engine/internal/approval"
	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/db"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/usage"
	"github.com/vicky-gupta/ai-governance-engine/internal/vault"
)

func TestParseSummary(t *testing.T) {
	got := ParseSummary("redacted 1 EMAIL, 2 PERSON, 1 IBAN")
	if len(got) != 3 || got["PERSON"] != 2 || got["EMAIL"] != 1 {
		t.Errorf("ParseSummary = %v", got)
	}
	if got := ParseSummary("max_tokens set to 1024 by policy"); len(got) != 0 {
		t.Errorf("not a redaction summary: %v", got)
	}
}

func TestReasonsAreGroupedWithoutApprovalIDs(t *testing.T) {
	for _, r := range []string{
		"credit decisions need human review (approval 2f854699-ebb4)",
		"credit decisions need human review (approval ded2b5f4 can't be used: approval has already been used)",
		"credit decisions need human review",
	} {
		if got := withoutApproval(r); got != "credit decisions need human review" {
			t.Errorf("withoutApproval(%q) = %q", r, got)
		}
	}
}

func TestSealAndIntact(t *testing.T) {
	r := Report{System: System{Name: "support-bot"}, Requests: Requests{Total: 3, ByDecision: map[string]int{"allow": 2, "block": 1}}}
	if err := Seal(&r); err != nil || len(r.Hash) != 64 {
		t.Fatalf("Seal: %q, %v", r.Hash, err)
	}
	if !Intact(r) {
		t.Fatal("a freshly sealed report is not intact")
	}
	r.Requests.ByDecision["block"] = 0 // someone edits the saved copy
	if Intact(r) {
		t.Error("an edited report still counts as intact")
	}
}

// world is a database with one AI system and some history.
type world struct {
	pool     *pgxpool.Pool
	builder  *Builder
	auditLog *audit.Store
	systemID string
}

func setup(t *testing.T) world {
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
	var id string
	if err := pool.QueryRow(ctx, `
		INSERT INTO ai_systems (name, owner, purpose, risk_tier, monthly_token_budget)
		VALUES ('loan-' || gen_random_uuid()::text, 'credit-team', 'loan pre-checks', 'high', 100000)
		RETURNING id::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	auditLog := audit.NewStore(pool)
	return world{pool: pool, builder: NewBuilder(pool, auditLog), auditLog: auditLog, systemID: id}
}

func trace(steps ...pipeline.Step) json.RawMessage {
	b, _ := json.Marshal(steps)
	return b
}

func (w world) record(t *testing.T, e audit.Entry) {
	t.Helper()
	e.SystemID, e.SystemName = w.systemID, "loan-agent"
	if e.RequestID == "" {
		e.RequestID = "r-" + time.Now().Format("150405.000000000")
	}
	if e.Trace == nil {
		e.Trace = trace()
	}
	if _, err := w.auditLog.Append(context.Background(), e); err != nil {
		t.Fatal(err)
	}
}

func TestBuildFromRealHistory(t *testing.T) {
	w := setup(t)
	ctx := context.Background()
	pii := pipeline.Step{Check: "pii_redaction", Action: pipeline.Modify, Reason: "redacted 1 EMAIL, 1 PERSON"}

	// Four requests: one forwarded with redactions, one blocked, two held
	// for the same reason (each with its own approval).
	w.record(t, audit.Entry{Action: "modify", Model: "mistral-small", Provider: "mistral", Region: "eu",
		PolicyVersion: "v1", Trace: trace(pii)})
	w.record(t, audit.Entry{Action: "block", Check: "policy", Reason: `message mentions blocked term "salary"`, PolicyVersion: "v1"})
	w.record(t, audit.Entry{RequestID: "held-1", Action: "hold", Check: "policy",
		Reason: "credit decisions need human review (approval 1111)", PolicyVersion: "v2", Trace: trace(pii)})
	w.record(t, audit.Entry{Action: "hold", Check: "policy",
		Reason: "credit decisions need human review (approval 2222)", PolicyVersion: "v2"})
	// What came back, and a reviewer's decision: not requests.
	w.record(t, audit.Entry{Action: "hold", Check: "tool_calls", Reason: "refunds need review"})
	w.record(t, audit.Entry{Action: "flag", Check: "response", Reason: "found after the answer was streamed"})
	w.record(t, audit.Entry{RequestID: "held-1", Action: "approve", Check: "approval", Reason: "approved by anna"})

	// The approval behind it, decided by a named reviewer.
	keys, _ := vault.NewKeys(make([]byte, 32))
	approvals := approval.NewStore(w.pool, keys, time.Hour)
	apID, err := approvals.Open(ctx, pipeline.Held{RequestID: "held-1-" + w.systemID, SystemID: w.systemID, RequestHash: "h"})
	if err != nil {
		t.Fatal(err)
	}
	rv, _, _ := approvals.CreateReviewer(ctx, "anna-"+time.Now().Format("150405.000000000"))
	a, _, _ := approvals.Get(ctx, apID)
	if _, err := approvals.Decide(ctx, apID, rv.ID, true, a.ContentHash, ""); err != nil {
		t.Fatal(err)
	}

	usageStore := usage.NewStore(w.pool)
	usageStore.Record(ctx, usage.Record{RequestID: "u-" + w.systemID, SystemID: w.systemID, Model: "mistral-small",
		Provider: "mistral", Usage: usage.Usage{TotalTokens: 321}})

	now := time.Now().UTC()
	rep, err := w.builder.Build(ctx, w.systemID, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	if rep.System.RiskTier != "high" || rep.System.Owner != "credit-team" {
		t.Errorf("system = %+v", rep.System)
	}
	if rep.Requests.Total != 4 || rep.Requests.ByDecision["modify"] != 1 || rep.Requests.ByDecision["block"] != 1 || rep.Requests.ByDecision["hold"] != 2 {
		t.Errorf("requests = %+v; tool calls, answers and approvals must not count as requests", rep.Requests)
	}
	if top := rep.Requests.TopReasons[0]; top.Name != "credit decisions need human review" || top.Count != 2 {
		t.Errorf("top reason = %+v; two holds with different approvals are one reason", top)
	}
	if rep.PersonalData.RequestsRedacted != 2 || rep.PersonalData.ByKind["PERSON"] != 2 || rep.PersonalData.ByKind["EMAIL"] != 2 {
		t.Errorf("personal data = %+v", rep.PersonalData)
	}
	if len(rep.Routing) != 1 || rep.Routing[0].Region != "eu" || rep.Routing[0].Requests != 1 {
		t.Errorf("routing = %+v; only forwarded requests go somewhere", rep.Routing)
	}
	if rep.Answers.ToolCalls["hold"] != 1 || rep.Answers.Text["flag"] != 1 {
		t.Errorf("answers = %+v", rep.Answers)
	}
	if len(rep.Oversight.Reviewers) != 1 || rep.Oversight.Reviewers[0].Approved != 1 || rep.Oversight.DecisionsLogged != 1 ||
		rep.Oversight.MedianToDecide == "" {
		t.Errorf("oversight = %+v", rep.Oversight)
	}
	if rep.Usage.TotalTokens != 321 || rep.Usage.Budget == nil || *rep.Usage.Budget != 100000 {
		t.Errorf("usage = %+v", rep.Usage)
	}
	if len(rep.PolicyVersions) != 2 {
		t.Errorf("policy versions = %v, want v1 and v2", rep.PolicyVersions)
	}
	if !rep.Integrity.ChainOK || rep.Integrity.HeadHash == "" || rep.Integrity.SystemEntries != 7 {
		t.Errorf("integrity = %+v", rep.Integrity)
	}

	// A period before any of this happened is empty.
	old, _ := w.builder.Build(ctx, w.systemID, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if old.Requests.Total != 0 || old.Integrity.SystemEntries != 0 {
		t.Errorf("earlier period: %+v", old.Requests)
	}
}

type failingRecorder struct{}

func (failingRecorder) Record(context.Context, audit.Entry) error { return errors.New("db down") }

func TestHandler(t *testing.T) {
	w := setup(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := Handler(w.builder, w.auditLog, log)
	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}

	// A system name with markup: the HTML page must show it, not run it.
	w.pool.Exec(context.Background(), "UPDATE ai_systems SET purpose = '<script>alert(1)</script>' WHERE id = $1", w.systemID)
	page := get(h, "/admin/reports/systems/"+w.systemID+"?format=html")
	if page.Code != 200 || !strings.Contains(page.Body.String(), "&lt;script&gt;") || strings.Contains(page.Body.String(), "<script>alert") {
		t.Errorf("html: %d, escaped=%v", page.Code, strings.Contains(page.Body.String(), "&lt;script&gt;"))
	}

	// JSON: sealed, recorded, and checkable later.
	rec := get(h, "/admin/reports/systems/"+w.systemID)
	var rep Report
	json.Unmarshal(rec.Body.Bytes(), &rep)
	if rec.Code != 200 || !Intact(rep) {
		t.Fatalf("json: %d, intact=%v", rec.Code, Intact(rep))
	}
	verify := func(body []byte) map[string]bool {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest("POST", "/admin/reports/verify", strings.NewReader(string(body))))
		var out map[string]bool
		json.Unmarshal(r.Body.Bytes(), &out)
		return out
	}
	if got := verify(rec.Body.Bytes()); !got["intact"] || !got["recorded"] {
		t.Errorf("verify unchanged report = %v, want intact and recorded", got)
	}
	rep.Requests.Total += 10 // edited after the fact
	edited, _ := json.Marshal(rep)
	if got := verify(edited); got["intact"] {
		t.Errorf("verify edited report = %v, want not intact", got)
	}

	for path, want := range map[string]int{
		"/admin/reports/systems/00000000-0000-0000-0000-000000000000":             404,
		"/admin/reports/systems/not-a-uuid":                                       404,
		"/admin/reports/systems/" + w.systemID + "?from=yesterday":                400,
		"/admin/reports/systems/" + w.systemID + "?from=2026-12-01&to=2026-11-01": 400,
		"/admin/reports/systems/" + w.systemID + "?format=pdf":                    400,
	} {
		if got := get(h, path).Code; got != want {
			t.Errorf("%s: %d, want %d", path, got, want)
		}
	}

	// No audit record, no report.
	if got := get(Handler(w.builder, failingRecorder{}, log), "/admin/reports/systems/"+w.systemID).Code; got != 503 {
		t.Errorf("audit log down: %d, want 503", got)
	}
}
