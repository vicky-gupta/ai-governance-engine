package policy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/tester"
)

const policyDir = "../../policies"

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRegoUnitTests runs the tests written in Rego (policies/*_test.rego),
// so CI fails if a policy change breaks them.
func TestRegoUnitTests(t *testing.T) {
	results, err := tester.Run(context.Background(), policyDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("no Rego tests found")
	}
	for _, r := range results {
		if !r.Pass() {
			t.Errorf("%s.%s failed (error: %v)", r.Package, r.Name, r.Error)
		}
	}
}

func TestEvaluateRealPolicy(t *testing.T) {
	e, err := Load(context.Background(), policyDir, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	input := func(tier, text string) map[string]any {
		return map[string]any{
			"system":   map[string]any{"name": "test", "risk_tier": tier},
			"messages": []any{map[string]any{"role": "user", "text": text}},
		}
	}

	res, version, err := e.Evaluate(context.Background(), input("limited", "hello"))
	if err != nil || len(res.Deny) != 0 || len(res.Hold) != 0 || *res.MaxTokens != 4096 {
		t.Errorf("clean: %+v, %v", res, err)
	}
	if version == "" || version != e.Version() {
		t.Errorf("version = %q, want the active version", version)
	}

	res, _, _ = e.Evaluate(context.Background(), input("limited", "the salary bands"))
	if len(res.Deny) != 1 {
		t.Errorf("blocked term: deny = %v", res.Deny)
	}

	res, _, _ = e.Evaluate(context.Background(), input("high", "Approve the credit application"))
	if len(res.Hold) != 1 || *res.MaxTokens != 1024 {
		t.Errorf("credit decision: %+v", res)
	}
}

// writePolicy replaces the policy file in dir.
func writePolicy(t *testing.T, dir, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "p.rego"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReloadKeepsOldVersionWhenNewOneIsBroken(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	writePolicy(t, dir, "package aigov\ndeny contains \"v1\" if true\n")
	e, err := Load(ctx, dir, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	v1 := e.Version()

	// A syntax error: rejected, the old rules keep working.
	writePolicy(t, dir, "package aigov\ndeny contains \"v2\" if {\n")
	e.reload(ctx)
	res, version, _ := e.Evaluate(ctx, map[string]any{})
	if version != v1 || len(res.Deny) != 1 || res.Deny[0] != "v1" {
		t.Errorf("after a broken file: version=%s deny=%v, want v1 still active", version, res.Deny)
	}

	// A valid change: the new version takes over.
	writePolicy(t, dir, "package aigov\ndeny contains \"v3\" if true\n")
	e.reload(ctx)
	res, version, _ = e.Evaluate(ctx, map[string]any{})
	if version == v1 || res.Deny[0] != "v3" {
		t.Errorf("after a valid change: version=%s deny=%v, want v3", version, res.Deny)
	}
}

func TestLoadRefusesBrokenOrMissingPolicy(t *testing.T) {
	ctx := context.Background()
	if _, err := Load(ctx, t.TempDir(), discardLogger()); err == nil {
		t.Error("an empty folder was accepted")
	}
	dir := t.TempDir()
	writePolicy(t, dir, "package aigov\ndeny contains if {\n")
	if _, err := Load(ctx, dir, discardLogger()); err == nil {
		t.Error("a broken policy was accepted")
	}
}

func TestTestFilesAreNotLoadedAsPolicy(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "package aigov\nallow := true\n")
	os.WriteFile(filepath.Join(dir, "p_test.rego"), []byte("package aigov\ndeny contains \"from test file\" if true\n"), 0o644)
	e, err := Load(context.Background(), dir, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	res, _, _ := e.Evaluate(context.Background(), map[string]any{})
	if len(res.Deny) != 0 {
		t.Errorf("rules from a _test.rego file were applied: %v", res.Deny)
	}
}

func TestBadMaxTokensIsAnError(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "package aigov\nmax_tokens := \"lots\"\n")
	e, err := Load(context.Background(), dir, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.Evaluate(context.Background(), map[string]any{}); err == nil {
		t.Error("a non-numeric max_tokens was accepted")
	}
}
func TestEvaluateToolCallsRealPolicy(t *testing.T) {
	e, err := Load(context.Background(), policyDir, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	input := func(name string, args any) map[string]any {
		return map[string]any{
			"system":     map[string]any{"name": "support-bot", "risk_tier": "limited"},
			"tool_calls": []any{map[string]any{"name": name, "arguments": args}},
		}
	}

	res, version, err := e.EvaluateToolCalls(context.Background(), input("get_order_status", map[string]any{"order_id": "A-1"}))
	if err != nil || len(res.Deny) != 0 || len(res.Hold) != 0 || version != e.Version() {
		t.Errorf("approved call: %+v, %q, %v", res, version, err)
	}
	if res, _, _ := e.EvaluateToolCalls(context.Background(), input("drop_database", map[string]any{})); len(res.Deny) != 1 {
		t.Errorf("unapproved call: deny = %v", res.Deny)
	}
	// Arguments arrive from Go as float64; the policy must still compare them.
	if res, _, _ := e.EvaluateToolCalls(context.Background(), input("issue_refund", map[string]any{"amount": 250.0})); len(res.Hold) != 1 {
		t.Errorf("large refund: hold = %v", res.Hold)
	}
}
