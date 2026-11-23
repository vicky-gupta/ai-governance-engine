package checks

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/catalog"
	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/policy"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

func request(t *testing.T, body string) *pipeline.Request {
	t.Helper()
	req, err := pipeline.ParseRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestModelPolicy(t *testing.T) {
	cat, err := catalog.Parse([]byte(`{
		"providers": [
			{"name":"groq","base_url":"https://api.groq.com/openai","api_key_env":"G","region":"us","models":["llama"]},
			{"name":"mistral","base_url":"https://api.mistral.ai","api_key_env":"M","region":"eu","models":["mistral-small"]}
		],
		"allowed_regions": {"minimal":["eu","us"], "limited":["eu","us"], "high":["eu"]}
	}`), func(string) string { return "key" })
	if err != nil {
		t.Fatal(err)
	}
	c := ModelPolicy{Catalog: cat}

	cases := []struct {
		name         string
		tier         registry.RiskTier
		model        string
		action       pipeline.Action
		wantProvider string
	}{
		{"approved model, allowed region", registry.RiskLimited, "llama", pipeline.Allow, "groq"},
		{"high risk, EU model", registry.RiskHigh, "mistral-small", pipeline.Allow, "mistral"},
		{"high risk, US model", registry.RiskHigh, "llama", pipeline.Block, ""},
		{"unknown model", registry.RiskMinimal, "gpt-unapproved", pipeline.Block, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := request(t, `{"model":"`+tc.model+`","messages":[{"role":"user","content":"hi"}]}`)
			req.System = registry.System{Name: "test", RiskTier: tc.tier}
			d := c.Check(context.Background(), req)
			if d.Action != tc.action || req.Provider != tc.wantProvider {
				t.Errorf("action=%s provider=%q (%s), want %s and %q", d.Action, req.Provider, d.Reason, tc.action, tc.wantProvider)
			}
		})
	}
}
func TestPIIRedaction(t *testing.T) {
	c := PIIRedaction{}
	ctx := context.Background()

	clean := request(t, `{"model":"m","messages":[{"role":"user","content":"What are your opening hours?"}]}`)
	if d := c.Check(ctx, clean); d.Action != pipeline.Allow {
		t.Errorf("clean request: %s, want allow", d.Action)
	}

	req := request(t, `{"model":"m","messages":[
		{"role":"system","content":"You help with payments."},
		{"role":"user","content":"Move 500 EUR from DE89 3704 0044 0532 0130 00 and confirm to anna@example.com"},
		{"role":"user","content":[{"type":"text","text":"Is DE89370400440532013000 correct?"}]}
	]}`)
	d := c.Check(ctx, req)
	if d.Action != pipeline.Modify || d.Reason != "redacted 1 EMAIL, 1 IBAN" {
		t.Fatalf("got %s %q, want modify with a summary", d.Action, d.Reason)
	}

	out, _ := req.Encode()
	body := string(out)
	for _, leaked := range []string{"DE89", "3704", "anna@example.com"} {
		if strings.Contains(body, leaked) {
			t.Errorf("%q reached the forwarded body: %s", leaked, body)
		}
	}
	// The same IBAN in two messages gets the same token.
	if strings.Count(body, "[IBAN_1]") != 2 || strings.Contains(body, "[IBAN_2]") {
		t.Errorf("tokens not consistent across messages: %s", body)
	}
	if strings.Contains(d.Reason, "anna") {
		t.Error("the reason contains a personal value")
	}
}

// fakeVault records what it was asked to save, or fails if err is set.
type fakeVault struct {
	requestID string
	saved     []pii.Replacement
	err       error
}

func (f *fakeVault) Save(_ context.Context, requestID string, reps []pii.Replacement) error {
	f.requestID, f.saved = requestID, reps
	return f.err
}

func TestPIIRedactionSavesToVault(t *testing.T) {
	v := &fakeVault{}
	req := request(t, `{"model":"m","messages":[{"role":"user","content":"Mail anna@example.com about DE89 3704 0044 0532 0130 00"}]}`)
	req.ID = "req-42"

	d := PIIRedaction{Vault: v}.Check(context.Background(), req)
	if d.Action != pipeline.Modify {
		t.Fatalf("action = %s, want modify", d.Action)
	}
	if v.requestID != "req-42" || len(v.saved) != 2 || v.saved[0].Value != "anna@example.com" {
		t.Errorf("vault got request %q, values %+v", v.requestID, v.saved)
	}

	// Nothing to redact: the vault isn't called.
	v2 := &fakeVault{}
	clean := request(t, `{"model":"m","messages":[{"role":"user","content":"hello"}]}`)
	PIIRedaction{Vault: v2}.Check(context.Background(), clean)
	if v2.requestID != "" {
		t.Error("vault was called for a clean request")
	}
}

func TestPIIRedactionBlocksWhenVaultFails(t *testing.T) {
	v := &fakeVault{err: errors.New("database down")}
	req := request(t, `{"model":"m","messages":[{"role":"user","content":"Mail anna@example.com"}]}`)
	if d := (PIIRedaction{Vault: v}).Check(context.Background(), req); d.Action != pipeline.Block {
		t.Errorf("action = %s, want block", d.Action)
	}
}
func TestPolicyWithRealRules(t *testing.T) {
	engine, err := policy.Load(context.Background(), "../../policies", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c := Policy{Engine: engine}

	cases := []struct {
		name          string
		tier          registry.RiskTier
		body          string
		action        pipeline.Action
		wantMaxTokens int
	}{
		{"within limit", registry.RiskLimited,
			`{"model":"m","max_tokens":200,"messages":[{"role":"user","content":"hi"}]}`, pipeline.Allow, 200},
		{"no limit set", registry.RiskLimited,
			`{"model":"m","messages":[{"role":"user","content":"hi"}]}`, pipeline.Modify, 4096},
		{"high risk gets a lower limit", registry.RiskHigh,
			`{"model":"m","max_tokens":3000,"messages":[{"role":"user","content":"hi"}]}`, pipeline.Modify, 1024},
		{"blocked term", registry.RiskLimited,
			`{"model":"m","max_tokens":200,"messages":[{"role":"user","content":"Our salary bands?"}]}`, pipeline.Block, 200},
		{"credit decision", registry.RiskHigh,
			`{"model":"m","max_tokens":200,"messages":[{"role":"user","content":"Reject the loan application"}]}`, pipeline.Hold, 200},
		{"held request is still capped", registry.RiskHigh,
			`{"model":"m","messages":[{"role":"user","content":"Reject the loan application"}]}`, pipeline.Hold, 1024},
		{"approved tool", registry.RiskLimited,
			`{"model":"m","max_tokens":200,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"get_order_status"}}]}`, pipeline.Allow, 200},
		{"unapproved tool", registry.RiskLimited,
			`{"model":"m","max_tokens":200,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"delete_customer"}}]}`, pipeline.Block, 200},
		{"unapproved tool as a legacy function", registry.RiskLimited,
			`{"model":"m","max_tokens":200,"messages":[{"role":"user","content":"hi"}],"functions":[{"name":"delete_customer"}]}`, pipeline.Block, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := request(t, tc.body)
			req.System = registry.System{Name: "support-bot", RiskTier: tc.tier}
			d := c.Check(context.Background(), req)
			if d.Action != tc.action || *req.MaxTokens != tc.wantMaxTokens {
				t.Errorf("action=%s max_tokens=%d (%s), want %s and %d", d.Action, *req.MaxTokens, d.Reason, tc.action, tc.wantMaxTokens)
			}
			if req.PolicyVersion != engine.Version() {
				t.Errorf("PolicyVersion = %q, want %q", req.PolicyVersion, engine.Version())
			}
		})
	}
}

// brokenEngine always fails, like a policy that errors at runtime.
type brokenEngine struct{}

func (brokenEngine) Evaluate(context.Context, map[string]any) (policy.Result, string, error) {
	return policy.Result{}, "v-broken", errors.New("boom")
}

func TestPolicyFailsClosed(t *testing.T) {
	req := request(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`)
	if d := (Policy{Engine: brokenEngine{}}).Check(context.Background(), req); d.Action != pipeline.Block {
		t.Errorf("action = %s, want block", d.Action)
	}
}

// fakeUsage returns a fixed amount used, or fails if err is set.
type fakeUsage struct {
	used int64
	err  error
}

func (f fakeUsage) UsedThisMonth(context.Context, string, time.Time) (int64, error) {
	return f.used, f.err
}

func TestTokenBudget(t *testing.T) {
	budget := int64(1000)
	withBudget := registry.System{ID: "sys-1", MonthlyTokenBudget: &budget}
	now := func() time.Time { return time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC) }
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`

	tests := []struct {
		name   string
		system registry.System
		usage  fakeUsage
		want   pipeline.Action
	}{
		{"no budget", registry.System{ID: "sys-2"}, fakeUsage{err: errors.New("never asked")}, pipeline.Allow},
		{"under budget", withBudget, fakeUsage{used: 999}, pipeline.Allow},
		{"budget used up", withBudget, fakeUsage{used: 1000}, pipeline.Block},
		{"usage unknown", withBudget, fakeUsage{err: errors.New("database down")}, pipeline.Block},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := request(t, body)
			req.System = tc.system
			d := TokenBudget{Usage: tc.usage, Now: now}.Check(context.Background(), req)
			if d.Action != tc.want {
				t.Errorf("action = %s (%s), want %s", d.Action, d.Reason, tc.want)
			}
			if tc.name == "budget used up" && !strings.Contains(d.Reason, "1 December 2026") {
				t.Errorf("reason %q should say when the budget resets", d.Reason)
			}
		})
	}
}

func TestTokenBudgetTurnsOnStreamUsage(t *testing.T) {
	check := TokenBudget{Usage: fakeUsage{}}

	req := request(t, `{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	if d := check.Check(context.Background(), req); d.Action != pipeline.Modify {
		t.Fatalf("stream without usage: action = %s, want modify", d.Action)
	}
	out, _ := req.Encode()
	if !strings.Contains(string(out), `"stream_options":{"include_usage":true}`) {
		t.Errorf("forwarded body %s should ask for stream usage", out)
	}

	// Already asked for, or not streaming: nothing to change.
	for _, body := range []string{
		`{"model":"m","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`,
		`{"model":"m","messages":[{"role":"user","content":"hi"}]}`,
	} {
		if d := check.Check(context.Background(), request(t, body)); d.Action != pipeline.Allow {
			t.Errorf("%s: action = %s, want allow", body, d.Action)
		}
	}
}
