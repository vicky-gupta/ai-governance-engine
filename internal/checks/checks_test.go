package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/catalog"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
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

func TestBlockedTerms(t *testing.T) {
	c := BlockedTerms{Terms: []string{"Project Falcon", "salary"}}
	ctx := context.Background()

	clean := request(t, `{"model":"m","messages":[{"role":"user","content":"What is the weather?"}]}`)
	if d := c.Check(ctx, clean); d.Action != pipeline.Allow {
		t.Errorf("clean message: %s, want allow", d.Action)
	}

	// Case-insensitive, and found in any message.
	dirty := request(t, `{"model":"m","messages":[
		{"role":"system","content":"You are helpful."},
		{"role":"user","content":"Summarise the project falcon roadmap"}]}`)
	if d := c.Check(ctx, dirty); d.Action != pipeline.Block {
		t.Errorf("blocked term: %s, want block", d.Action)
	}
}

func TestMaxTokens(t *testing.T) {
	c := MaxTokens{Limit: 1000}
	ctx := context.Background()

	cases := []struct {
		name      string
		body      string
		action    pipeline.Action
		wantLimit int
	}{
		{"under limit", `{"model":"m","max_tokens":200,"messages":[{"role":"user","content":"hi"}]}`, pipeline.Allow, 200},
		{"at limit", `{"model":"m","max_tokens":1000,"messages":[{"role":"user","content":"hi"}]}`, pipeline.Allow, 1000},
		{"over limit", `{"model":"m","max_tokens":5000,"messages":[{"role":"user","content":"hi"}]}`, pipeline.Modify, 1000},
		{"missing", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, pipeline.Modify, 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := request(t, tc.body)
			d := c.Check(ctx, req)
			if d.Action != tc.action || *req.MaxTokens != tc.wantLimit {
				t.Errorf("action=%s max_tokens=%d, want %s and %d", d.Action, *req.MaxTokens, tc.action, tc.wantLimit)
			}
		})
	}
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
