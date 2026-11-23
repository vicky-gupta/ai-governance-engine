package toolguard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/policy"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// fakePolicy denies "drop_database", holds "issue_refund", allows the rest,
// and remembers the input it was given.
type fakePolicy struct {
	input map[string]any
	err   error
}

func (f *fakePolicy) EvaluateToolCalls(_ context.Context, input map[string]any) (policy.ToolResult, string, error) {
	f.input = input
	if f.err != nil {
		return policy.ToolResult{}, "v1", f.err
	}
	var res policy.ToolResult
	for _, c := range input["tool_calls"].([]any) {
		switch c.(map[string]any)["name"] {
		case "drop_database":
			res.Deny = append(res.Deny, "drop_database is not approved")
		case "issue_refund":
			res.Hold = append(res.Hold, "refunds need review")
		}
	}
	return res, "v1", nil
}

type fakeRecorder struct {
	entries []audit.Entry
	err     error
}

func (f *fakeRecorder) Record(_ context.Context, e audit.Entry) error {
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, e)
	return nil
}

const withTools = `{"model":"m","messages":[{"role":"user","content":"hi"}],
	"tools":[{"type":"function","function":{"name":"get_order_status"}}]}`

// run sends one request through the guard to a fake provider that answers
// with contentType and body.
func run(t *testing.T, p Policy, rec Recorder, reqBody, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := pipeline.ParseRequest([]byte(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.ID = "req-1"
	req.System = registry.System{ID: "sys-1", Name: "support-bot", RiskTier: registry.RiskLimited}

	provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		for _, piece := range strings.SplitAfter(body, "\n") {
			io.WriteString(w, piece)
			http.NewResponseController(w).Flush()
		}
	})
	h := Middleware(p, rec, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))(provider)

	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r = r.WithContext(pipeline.WithRequest(r.Context(), req))
	w := httptest.NewRecorder()
	w.Header().Set("X-Request-ID", "req-1")
	w.Header().Set("X-Aigov-Decision", "allow")
	h.ServeHTTP(w, r)
	return w
}

func jsonResponse(calls ...string) string {
	tc := []string{}
	for _, c := range calls {
		tc = append(tc, `{"id":"call_1","type":"function","function":{"name":"`+c+`","arguments":"{\"amount\":250}"}}`)
	}
	return `{"model":"m","choices":[{"message":{"role":"assistant","content":null,"tool_calls":[` +
		strings.Join(tc, ",") + `]}}]}`
}

func TestAllowedToolCallPassesThroughAndIsAudited(t *testing.T) {
	rec := &fakeRecorder{}
	body := jsonResponse("get_order_status")
	w := run(t, &fakePolicy{}, rec, withTools, "application/json", body)

	if w.Code != http.StatusOK || w.Body.String() != body {
		t.Fatalf("got %d %s, want the provider's response unchanged", w.Code, w.Body)
	}
	if len(rec.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(rec.entries))
	}
	e := rec.entries[0]
	if e.RequestID != "req-1" || e.Check != "tool_calls" || e.Action != "allow" || !strings.Contains(e.Reason, "get_order_status") {
		t.Errorf("audit entry = %+v", e)
	}
}

func TestBlockedAndHeldToolCalls(t *testing.T) {
	tests := []struct {
		tool, wantType, wantDecision, wantAction string
	}{
		{"drop_database", "policy_violation", "block", "block"},
		{"issue_refund", "approval_required", "hold", "hold"},
	}
	for _, tc := range tests {
		t.Run(tc.tool, func(t *testing.T) {
			rec := &fakeRecorder{}
			w := run(t, &fakePolicy{}, rec, withTools, "application/json", jsonResponse(tc.tool))

			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", w.Code)
			}
			var got struct {
				Error struct{ Type string } `json:"error"`
			}
			json.Unmarshal(w.Body.Bytes(), &got)
			if got.Error.Type != tc.wantType {
				t.Errorf("error type = %q, want %q (body %s)", got.Error.Type, tc.wantType, w.Body)
			}
			if strings.Contains(w.Body.String(), "tool_calls") {
				t.Error("the blocked tool call leaked to the caller")
			}
			if w.Header().Get("X-Aigov-Decision") != tc.wantDecision || w.Header().Get("X-Request-ID") != "req-1" {
				t.Errorf("headers = %v", w.Header())
			}
			if len(rec.entries) != 1 || rec.entries[0].Action != tc.wantAction {
				t.Errorf("audit = %+v, want one %s entry", rec.entries, tc.wantAction)
			}
		})
	}
}

func TestStreamedToolCallIsReassembled(t *testing.T) {
	// The arguments of one call arrive in three pieces across chunks.
	stream := `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"drop_database","arguments":""}}]}}]}
data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"tab"}}]}}]}
data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"le\":\"users\"}"}}]}}]}
data: [DONE]
`
	p := &fakePolicy{}
	w := run(t, p, &fakeRecorder{}, withTools, "text/event-stream", stream)

	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "data:") {
		t.Fatalf("got %d %s, want 403 and no stream data", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q; the provider's stream header must be replaced", ct)
	}
	call := p.input["tool_calls"].([]any)[0].(map[string]any)
	args, _ := call["arguments"].(map[string]any)
	if args["table"] != "users" {
		t.Errorf("arguments = %v, want the pieces joined into {table: users}", call["arguments"])
	}
}

func TestPassesThroughWithoutChecking(t *testing.T) {
	tests := []struct {
		name, reqBody, body string
	}{
		{"no tools offered", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`, jsonResponse("drop_database")},
		{"text answer", withTools, `{"choices":[{"message":{"role":"assistant","content":"Your order is on its way."}}]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, rec := &fakePolicy{}, &fakeRecorder{}
			w := run(t, p, rec, tc.reqBody, "application/json", tc.body)
			if w.Code != http.StatusOK || w.Body.String() != tc.body {
				t.Errorf("got %d %s, want the response unchanged", w.Code, w.Body)
			}
			if p.input != nil || len(rec.entries) != 0 {
				t.Error("policy or audit was called for a response without tool calls")
			}
		})
	}
}

func TestFailsClosed(t *testing.T) {
	t.Run("policy error blocks", func(t *testing.T) {
		rec := &fakeRecorder{}
		w := run(t, &fakePolicy{err: errors.New("broken")}, rec, withTools, "application/json", jsonResponse("get_order_status"))
		if w.Code != http.StatusForbidden || len(rec.entries) != 1 || rec.entries[0].Action != "block" {
			t.Errorf("status %d, audit %+v; want 403 and a block entry", w.Code, rec.entries)
		}
	})
	t.Run("audit failure withholds the response", func(t *testing.T) {
		w := run(t, &fakePolicy{}, &fakeRecorder{err: errors.New("db down")}, withTools, "application/json", jsonResponse("get_order_status"))
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "get_order_status") {
			t.Errorf("got %d %s, want 503 without the tool call", w.Code, w.Body)
		}
	})
	t.Run("invalid arguments reach the policy as null", func(t *testing.T) {
		p := &fakePolicy{}
		body := `{"choices":[{"message":{"tool_calls":[{"function":{"name":"get_order_status","arguments":"{not json"}}]}}]}`
		run(t, p, &fakeRecorder{}, withTools, "application/json", body)
		if call := p.input["tool_calls"].([]any)[0].(map[string]any); call["arguments"] != nil {
			t.Errorf("arguments = %v, want nil so the policy can reject them", call["arguments"])
		}
	})
}
