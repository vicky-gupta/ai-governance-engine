package outputguard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/policy"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// A real, checksum-valid example IBAN.
const iban = "DE89 3704 0044 0532 0130 00"

// fakePolicy denies answers that mention "falcon" and remembers its input.
type fakePolicy struct {
	input map[string]any
	err   error
}

func (f *fakePolicy) EvaluateResponse(_ context.Context, input map[string]any) (policy.ResponseResult, string, error) {
	f.input = input
	if f.err != nil {
		return policy.ResponseResult{}, "v1", f.err
	}
	if strings.Contains(strings.ToLower(input["text"].(string)), "falcon") {
		return policy.ResponseResult{Deny: []string{`the answer mentions "falcon"`}}, "v1", nil
	}
	return policy.ResponseResult{}, "v1", nil
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

// run sends a request through the guard to a fake provider that answers
// with status, contentType and body, written in pieces.
func run(t *testing.T, p Policy, rec Recorder, status int, contentType, body string) *httptest.ResponseRecorder {
	t.Helper()
	req, _ := pipeline.ParseRequest([]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	req.ID = "req-1"
	req.System = registry.System{ID: "sys-1", Name: "support-bot", RiskTier: registry.RiskLimited}

	provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(status)
		for _, piece := range strings.SplitAfter(body, "\n") {
			io.WriteString(w, piece)
			http.NewResponseController(w).Flush()
		}
	})
	h := Middleware(p, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))(provider)
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r = r.WithContext(pipeline.WithRequest(r.Context(), req))
	w := httptest.NewRecorder()
	w.Header().Set("X-Request-ID", "req-1")
	h.ServeHTTP(w, r)
	return w
}

func answerJSON(text string) string {
	b, _ := json.Marshal(text)
	return `{"id":"x","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":` +
		string(b) + `}}],"usage":{"total_tokens":7},"x_provider_field":1}`
}

func content(t *testing.T, body string) string {
	t.Helper()
	var resp struct {
		Choices []struct {
			Message struct{ Content string } `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil || len(resp.Choices) == 0 {
		t.Fatalf("not an answer: %s", body)
	}
	return resp.Choices[0].Message.Content
}

func TestCleanAnswerPassesUnchanged(t *testing.T) {
	rec := &fakeRecorder{}
	// [EMAIL_1] is a token from the request: not personal data.
	body := answerJSON("I wrote to [EMAIL_1]; your order ships today.")
	w := run(t, &fakePolicy{}, rec, 200, "application/json", body)
	if w.Code != 200 || w.Body.String() != body {
		t.Errorf("got %d %s, want the answer unchanged", w.Code, w.Body)
	}
	if len(rec.entries) != 0 {
		t.Errorf("audit = %+v; clean answers are not recorded", rec.entries)
	}
}

func TestPersonalDataIsRemoved(t *testing.T) {
	rec, p := &fakeRecorder{}, &fakePolicy{}
	w := run(t, p, rec, 200, "application/json", answerJSON("Pay to "+iban+" or mail max@example.de, ref [EMAIL_1]."))

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	got := content(t, w.Body.String())
	if want := "Pay to [REDACTED_IBAN] or mail [REDACTED_EMAIL], ref [EMAIL_1]."; got != want {
		t.Errorf("content = %q\nwant      %q", got, want)
	}
	if !strings.Contains(w.Body.String(), `"x_provider_field":1`) {
		t.Error("fields the gateway doesn't know about were lost")
	}
	if cl := w.Header().Get("Content-Length"); cl != strconv.Itoa(w.Body.Len()) {
		t.Errorf("Content-Length = %s, body is %d bytes", cl, w.Body.Len())
	}
	if w.Header().Get("X-Aigov-Decision") != "modify" {
		t.Errorf("X-Aigov-Decision = %q, want modify", w.Header().Get("X-Aigov-Decision"))
	}
	if len(rec.entries) != 1 || rec.entries[0].Action != "modify" || rec.entries[0].Check != "response" {
		t.Fatalf("audit = %+v, want one modify entry", rec.entries)
	}
	if r := rec.entries[0].Reason; strings.Contains(r, "3704") || strings.Contains(r, "max@") {
		t.Errorf("audit reason %q contains the personal data itself", r)
	}
	if kinds := p.input["pii"].([]string); len(kinds) != 2 {
		t.Errorf("policy saw pii = %v, want [EMAIL IBAN]", kinds)
	}
}

func TestDeniedAnswerIsBlocked(t *testing.T) {
	rec := &fakeRecorder{}
	w := run(t, &fakePolicy{}, rec, 200, "application/json", answerJSON("Project Falcon launches in May."))
	if w.Code != 403 || strings.Contains(w.Body.String(), "May") {
		t.Fatalf("got %d %s, want 403 without the answer", w.Code, w.Body)
	}
	if w.Header().Get("X-Aigov-Decision") != "block" || w.Header().Get("X-Request-ID") != "req-1" {
		t.Errorf("headers = %v", w.Header())
	}
	if len(rec.entries) != 1 || rec.entries[0].Action != "block" {
		t.Errorf("audit = %+v, want one block entry", rec.entries)
	}
}

func TestFailsClosed(t *testing.T) {
	t.Run("policy error blocks", func(t *testing.T) {
		w := run(t, &fakePolicy{err: errors.New("broken")}, &fakeRecorder{}, 200, "application/json", answerJSON("hello"))
		if w.Code != 403 {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})
	t.Run("audit failure withholds the answer", func(t *testing.T) {
		w := run(t, &fakePolicy{}, &fakeRecorder{err: errors.New("db down")}, 200, "application/json", answerJSON("IBAN "+iban))
		if w.Code != 503 || strings.Contains(w.Body.String(), "3704") {
			t.Errorf("got %d %s, want 503 without the IBAN", w.Code, w.Body)
		}
	})
}

func TestStreamPassesThroughAndIsCheckedAfterwards(t *testing.T) {
	stream := `data: {"choices":[{"index":0,"delta":{"content":"Pay to DE89 3704 "}}]}
data: {"choices":[{"index":0,"delta":{"content":"0044 0532 0130 00 today."}}]}
data: [DONE]
`
	rec := &fakeRecorder{}
	w := run(t, &fakePolicy{}, rec, 200, "text/event-stream", stream)

	if w.Body.String() != stream {
		t.Errorf("stream was changed: %s", w.Body)
	}
	// The IBAN was split across two chunks; the check still finds it.
	if len(rec.entries) != 1 || rec.entries[0].Action != "flag" || !strings.Contains(rec.entries[0].Reason, "IBAN") {
		t.Errorf("audit = %+v, want one flag entry naming IBAN", rec.entries)
	}

	clean := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: [DONE]\n\n"
	rec = &fakeRecorder{}
	run(t, &fakePolicy{}, rec, 200, "text/event-stream", clean)
	if len(rec.entries) != 0 {
		t.Errorf("clean stream recorded: %+v", rec.entries)
	}
}

func TestNotChecked(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"provider error", 500, `{"error":{"message":"IBAN ` + iban + `"}}`},
		{"only tool calls", 200, `{"choices":[{"message":{"content":null,"tool_calls":[{"function":{"name":"x","arguments":"{}"}}]}}]}`},
		{"not JSON", 200, "oops"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, rec := &fakePolicy{}, &fakeRecorder{}
			w := run(t, p, rec, tc.status, "application/json", tc.body)
			if w.Code != tc.status || w.Body.String() != tc.body {
				t.Errorf("got %d %s, want it unchanged", w.Code, w.Body)
			}
			if p.input != nil || len(rec.entries) != 0 {
				t.Error("checked or recorded something that should pass through")
			}
		})
	}
}
