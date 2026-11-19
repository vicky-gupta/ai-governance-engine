package usage

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

type fakeRecorder struct {
	records []Record
	err     error
}

func (f *fakeRecorder) Record(_ context.Context, r Record) error {
	if f.err != nil {
		return f.err
	}
	f.records = append(f.records, r)
	return nil
}

// serve runs the meter in front of a fake provider that answers with
// contentType and the given body pieces, flushing after each one.
func serve(t *testing.T, rec Recorder, status int, contentType string, pieces ...string) *httptest.ResponseRecorder {
	t.Helper()
	provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		for _, p := range pieces {
			io.WriteString(w, p)
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Errorf("flush through the meter failed: %v", err)
			}
		}
	})
	h := Middleware(rec, slog.New(slog.NewTextHandler(io.Discard, nil)))(provider)
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	req = req.WithContext(auth.WithSystem(req.Context(), registry.System{ID: "sys-1", Name: "support-bot"}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestMeterJSONResponse(t *testing.T) {
	rec := &fakeRecorder{}
	body := `{"id":"x","model":"llama-3.1-8b-instant","choices":[],` +
		`"usage":{"prompt_tokens":12,"completion_tokens":30,"total_tokens":42}}`
	w := serve(t, rec, 200, "application/json", body[:20], body[20:])

	if w.Body.String() != body {
		t.Errorf("caller got %q, want the provider's response unchanged", w.Body)
	}
	if len(rec.records) != 1 {
		t.Fatalf("recorded %d, want 1", len(rec.records))
	}
	got := rec.records[0]
	if got.SystemID != "sys-1" || got.Model != "llama-3.1-8b-instant" || got.TotalTokens != 42 || got.PromptTokens != 12 {
		t.Errorf("recorded %+v", got)
	}
}

func TestMeterStream(t *testing.T) {
	tests := map[string]string{
		// OpenAI with stream_options.include_usage: a last chunk with usage.
		"openai": `data: {"model":"gpt","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}` + "\n\n",
		// Groq: usage in x_groq on the last content chunk.
		"groq": `data: {"model":"gpt","choices":[{"delta":{}}],"x_groq":{"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}}` + "\n\n",
	}
	for name, last := range tests {
		t.Run(name, func(t *testing.T) {
			rec := &fakeRecorder{}
			pieces := []string{
				`data: {"model":"gpt","choices":[{"delta":{"content":"Hel"}}]}` + "\n\n",
				`data: {"model":"gpt","choices":[{"delta":{"content":"lo"}}]}` + "\n\n",
				// A chunk split across two writes must still be read correctly.
				last[:30], last[30:],
				"data: [DONE]\n\n",
			}
			w := serve(t, rec, 200, "text/event-stream", pieces...)
			if !strings.Contains(w.Body.String(), "[DONE]") {
				t.Error("stream did not reach the caller")
			}
			if len(rec.records) != 1 || rec.records[0].TotalTokens != 12 || rec.records[0].CompletionTokens != 7 {
				t.Errorf("recorded %+v, want 12 total tokens", rec.records)
			}
		})
	}
}

func TestMeterSkips(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{"provider error", 500, `{"error":{"message":"boom"},"usage":{"total_tokens":5}}`},
		{"no usage in response", 200, `{"model":"m","choices":[]}`},
		{"not JSON", 200, `oops`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := &fakeRecorder{}
			w := serve(t, rec, tc.status, "application/json", tc.body)
			if w.Code != tc.status || w.Body.String() != tc.body {
				t.Errorf("caller got %d %q, want the provider's response unchanged", w.Code, w.Body)
			}
			if len(rec.records) != 0 {
				t.Errorf("recorded %+v, want nothing", rec.records)
			}
		})
	}
}

func TestMeterRecordFailureDoesNotBreakResponse(t *testing.T) {
	rec := &fakeRecorder{err: errors.New("database down")}
	body := `{"model":"m","usage":{"total_tokens":3}}`
	if w := serve(t, rec, 200, "application/json", body); w.Code != 200 || w.Body.String() != body {
		t.Errorf("caller got %d %q; the response must be unaffected", w.Code, w.Body)
	}
}
