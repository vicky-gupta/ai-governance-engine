package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// fakeRecorder keeps audit entries in memory, or fails if err is set.
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

// run sends body through the middleware and returns the response plus
// the body the next handler (the proxy) received, if it was reached.
func run(t *testing.T, p *Pipeline, body string, withSystem bool) (*httptest.ResponseRecorder, string, bool) {
	t.Helper()
	return runWith(t, p, &fakeRecorder{}, body, withSystem)
}

func runWith(t *testing.T, p *Pipeline, rec Recorder, body string, withSystem bool) (*httptest.ResponseRecorder, string, bool) {
	t.Helper()
	var forwarded string
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		b, _ := io.ReadAll(r.Body)
		forwarded = string(b)
		if r.ContentLength != int64(len(b)) {
			t.Errorf("ContentLength = %d, body is %d bytes", r.ContentLength, len(b))
		}
	})
	h := Middleware(p, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))(next)

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	if withSystem {
		req = req.WithContext(auth.WithSystem(req.Context(), registry.System{ID: "sys-1", Name: "support-bot"}))
	}
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	return resp, forwarded, reached
}

const validBody = `{"model":"m","messages":[{"role":"user","content":"hello"}]}`

func TestMiddlewareAllowForwardsOriginalBody(t *testing.T) {
	rec, forwarded, reached := run(t, New(fakeCheck{name: "ok", action: Allow}), validBody, true)
	if !reached || forwarded != validBody {
		t.Errorf("reached=%v forwarded=%q, want the original body", reached, forwarded)
	}
	if rec.Header().Get("X-Aigov-Decision") != "allow" {
		t.Errorf("decision header = %q", rec.Header().Get("X-Aigov-Decision"))
	}
}

func TestMiddlewareModifyForwardsChangedBody(t *testing.T) {
	rename := fakeCheck{name: "rename", action: Modify, modify: func(r *Request) { r.Model = "safe-model" }}
	_, forwarded, reached := run(t, New(rename), validBody, true)
	if !reached || !strings.Contains(forwarded, `"model":"safe-model"`) {
		t.Errorf("reached=%v forwarded=%q, want the modified body", reached, forwarded)
	}
}

func TestMiddlewareBlockAndHold(t *testing.T) {
	cases := map[Action]string{Block: "policy_violation", Hold: "approval_required"}
	for action, errType := range cases {
		t.Run(string(action), func(t *testing.T) {
			rec, _, reached := run(t, New(fakeCheck{name: "rule", action: action}), validBody, true)
			if reached {
				t.Error("request reached the proxy")
			}
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errType) {
				t.Errorf("status=%d body=%s, want 403 with %s", rec.Code, rec.Body, errType)
			}
		})
	}
}

func TestMiddlewareBadInput(t *testing.T) {
	p := New()
	if rec, _, reached := run(t, p, `not json`, true); reached || rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: reached=%v status=%d, want 400", reached, rec.Code)
	}
	big := `{"model":"m","messages":[{"role":"user","content":"` + strings.Repeat("a", maxBodyBytes) + `"}]}`
	if rec, _, reached := run(t, p, big, true); reached || rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("huge body: reached=%v status=%d, want 413", reached, rec.Code)
	}
}

func TestMiddlewareWithoutAuthFailsClosed(t *testing.T) {
	rec, _, reached := run(t, New(), validBody, false)
	if reached || rec.Code != http.StatusInternalServerError {
		t.Errorf("reached=%v status=%d, want 500 and not reached", reached, rec.Code)
	}
}

func TestMiddlewareRecordsEveryDecision(t *testing.T) {
	rename := fakeCheck{name: "rename", action: Modify, modify: func(r *Request) { r.Model = "safe-model" }}
	cases := []struct {
		name          string
		check         Check
		wantModel     string // the model actually used, after any changes
		wantForwarded bool
	}{
		{"allow", fakeCheck{name: "ok", action: Allow}, "m", true},
		{"modify", rename, "safe-model", true},
		{"block", fakeCheck{name: "rule", action: Block}, "m", false},
		{"hold", fakeCheck{name: "rule", action: Hold}, "m", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &fakeRecorder{}
			resp, forwarded, _ := runWith(t, New(tc.check), rec, validBody, true)

			if len(rec.entries) != 1 {
				t.Fatalf("got %d audit entries, want 1", len(rec.entries))
			}
			e := rec.entries[0]
			if e.SystemID != "sys-1" || e.Action != tc.name || e.Model != tc.wantModel {
				t.Errorf("entry = %+v", e)
			}
			if e.RequestID == "" || e.RequestID != resp.Header().Get("X-Request-ID") {
				t.Errorf("request ID %q does not match the response header", e.RequestID)
			}
			if e.RequestHash != audit.HashBytes([]byte(validBody)) {
				t.Error("request hash is not the hash of the received body")
			}
			if tc.wantForwarded && e.ForwardedHash != audit.HashBytes([]byte(forwarded)) {
				t.Error("forwarded hash is not the hash of what the proxy received")
			}
			if !tc.wantForwarded && e.ForwardedHash != "" {
				t.Error("a request that was not forwarded has a forwarded hash")
			}
		})
	}
}

func TestMiddlewareRefusesWhenAuditFails(t *testing.T) {
	rec := &fakeRecorder{err: errors.New("database down")}
	resp, _, reached := runWith(t, New(), rec, validBody, true)
	if reached || resp.Code != http.StatusServiceUnavailable {
		t.Errorf("reached=%v status=%d, want 503 and not forwarded", reached, resp.Code)
	}
}
func TestMiddlewarePassesRouteToProxy(t *testing.T) {
	route := fakeCheck{name: "route", action: Allow, modify: func(r *Request) {
		r.Provider, r.Region = "mistral", "eu"
	}}
	rec := &fakeRecorder{}
	var gotProvider string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gotProvider = ProviderFrom(r) })
	h := Middleware(New(route), rec, slog.New(slog.NewTextHandler(io.Discard, nil)))(next)

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(validBody))
	req = req.WithContext(auth.WithSystem(req.Context(), registry.System{ID: "sys-1", Name: "support-bot"}))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if gotProvider != "mistral" {
		t.Errorf("proxy saw provider %q, want mistral", gotProvider)
	}
	if e := rec.entries[0]; e.Provider != "mistral" || e.Region != "eu" {
		t.Errorf("audit entry provider=%q region=%q, want mistral/eu", e.Provider, e.Region)
	}
}
