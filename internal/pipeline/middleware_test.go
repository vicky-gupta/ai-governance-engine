package pipeline

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// run sends body through the middleware and returns the response plus
// the body the next handler (the proxy) received, if it was reached.
func run(t *testing.T, p *Pipeline, body string, withSystem bool) (*httptest.ResponseRecorder, string, bool) {
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
	h := Middleware(p, slog.New(slog.NewTextHandler(io.Discard, nil)))(next)

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	if withSystem {
		req = req.WithContext(auth.WithSystem(req.Context(), registry.System{Name: "support-bot"}))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, forwarded, reached
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
