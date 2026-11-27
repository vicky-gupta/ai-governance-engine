package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/health"
	"github.com/vicky-gupta/ai-governance-engine/internal/usage"
)

type fakeAudit struct{ err error }

func (f fakeAudit) Record(context.Context, audit.Entry) error { return f.err }

type fakeUsage struct{}

func (fakeUsage) Record(context.Context, usage.Record) error { return nil }

// Only decisions that reached the audit log are counted; failed writes
// are counted separately.
func TestAuditDecisions(t *testing.T) {
	m := New()
	ok := m.Audit(fakeAudit{})
	ok.Record(context.Background(), audit.Entry{SystemName: "loan-agent", Check: "policy", Action: "hold"})
	ok.Record(context.Background(), audit.Entry{SystemName: "loan-agent", Action: "allow"})

	broken := m.Audit(fakeAudit{err: errors.New("db down")})
	if err := broken.Record(context.Background(), audit.Entry{SystemName: "loan-agent", Action: "allow"}); err == nil {
		t.Fatal("the wrapper swallowed the audit error")
	}

	if v := testutil.ToFloat64(m.decisions.WithLabelValues("loan-agent", "policy", "hold")); v != 1 {
		t.Errorf("hold decisions = %v, want 1", v)
	}
	if v := testutil.ToFloat64(m.decisions.WithLabelValues("loan-agent", "pipeline", "allow")); v != 1 {
		t.Errorf("allow decisions = %v, want 1 (the failed write must not count)", v)
	}
	if v := testutil.ToFloat64(m.auditFailures); v != 1 {
		t.Errorf("audit failures = %v, want 1", v)
	}
}

func TestTokens(t *testing.T) {
	m := New()
	m.Usage(fakeUsage{}).Record(context.Background(), usage.Record{
		SystemName: "support-bot", Provider: "groq",
		Usage: usage.Usage{PromptTokens: 120, CompletionTokens: 30, TotalTokens: 150},
	})
	if v := testutil.ToFloat64(m.tokens.WithLabelValues("support-bot", "groq", "prompt")); v != 120 {
		t.Errorf("prompt tokens = %v", v)
	}
	if v := testutil.ToFloat64(m.tokens.WithLabelValues("support-bot", "groq", "completion")); v != 30 {
		t.Errorf("completion tokens = %v", v)
	}
}

// The upstream wrapper records the provider's status and doesn't break
// streaming: Flush must still reach the real writer.
func TestUpstream(t *testing.T) {
	m := New()
	provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.(http.Flusher).Flush()
	})
	w := httptest.NewRecorder()
	m.Upstream("groq", provider).ServeHTTP(w, httptest.NewRequest("POST", "/", nil))

	if !w.Flushed {
		t.Error("Flush did not reach the underlying writer")
	}
	if v := testutil.ToFloat64(m.upstreamResponses.WithLabelValues("groq", "502")); v != 1 {
		t.Errorf("502 responses = %v, want 1", v)
	}
	if n := testutil.CollectAndCount(m.upstreamDuration); n != 1 {
		t.Errorf("duration series = %d, want 1", n)
	}
}

func TestHTTPRoutes(t *testing.T) {
	m := New()
	m.ObserveHTTP("POST /v1/chat/completions", 200, 2*time.Second)
	m.ObserveHTTP("", 404, time.Millisecond)
	if v := testutil.ToFloat64(m.httpRequests.WithLabelValues("unmatched", "404")); v != 1 {
		t.Errorf("unmatched 404s = %v, want 1", v)
	}
}

// State is read at scrape time. A count that can't be read is left out,
// never reported as 0.
func TestState(t *testing.T) {
	m := New()
	m.WatchState(State{
		Probes: []health.Probe{
			{Name: "postgres", Required: true, Check: func(context.Context) error { return nil }},
			{Name: "redis", Check: func(context.Context) error { return errors.New("refused") }},
		},
		Pending:       func(context.Context) (int, error) { return 0, errors.New("db down") },
		PolicyVersion: func() string { return "a1b2c3" },
	})

	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	out := w.Body.String()
	for _, want := range []string{
		`aigov_dependency_up{dependency="postgres",required="true"} 1`,
		`aigov_dependency_up{dependency="redis",required="false"} 0`,
		`aigov_policy_info{version="a1b2c3"} 1`,
		`go_goroutines`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics is missing %s", want)
		}
	}
	if strings.Contains(out, "aigov_approvals_pending ") {
		t.Error("pending approvals reported although the count failed")
	}
}

func TestRequireToken(t *testing.T) {
	m := New()
	h := RequireToken("s3cret", m.Handler())
	for _, tc := range []struct {
		header string
		want   int
	}{
		{"", http.StatusUnauthorized},
		{"Bearer wrong", http.StatusUnauthorized},
		{"Bearer s3cret", http.StatusOK},
	} {
		r := httptest.NewRequest("GET", "/metrics", nil)
		if tc.header != "" {
			r.Header.Set("Authorization", tc.header)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("Authorization %q: got %d, want %d", tc.header, w.Code, tc.want)
		}
	}
	// No token configured: open, as before.
	w := httptest.NewRecorder()
	RequireToken("", m.Handler()).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != http.StatusOK {
		t.Errorf("without a token: got %d, want 200", w.Code)
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:9091": true, "localhost:9091": true, "[::1]:9091": true,
		":9091": false, "0.0.0.0:9091": false, "192.168.1.20:9091": false,
	} {
		if got := IsLoopback(addr); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}
