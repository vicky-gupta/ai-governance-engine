package ratelimit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// fakeCounter counts in memory, per system and window, like Redis would.
type fakeCounter struct {
	counts map[string]int64
	err    error
}

func (f *fakeCounter) Hit(_ context.Context, id string, now time.Time) (int64, time.Time, error) {
	if f.err != nil {
		return 0, time.Time{}, f.err
	}
	window := now.UTC().Truncate(time.Minute)
	key := id + window.String()
	f.counts[key]++
	return f.counts[key], window.Add(time.Minute), nil
}

// at10s is 10 seconds into a minute, so 50 seconds are left in the window.
var at10s = time.Date(2026, 11, 19, 18, 30, 10, 0, time.UTC)

func newLimiter(c Counter, clock *time.Time) *Limiter {
	return &Limiter{
		Counter:    c,
		DefaultRPM: 3,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:        func() time.Time { return *clock },
	}
}

func send(t *testing.T, l *Limiter, sys registry.System) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	reached := false
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	req = req.WithContext(auth.WithSystem(req.Context(), sys))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, reached
}

func TestLimitPerMinute(t *testing.T) {
	clock := at10s
	l := newLimiter(&fakeCounter{counts: map[string]int64{}}, &clock)
	bot := registry.System{ID: "sys-1", Name: "support-bot"}

	for i := 1; i <= 3; i++ {
		rec, reached := send(t, l, bot)
		if !reached || rec.Header().Get("X-RateLimit-Remaining") != strconv.Itoa(3-i) {
			t.Fatalf("request %d: reached=%v remaining=%s", i, reached, rec.Header().Get("X-RateLimit-Remaining"))
		}
	}

	rec, reached := send(t, l, bot)
	if reached || rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: reached=%v status=%d, want 429", reached, rec.Code)
	}
	if rec.Header().Get("Retry-After") != "50" {
		t.Errorf("Retry-After = %q, want 50 (seconds left in the minute)", rec.Header().Get("Retry-After"))
	}

	// A new minute starts a new window.
	clock = at10s.Add(time.Minute)
	if _, reached := send(t, l, bot); !reached {
		t.Error("first request of the next minute was rejected")
	}
}

func TestLimitsAreSeparatePerSystem(t *testing.T) {
	clock := at10s
	l := newLimiter(&fakeCounter{counts: map[string]int64{}}, &clock)
	for i := 0; i < 3; i++ {
		send(t, l, registry.System{ID: "sys-1", Name: "busy-bot"})
	}
	if _, reached := send(t, l, registry.System{ID: "sys-2", Name: "quiet-bot"}); !reached {
		t.Error("one system's traffic used up another system's limit")
	}
}

func TestSystemLimitOverridesDefault(t *testing.T) {
	clock := at10s
	l := newLimiter(&fakeCounter{counts: map[string]int64{}}, &clock)
	five := 5
	vip := registry.System{ID: "sys-3", Name: "batch-job", RateLimitRPM: &five}
	for i := 1; i <= 5; i++ {
		if _, reached := send(t, l, vip); !reached {
			t.Fatalf("request %d of 5 was rejected", i)
		}
	}
	if rec, _ := send(t, l, vip); rec.Header().Get("X-RateLimit-Limit") != "5" || rec.Code != http.StatusTooManyRequests {
		t.Errorf("limit header=%s status=%d, want 5 and 429", rec.Header().Get("X-RateLimit-Limit"), rec.Code)
	}
}

func TestCounterDownFailsOpen(t *testing.T) {
	clock := at10s
	l := newLimiter(&fakeCounter{err: errors.New("redis down")}, &clock)
	if _, reached := send(t, l, registry.System{ID: "sys-1", Name: "bot"}); !reached {
		t.Error("request was rejected while the counter was down; rate limits fail open")
	}
}

func TestNoSystemFailsClosed(t *testing.T) {
	clock := at10s
	l := newLimiter(&fakeCounter{counts: map[string]int64{}}, &clock)
	reached := false
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", nil))
	if reached || rec.Code != http.StatusInternalServerError {
		t.Errorf("reached=%v status=%d, want 500", reached, rec.Code)
	}
}
