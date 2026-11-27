package server

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testDeps returns working defaults; each test overrides what it needs.
func testDeps() Deps {
	return Deps{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Ready:  http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Chat:   http.NotFoundHandler(),
		Models: http.NotFoundHandler(),
		Admin:  http.NotFoundHandler(),
		Review: http.NotFoundHandler(),
	}
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	New(testDeps()).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
}

// Every request is reported with the matched route, never the raw path,
// and logged with its status and request ID.
func TestObserveAndLog(t *testing.T) {
	type seen struct {
		route  string
		status int
	}
	var got []seen
	var logs bytes.Buffer
	deps := testDeps()
	deps.Log = slog.New(slog.NewTextHandler(&logs, nil))
	deps.Chat = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "req-123")
		w.WriteHeader(http.StatusForbidden)
	})
	deps.Observe = func(route string, status int, _ time.Duration) { got = append(got, seen{route, status}) }
	h := New(deps).Handler()

	for _, req := range []*http.Request{
		httptest.NewRequest("POST", "/v1/chat/completions", nil),
		httptest.NewRequest("GET", "/wp-admin/setup.php", nil),
		httptest.NewRequest("GET", "/healthz", nil),
	} {
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	want := []seen{{"POST /v1/chat/completions", 403}, {"", 404}, {"GET /healthz", 200}}
	if len(got) != len(want) {
		t.Fatalf("observed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("observed[%d] = %v, want %v", i, got[i], want[i])
		}
	}
	if !strings.Contains(logs.String(), "status=403") || !strings.Contains(logs.String(), "request_id=req-123") {
		t.Errorf("log line misses status or request ID:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "/healthz") {
		t.Error("health checks should not be logged")
	}
}

func TestRouting(t *testing.T) {
	var hit string
	deps := testDeps()
	deps.Chat = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = "chat" })
	deps.Models = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = "models" })
	deps.Admin = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = "admin" })
	deps.Review = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = "review" })
	h := New(deps).Handler()

	cases := []struct {
		method, path string
		wantHit      string
		wantCode     int
	}{
		{"POST", "/v1/chat/completions", "chat", http.StatusOK},
		{"GET", "/v1/models", "models", http.StatusOK},
		{"GET", "/admin/systems", "admin", http.StatusOK},
		{"POST", "/v1/files", "", http.StatusNotFound},
		{"GET", "/v1/chat/completions", "", http.StatusMethodNotAllowed},
		{"GET", "/review/approvals", "review", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			hit = ""
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if hit != tc.wantHit || rec.Code != tc.wantCode {
				t.Errorf("hit=%q status=%d, want hit=%q status=%d", hit, rec.Code, tc.wantHit, tc.wantCode)
			}
		})
	}
}
