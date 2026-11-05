package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeDB lets tests choose whether the database is "up".
type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

// testDeps returns working defaults; each test overrides what it needs.
func testDeps() Deps {
	return Deps{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		DB:     fakeDB{},
		Chat:   http.NotFoundHandler(),
		Models: http.NotFoundHandler(),
		Admin:  http.NotFoundHandler(),
	}
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	New(testDeps()).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
}

func TestReadyz(t *testing.T) {
	deps := testDeps()
	rec := httptest.NewRecorder()
	New(deps).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("db up: got %d, want 200", rec.Code)
	}

	deps.DB = fakeDB{err: errors.New("connection refused")}
	rec = httptest.NewRecorder()
	New(deps).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("db down: got %d, want 503", rec.Code)
	}
}

func TestRouting(t *testing.T) {
	var hit string
	deps := testDeps()
	deps.Chat = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = "chat" })
	deps.Models = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = "models" })
	deps.Admin = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = "admin" })
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
