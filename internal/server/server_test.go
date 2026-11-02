package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), "127.0.0.1:1", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
}

func TestReadyz(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Nothing listening: should be 503.
	rec := httptest.NewRecorder()
	New(log, "127.0.0.1:1", http.NotFoundHandler()).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no db: got %d, want 503", rec.Code)
	}

	// Fake database listening: should be 200.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	rec = httptest.NewRecorder()
	New(log, ln.Addr().String(), http.NotFoundHandler()).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("db up: got %d, want 200", rec.Code)
	}
}

func TestVersion(t *testing.T) {
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), "127.0.0.1:1", http.NotFoundHandler())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/version", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if body["version"] != Version {
		t.Errorf("got version %q, want %q", body["version"], Version)
	}
}

func TestRoutesReachProxy(t *testing.T) {
	called := false
	fake := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), "127.0.0.1:1", fake)

	s.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/chat/completions", nil))
	if !called {
		t.Error("POST /v1/chat/completions did not reach the proxy")
	}

	called = false
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/v1/files", nil))
	if called || rec.Code != http.StatusNotFound {
		t.Errorf("unlisted route: called=%v status=%d, want not called and 404", called, rec.Code)
	}
}
