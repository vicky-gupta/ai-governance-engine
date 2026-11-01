package server

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), "127.0.0.1:1")
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
	New(log, "127.0.0.1:1").Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
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
	New(log, ln.Addr().String()).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("db up: got %d, want 200", rec.Code)
	}
}
