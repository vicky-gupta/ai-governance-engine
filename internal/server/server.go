package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"time"
)

type Server struct {
	log    *slog.Logger
	dbAddr string
}

func New(log *slog.Logger, dbAddr string) *Server {
	return &Server{log: log, dbAddr: dbAddr}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	return s.logRequests(mux)
}

// Is the process alive?
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Can we serve traffic? (Is the database reachable?)
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", s.dbAddr)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready", "database": err.Error()})
		return
	}
	conn.Close()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready", "database": "ok"})
}

// One log line per request.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Info("request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
