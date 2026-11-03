package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

var Version = "dev"

// Pinger is anything that can check the database connection.
// *pgxpool.Pool implements it.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps holds everything the server needs.
type Deps struct {
	Log   *slog.Logger
	DB    Pinger       // used by /readyz
	Proxy http.Handler // model routes, already wrapped with auth
	Admin http.Handler // the /admin API
}

type Server struct {
	deps Deps
}

func New(deps Deps) *Server {
	return &Server{deps: deps}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.HandleFunc("GET /version", s.handleVersion)

	// OpenAI-compatible routes. Only these are forwarded; anything
	// else gets a 404 (deny by default).
	mux.Handle("POST /v1/chat/completions", s.deps.Proxy)
	mux.Handle("GET /v1/models", s.deps.Proxy)

	// Registry management. The admin handler does its own routing.
	mux.Handle("/admin/", s.deps.Admin)

	return s.logRequests(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": Version})
}

// Can we serve traffic? (Can we query the database?)
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.deps.DB.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready", "database": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready", "database": "ok"})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.deps.Log.Info("request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
