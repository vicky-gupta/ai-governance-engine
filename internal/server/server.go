package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

var Version = "dev"

// Deps holds everything the server needs.
type Deps struct {
	Log    *slog.Logger
	Ready  http.Handler // GET /readyz: are the dependencies up?
	Chat   http.Handler // POST /v1/chat/completions: auth + pipeline + proxy
	Models http.Handler // GET /v1/models: auth + proxy
	Admin  http.Handler // the /admin API
	Review http.Handler // the /review API for human reviewers

	// Observe, if set, is called after every request (for metrics).
	// route is the pattern that matched, or "" if none did.
	Observe func(route string, status int, d time.Duration)
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
	mux.Handle("GET /readyz", s.deps.Ready)
	mux.HandleFunc("GET /version", s.handleVersion)

	// OpenAI-compatible routes. Only these are forwarded; anything
	// else gets a 404 (deny by default).
	mux.Handle("POST /v1/chat/completions", s.deps.Chat)
	mux.Handle("GET /v1/models", s.deps.Models)

	// Registry management. The admin handler does its own routing.
	mux.Handle("/admin/", s.deps.Admin)
	mux.Handle("/review/", s.deps.Review)

	return s.logRequests(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": Version})
}

// logRequests logs every request with its status and request ID, so a
// log line can be matched to its audit entry, and reports it to Observe.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		d := time.Since(start)

		// The mux sets r.Pattern on this same request when a route
		// matches. Health checks are polled constantly; they are counted
		// but not logged.
		if r.Pattern != "GET /healthz" && r.Pattern != "GET /readyz" {
			s.deps.Log.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"route", r.Pattern,
				"status", sw.code(),
				"duration_ms", d.Milliseconds(),
				"request_id", w.Header().Get("X-Request-Id"), // set by the pipeline, if it ran
			)
		}
		if s.deps.Observe != nil {
			s.deps.Observe(r.Pattern, sw.code(), d)
		}
	})
}

// statusWriter remembers the status code. It passes Flush on, so
// streamed responses still stream.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(p)
}

func (s *statusWriter) Flush()                      { http.NewResponseController(s.ResponseWriter).Flush() }
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) code() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
