package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// fakeLookup is an in-memory stand-in for the database.
type fakeLookup map[string]registry.System

func (f fakeLookup) SystemByKey(_ context.Context, key string) (registry.System, error) {
	if key == "boom" {
		return registry.System{}, errors.New("database down")
	}
	sys, ok := f[key]
	if !ok {
		return registry.System{}, registry.ErrNotFound
	}
	return sys, nil
}

func TestMiddleware(t *testing.T) {
	lookup := fakeLookup{
		"good":     {Name: "support-bot", RiskTier: registry.RiskLimited, Status: "active"},
		"disabled": {Name: "old-bot", RiskTier: registry.RiskMinimal, Status: "disabled"},
		"banned":   {Name: "social-scorer", RiskTier: registry.RiskUnacceptable, Status: "active"},
	}

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"not bearer", "Basic abc", http.StatusUnauthorized},
		{"unknown key", "Bearer nope", http.StatusUnauthorized},
		{"disabled system", "Bearer disabled", http.StatusForbidden},
		{"unacceptable risk", "Bearer banned", http.StatusForbidden},
		{"database error", "Bearer boom", http.StatusServiceUnavailable},
		{"valid key", "Bearer good", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen registry.System
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen, _ = SystemFrom(r.Context())
			})
			h := Middleware(lookup, slog.New(slog.NewTextHandler(io.Discard, nil)))(next)

			req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body)
			}
			if tc.want == http.StatusOK && seen.Name != "support-bot" {
				t.Errorf("next handler saw system %+v, want support-bot", seen)
			}
			if tc.want != http.StatusOK && seen.Name != "" {
				t.Error("request reached the next handler but should have been rejected")
			}
		})
	}
}
