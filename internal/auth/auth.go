// Package auth checks the gateway API key on every model request and works
// out which registered AI system is calling.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// Lookup finds the AI system that owns a key. registry.Store implements it;
// tests use a fake.
type Lookup interface {
	SystemByKey(ctx context.Context, key string) (registry.System, error)
}

type ctxKey struct{}

// SystemFrom returns the AI system that made this request.
func SystemFrom(ctx context.Context) (registry.System, bool) {
	sys, ok := ctx.Value(ctxKey{}).(registry.System)
	return sys, ok
}

// Middleware rejects requests without a valid key, and requests from AI
// systems that are disabled or classified as unacceptable risk.
func Middleware(lookup Lookup, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || key == "" {
				apierr.Write(w, http.StatusUnauthorized, "invalid_request_error",
					"missing API key: send 'Authorization: Bearer YOUR_GATEWAY_KEY'")
				return
			}

			sys, err := lookup.SystemByKey(r.Context(), key)
			if errors.Is(err, registry.ErrNotFound) {
				apierr.Write(w, http.StatusUnauthorized, "invalid_request_error", "invalid API key")
				return
			}
			if err != nil {
				log.Error("key lookup failed", "error", err)
				apierr.Write(w, http.StatusServiceUnavailable, "gateway_error", "registry unavailable")
				return
			}

			if sys.Status != "active" {
				apierr.Write(w, http.StatusForbidden, "permission_denied",
					"AI system '"+sys.Name+"' is disabled")
				return
			}
			if sys.RiskTier == registry.RiskUnacceptable {
				apierr.Write(w, http.StatusForbidden, "permission_denied",
					"AI system '"+sys.Name+"' is classified as unacceptable risk (EU AI Act, Article 5) and may not call models")
				return
			}

			log.Info("ai request", "ai_system", sys.Name, "risk_tier", sys.RiskTier, "path", r.URL.Path)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sys)))
		})
	}
}
