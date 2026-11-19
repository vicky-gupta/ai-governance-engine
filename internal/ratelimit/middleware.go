package ratelimit

import (
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
)

// Limiter enforces each AI system's requests-per-minute limit.
type Limiter struct {
	Counter    Counter
	DefaultRPM int // for systems without their own limit
	Log        *slog.Logger
	Now        func() time.Time // nil means time.Now; tests set a fixed clock
}

// Middleware rejects requests over the limit with 429 Too Many Requests.
// It must sit after the auth middleware.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sys, ok := auth.SystemFrom(r.Context())
		if !ok {
			l.Log.Error("ratelimit: no AI system in request context")
			apierr.Write(w, http.StatusInternalServerError, "gateway_error", "internal error")
			return
		}
		limit := l.DefaultRPM
		if sys.RateLimitRPM != nil {
			limit = *sys.RateLimitRPM
		}

		now := time.Now()
		if l.Now != nil {
			now = l.Now()
		}
		count, resetAt, err := l.Counter.Hit(r.Context(), sys.ID, now)
		if err != nil {
			// A rate limit protects capacity and cost, not data. If Redis is
			// down, let traffic through rather than take every AI system
			// offline, and say so loudly in the logs.
			l.Log.Warn("ratelimit: counter unavailable, request allowed without a limit check",
				"ai_system", sys.Name, "error", err)
			next.ServeHTTP(w, r)
			return
		}

		remaining := int64(limit) - count
		if remaining < 0 {
			remaining = 0
		}
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))

		if count > int64(limit) {
			retryAfter := int(math.Ceil(resetAt.Sub(now).Seconds()))
			if retryAfter < 1 {
				retryAfter = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			l.Log.Info("rate limit exceeded", "ai_system", sys.Name, "limit", limit, "count", count)
			apierr.Write(w, http.StatusTooManyRequests, "rate_limit_exceeded",
				fmt.Sprintf("AI system '%s' is limited to %d requests per minute; try again in %d seconds",
					sys.Name, limit, retryAfter))
			return
		}
		next.ServeHTTP(w, r)
	})
}
