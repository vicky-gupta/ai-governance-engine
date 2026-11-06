package proxy

import (
	"log/slog"
	"net/http"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
)

// Router sends each request to the provider chosen for it. pick returns
// the provider's name; the router doesn't know or care how it was chosen.
func NewRouter(providers map[string]http.Handler, pick func(*http.Request) string, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := pick(r)
		h, ok := providers[name]
		if !ok {
			// No route means a wiring mistake (e.g. the routing check is
			// missing). Never guess a provider: fail closed.
			log.Error("router: no provider for request", "provider", name)
			apierr.Write(w, http.StatusInternalServerError, "gateway_error", "no provider selected for this request")
			return
		}
		h.ServeHTTP(w, r)
	})
}
