// Package proxy forwards OpenAI-compatible requests to an LLM provider.
package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
)

// New returns a handler that forwards requests to target, replacing the
// caller's Authorization header with the gateway's own provider key.
func New(target *url.URL, apiKey string, log *slog.Logger) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// Send the request to the provider, keeping the path
			// (/v1/chat/completions) and query string.
			r.SetURL(target)

			// Never forward the caller's credentials. The provider only
			// ever sees the gateway's key.
			r.Out.Header.Set("Authorization", "Bearer "+apiKey)
		},

		// Send each chunk to the client as soon as it arrives, so
		// streamed tokens are not held back in a buffer.
		FlushInterval: -1,

		// Provider unreachable: answer in OpenAI's error format so
		// client SDKs can parse it.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("upstream request failed", "path", r.URL.Path, "error", err)
			apierr.Write(w, http.StatusBadGateway, "gateway_error", "upstream provider unreachable")
		},
	}
}
