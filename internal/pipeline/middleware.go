package pipeline

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
)

// maxBodyBytes limits request size. Chat requests with long histories can
// be large, but 10 MB is far beyond any normal one.
const maxBodyBytes = 10 << 20

// Middleware runs the pipeline on every chat request before it reaches
// the proxy. It must sit after the auth middleware.
func Middleware(p *Pipeline, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sys, ok := auth.SystemFrom(r.Context())
			if !ok {
				// Wiring mistake: auth didn't run first. Fail closed.
				log.Error("pipeline: no AI system in request context")
				apierr.Write(w, http.StatusInternalServerError, "gateway_error", "internal error")
				return
			}

			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
			if err != nil {
				var tooBig *http.MaxBytesError
				if errors.As(err, &tooBig) {
					apierr.Write(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "request body too large")
					return
				}
				apierr.Write(w, http.StatusBadRequest, "invalid_request_error", "could not read request body")
				return
			}

			req, err := ParseRequest(body)
			if err != nil {
				apierr.Write(w, http.StatusBadRequest, "invalid_request_error", err.Error())
				return
			}
			req.System = sys

			res := p.Run(r.Context(), req)
			log.Info("decision",
				"ai_system", sys.Name,
				"action", res.Action,
				"check", res.Check,
				"reason", res.Reason,
				"trace", res.Trace,
			)
			w.Header().Set("X-Aigov-Decision", string(res.Action))

			switch res.Action {
			case Block:
				apierr.Write(w, http.StatusForbidden, "policy_violation",
					"blocked by "+res.Check+": "+res.Reason)
				return
			case Hold:
				// The approval workflow arrives in Module 10. Until then,
				// a held request is refused with a clear explanation.
				apierr.Write(w, http.StatusForbidden, "approval_required",
					"held for human review by "+res.Check+": "+res.Reason)
				return
			case Modify:
				body, err = req.Encode()
				if err != nil {
					log.Error("pipeline: re-encoding request failed", "error", err)
					apierr.Write(w, http.StatusInternalServerError, "gateway_error", "internal error")
					return
				}
			}

			// The body was consumed above, so give the next handler a fresh
			// reader over the (possibly modified) bytes.
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			r.Header.Set("Content-Length", strconv.Itoa(len(body)))
			next.ServeHTTP(w, r)
		})
	}
}
