package pipeline

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
)

// Recorder writes audit entries. audit.Store implements it; tests use a fake.
type Recorder interface {
	Record(ctx context.Context, e audit.Entry) error
}

type providerKey struct{}

// ProviderFrom returns the provider the pipeline chose for this request.
// The proxy router uses it to decide where to send the request.
func ProviderFrom(r *http.Request) string {
	p, _ := r.Context().Value(providerKey{}).(string)
	return p
}

// maxBodyBytes limits request size. Chat requests with long histories can
// be large, but 10 MB is far beyond any normal one.
const maxBodyBytes = 10 << 20

// Middleware runs the pipeline on every chat request before it reaches
// the proxy, and records every decision in the audit log. It must sit
// after the auth middleware.
func Middleware(p *Pipeline, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
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
			requestID := newRequestID()
			w.Header().Set("X-Request-ID", requestID)
			w.Header().Set("X-Aigov-Decision", string(res.Action))
			log.Info("decision",
				"request_id", requestID,
				"ai_system", sys.Name,
				"action", res.Action,
				"check", res.Check,
				"reason", res.Reason,
				"trace", res.Trace,
			)

			// What gets forwarded: the original bytes, or the modified request.
			forward := body
			if res.Action == Modify {
				forward, err = req.Encode()
				if err != nil {
					log.Error("pipeline: re-encoding request failed", "error", err)
					apierr.Write(w, http.StatusInternalServerError, "gateway_error", "internal error")
					return
				}
			}

			trace, _ := json.Marshal(res.Trace)
			entry := audit.Entry{
				RequestID:   requestID,
				SystemID:    sys.ID,
				SystemName:  sys.Name,
				Model:       req.Model,
				Provider:    req.Provider,
				Region:      req.Region,
				Action:      string(res.Action),
				Check:       res.Check,
				Reason:      res.Reason,
				Trace:       trace,
				RequestHash: audit.HashBytes(body),
			}
			if res.Action == Allow || res.Action == Modify {
				entry.ForwardedHash = audit.HashBytes(forward)
			}

			// No record, no request: if the decision can't be written down,
			// the request is refused rather than handled without a trace.
			if err := rec.Record(r.Context(), entry); err != nil {
				log.Error("audit write failed", "request_id", requestID, "error", err)
				apierr.Write(w, http.StatusServiceUnavailable, "gateway_error",
					"audit log unavailable; request not processed")
				return
			}

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
			}

			// The body was consumed above, so give the next handler a fresh
			// reader over the (possibly modified) bytes.
			r.Body = io.NopCloser(bytes.NewReader(forward))
			r = r.WithContext(context.WithValue(r.Context(), providerKey{}, req.Provider))
			r.Body = io.NopCloser(bytes.NewReader(forward))
			r.ContentLength = int64(len(forward))
			r.Header.Set("Content-Length", strconv.Itoa(len(forward)))
			next.ServeHTTP(w, r)
		})
	}
}

// newRequestID returns a random ID that links a response to its audit
// entry. Callers see it in the X-Request-ID response header.
func newRequestID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}
