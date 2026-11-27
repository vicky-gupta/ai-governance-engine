package usage

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
)

// Recorder stores usage records. Store implements it; tests use a fake.
type Recorder interface {
	Record(ctx context.Context, rec Record) error
}

// maxJSONBytes caps how much of a non-streamed response we keep to find
// the usage numbers. Chat responses are far smaller.
const maxJSONBytes = 10 << 20

// Middleware reads the token usage from each provider response as it is
// sent to the caller, without delaying it, and records it once the
// response is complete. It sits between the pipeline and the proxy.
func Middleware(rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mw := &meteredWriter{ResponseWriter: w}
			next.ServeHTTP(mw, r)

			if mw.status != http.StatusOK {
				return // errors from the provider use no tokens worth billing
			}
			model, u, ok := mw.result()
			sys, _ := auth.SystemFrom(r.Context())
			if !ok {
				log.Warn("usage: provider response had no token usage; request not metered",
					"request_id", pipeline.RequestIDFrom(r), "ai_system", sys.Name)
				return
			}
			record := Record{
				RequestID:  pipeline.RequestIDFrom(r),
				SystemID:   sys.ID,
				SystemName: sys.Name,
				Model:      model,
				Provider:   pipeline.ProviderFrom(r),
				Usage:      u,
			}
			// The response is already with the caller, who may have hung up,
			// which cancels r.Context(). The record must still be written.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
			defer cancel()
			if err := rec.Record(ctx, record); err != nil {
				log.Error("usage: could not record usage", "request_id", record.RequestID, "error", err)
				return
			}
			log.Info("usage", "request_id", record.RequestID, "ai_system", sys.Name,
				"model", model, "total_tokens", u.TotalTokens)
		})
	}
}

// meteredWriter passes everything through to the real ResponseWriter
// and looks at the bytes on the way.
type meteredWriter struct {
	http.ResponseWriter
	status    int
	streaming bool
	sse       sseScanner
	body      bytes.Buffer
	overflow  bool
}

func (m *meteredWriter) WriteHeader(code int) {
	if m.status == 0 {
		m.status = code
		m.streaming = strings.HasPrefix(m.Header().Get("Content-Type"), "text/event-stream")
	}
	m.ResponseWriter.WriteHeader(code)
}

func (m *meteredWriter) Write(p []byte) (int, error) {
	if m.status == 0 {
		m.WriteHeader(http.StatusOK)
	}
	if m.streaming {
		m.sse.Write(p)
	} else if !m.overflow {
		if m.body.Len()+len(p) > maxJSONBytes {
			m.overflow = true
			m.body.Reset()
		} else {
			m.body.Write(p)
		}
	}
	return m.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the real writer, so flushing
// still works and streamed responses are not buffered.
func (m *meteredWriter) Unwrap() http.ResponseWriter { return m.ResponseWriter }

// Flush is for code that checks for http.Flusher directly.
func (m *meteredWriter) Flush() { http.NewResponseController(m.ResponseWriter).Flush() }

func (m *meteredWriter) result() (string, Usage, bool) {
	if m.streaming {
		// A last line without a trailing newline is still a line.
		if len(m.sse.partial) > 0 {
			m.sse.line(m.sse.partial)
		}
		return m.sse.model, m.sse.usage, m.sse.found
	}
	if m.overflow {
		return "", Usage{}, false
	}
	return parse(m.body.Bytes())
}
