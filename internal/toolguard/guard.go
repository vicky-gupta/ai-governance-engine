// Package toolguard checks the tool calls an AI model makes before they
// reach the AI agent that would carry them out. A model's answer is just
// text until an agent acts on it; a tool call is where it becomes an
// action (a refund, an email, a database change), so this is the last
// point where the gateway can stop it.
package toolguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/policy"
)

// Policy evaluates the tool-call rules. policy.Engine implements it.
type Policy interface {
	EvaluateToolCalls(ctx context.Context, input map[string]any) (policy.ToolResult, string, error)
}

// Recorder writes audit entries. audit.Store implements it.
type Recorder interface {
	Record(ctx context.Context, e audit.Entry) error
}

// Approvals keeps held tool calls for human review and gives back the
// approved answer once. approval.Store implements it.
type Approvals interface {
	OpenToolCalls(ctx context.Context, h pipeline.Held, response []byte, contentType string) (string, error)
	UseToolCalls(ctx context.Context, id, systemID, requestHash, requestID string) (reviewer string, response []byte, contentType string, err error)
}

// checkName is how this check appears in the audit log.
const checkName = "tool_calls"

// Middleware checks the tool calls in every response to a request that
// offered the model tools. It sits between the pipeline and the proxy.
//
// To check a tool call, the gateway needs the whole response before the
// agent sees any of it, so responses to tool requests are held back and
// sent in one piece, even when streamed. Requests without tools are not
// affected.
//
// Held tool calls wait for a reviewer (approvals may be nil: then they are
// simply refused). Once approved, the agent sends the same request again
// with the approval ID, and gets back the answer the reviewer approved,
// without the model being asked again: a new answer could contain a
// different tool call.
func Middleware(p Policy, rec Recorder, approvals Approvals, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req, ok := pipeline.RequestFrom(r)
			if !ok {
				log.Error("toolguard: no pipeline request in context")
				apierr.Write(w, http.StatusInternalServerError, "gateway_error", "internal error")
				return
			}
			if len(req.ToolNames()) == 0 {
				next.ServeHTTP(w, r) // no tools offered, so no tool calls possible
				return
			}
			if id := r.Header.Get(pipeline.ApprovalHeader); id != "" && approvals != nil {
				if replayed := replay(w, r, approvals, rec, log, req, id); replayed {
					return
				}
			}

			buf := &holdingWriter{header: w.Header()}
			next.ServeHTTP(buf, r)

			if buf.status != http.StatusOK {
				buf.release(w) // provider errors pass through unchanged
				return
			}
			var calls []Call
			if strings.HasPrefix(w.Header().Get("Content-Type"), "text/event-stream") {
				calls = fromStream(buf.body.Bytes())
			} else {
				calls = fromJSON(buf.body.Bytes())
			}
			if len(calls) == 0 {
				buf.release(w) // the model answered in text
				return
			}

			action, reason, version := decide(r.Context(), p, req, calls)

			// Held tool calls wait for a reviewer, with the answer kept for later.
			var approvalID string
			if action == pipeline.Hold && approvals != nil {
				held := pipeline.HeldRequest(req, reason)
				for _, c := range calls {
					held.ToolCalls = append(held.ToolCalls, pipeline.HeldToolCall{Name: c.Name, Arguments: c.Arguments})
				}
				id, err := approvals.OpenToolCalls(r.Context(), held, buf.body.Bytes(), w.Header().Get("Content-Type"))
				if err != nil {
					log.Error("toolguard: could not open an approval", "request_id", req.ID, "error", err)
					replace(w, http.StatusServiceUnavailable, "", "gateway_error",
						"approval workflow unavailable; response withheld")
					return
				}
				approvalID = id
				reason += " (approval " + id + ")"
			}
			entry := audit.Entry{
				RequestID:     req.ID,
				SystemID:      req.System.ID,
				SystemName:    req.System.Name,
				Model:         req.Model,
				Provider:      req.Provider,
				Region:        req.Region,
				PolicyVersion: version,
				Action:        string(action),
				Check:         checkName,
				Reason:        reason,
			}
			// The response is already paid for, but the agent hasn't seen it:
			// if we can't record what we decided, it doesn't get it.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
			defer cancel()
			if err := rec.Record(ctx, entry); err != nil {
				log.Error("toolguard: audit record failed; response withheld", "request_id", req.ID, "error", err)
				replace(w, http.StatusServiceUnavailable, "", "gateway_error", "audit log unavailable; response withheld")
				return
			}
			log.Info("tool calls checked", "request_id", req.ID, "ai_system", req.System.Name,
				"action", action, "tools", names(calls), "reason", reason)

			switch action {
			case pipeline.Allow:
				buf.release(w)
			case pipeline.Hold:
				msg := "tool call held for human review: " + reason
				if approvalID != "" {
					msg += ". Once a reviewer approves it, send the same request again with the header " +
						pipeline.ApprovalHeader + ": " + approvalID
					w.Header().Set("X-Aigov-Approval-Id", approvalID) // before replace writes the response
				}
				replace(w, http.StatusForbidden, action, "approval_required", msg)
			default:
				replace(w, http.StatusForbidden, action, "policy_violation", "tool call blocked: "+reason)
			}
		})
	}
}

// replay answers a request sent again with an approval ID. It reports
// whether it answered: an approval for something else (a held request,
// handled by the pipeline) is not its business, and the request goes on
// to the model as usual.
func replay(w http.ResponseWriter, r *http.Request, approvals Approvals, rec Recorder, log *slog.Logger,
	req *pipeline.Request, id string) bool {
	reviewer, response, contentType, err := approvals.UseToolCalls(r.Context(), id, req.System.ID, req.BodyHash, req.ID)
	if errors.Is(err, pipeline.ErrOtherKind) {
		return false
	}

	entry := audit.Entry{
		RequestID:  req.ID,
		SystemID:   req.System.ID,
		SystemName: req.System.Name,
		Model:      req.Model,
		Provider:   req.Provider,
		Region:     req.Region,
		Check:      checkName,
	}
	if err != nil {
		entry.Action = string(pipeline.Hold)
		entry.Reason = fmt.Sprintf("approval %s can't be used: %v", id, err)
	} else {
		entry.Action = string(pipeline.Allow)
		entry.Reason = fmt.Sprintf("tool calls approved by %s (approval %s); the approved answer was given back", reviewer, id)
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
	defer cancel()
	if recErr := rec.Record(ctx, entry); recErr != nil {
		log.Error("toolguard: audit record failed", "request_id", req.ID, "error", recErr)
		replace(w, http.StatusServiceUnavailable, "", "gateway_error", "audit log unavailable; response withheld")
		return true
	}
	if err != nil {
		replace(w, http.StatusForbidden, pipeline.Hold, "approval_invalid", entry.Reason)
		return true
	}

	log.Info("approved tool calls given back", "request_id", req.ID, "approval", id, "reviewer", reviewer)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Aigov-Decision", string(pipeline.Allow))
	w.WriteHeader(http.StatusOK)
	w.Write(response)
	return true
}

// decide runs the tool-call policy. Anything it can't evaluate is blocked.
func decide(ctx context.Context, p Policy, req *pipeline.Request, calls []Call) (pipeline.Action, string, string) {
	toolCalls := make([]any, 0, len(calls))
	for _, c := range calls {
		var args any // stays nil when the arguments are not valid JSON
		if err := json.Unmarshal([]byte(c.Arguments), &args); err != nil {
			args = nil
		}
		toolCalls = append(toolCalls, map[string]any{"name": c.Name, "arguments": args})
	}
	input := map[string]any{
		"system": map[string]any{
			"name":      req.System.Name,
			"owner":     req.System.Owner,
			"risk_tier": string(req.System.RiskTier),
		},
		"model":      req.Model,
		"tool_calls": toolCalls,
	}

	res, version, err := p.EvaluateToolCalls(ctx, input)
	switch {
	case err != nil:
		return pipeline.Block, "tool-call policy could not be evaluated", version
	case len(res.Deny) > 0:
		return pipeline.Block, strings.Join(res.Deny, "; "), version
	case len(res.Hold) > 0:
		return pipeline.Hold, strings.Join(res.Hold, "; "), version
	}
	return pipeline.Allow, "tool calls: " + strings.Join(names(calls), ", "), version
}

func names(calls []Call) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = c.Name
	}
	return out
}

// replace throws away the provider's response and sends an error
// instead. The provider's headers (content type, length, encoding) are
// cleared first: they describe a body the caller will never get. Our own
// headers stay, and X-Aigov-Decision is updated to the final decision.
func replace(w http.ResponseWriter, status int, action pipeline.Action, errType, message string) {
	h := w.Header()
	for k := range h {
		if k != "X-Request-Id" && k != "X-Aigov-Approval-Id" && !strings.HasPrefix(k, "X-Ratelimit-") {
			delete(h, k)
		}
	}
	if action != "" {
		h.Set("X-Aigov-Decision", string(action))
	}
	apierr.Write(w, status, errType, message)
}

// holdingWriter collects the whole response instead of sending it.
type holdingWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (h *holdingWriter) Header() http.Header { return h.header }

func (h *holdingWriter) WriteHeader(code int) {
	if h.status == 0 {
		h.status = code
	}
}

func (h *holdingWriter) Write(p []byte) (int, error) {
	if h.status == 0 {
		h.status = http.StatusOK
	}
	return h.body.Write(p)
}

// Flush does nothing: nothing may reach the caller before the check.
func (h *holdingWriter) Flush() {}

// release sends the held response on unchanged. A write error means the
// caller hung up; there is nothing left to do.
func (h *holdingWriter) release(w http.ResponseWriter) {
	if h.status == 0 {
		h.status = http.StatusOK
	}
	w.WriteHeader(h.status)
	w.Write(h.body.Bytes())
}
