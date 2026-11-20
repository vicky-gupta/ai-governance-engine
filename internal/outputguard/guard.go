// Package outputguard checks the text of a model's answer: personal data
// the model should not reveal, and content the policy forbids.
//
// The model never sees the caller's personal data (it was redacted on the
// way in), so personal data in an answer comes from the model itself:
// from its training data, or made up. Either way it must not reach the
// caller unchecked.
package outputguard

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/policy"
)

// Policy evaluates the answer rules. policy.Engine implements it.
type Policy interface {
	EvaluateResponse(ctx context.Context, input map[string]any) (policy.ResponseResult, string, error)
}

// Recorder writes audit entries. audit.Store implements it.
type Recorder interface {
	Record(ctx context.Context, e audit.Entry) error
}

const checkName = "response"

// flag is the audit action for a problem found in an answer that had
// already been streamed to the caller: recorded, but too late to stop.
const flag = "flag"

// Middleware checks every successful answer. It sits between the
// pipeline and the tool guard.
//
// A normal answer is held until it is checked, then passed on, cleaned
// up, or replaced by an error. A streamed answer can't be held without
// losing the point of streaming, so it passes through as it comes and is
// checked once it is complete; problems are then recorded, not stopped.
// That is why high-risk systems may not stream (see policies/aigov.rego).
func Middleware(p Policy, rec Recorder, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			req, ok := pipeline.RequestFrom(r)
			if !ok {
				log.Error("outputguard: no pipeline request in context")
				apierr.Write(w, http.StatusInternalServerError, "gateway_error", "internal error")
				return
			}
			g := &guardWriter{w: w}
			next.ServeHTTP(g, r)

			c := checker{p: p, rec: rec, log: log, req: req}
			switch {
			case g.streaming:
				c.afterStream(r.Context(), g.stream.String())
			case g.holding:
				c.answer(r.Context(), w, g.status, g.body.Bytes())
			}
		})
	}
}

type checker struct {
	p   Policy
	rec Recorder
	log *slog.Logger
	req *pipeline.Request
}

// answer checks a held, non-streamed answer and sends it on.
func (c checker) answer(ctx context.Context, w http.ResponseWriter, status int, body []byte) {
	ans, ok := parseAnswer(body)
	if !ok {
		send(w, status, body) // not JSON; nothing we can read
		return
	}
	text := ans.text()
	if text == "" {
		send(w, status, body) // e.g. only tool calls, checked by the tool guard
		return
	}
	found := pii.Find(text)

	deny, version, err := c.evaluate(ctx, text, kinds(found))
	switch {
	case err != nil:
		deny = []string{"answer policy could not be evaluated"}
	case len(deny) == 0 && len(found) == 0:
		send(w, status, body) // clean: passed on unchanged, nothing to record
		return
	}

	if len(deny) > 0 {
		reason := strings.Join(deny, "; ")
		if !c.record(ctx, pipeline.Block, reason, version) {
			replace(w, http.StatusServiceUnavailable, "", "gateway_error", "audit log unavailable; answer withheld")
			return
		}
		replace(w, http.StatusForbidden, pipeline.Block, "policy_violation", "answer blocked: "+reason)
		return
	}

	// Personal data, but nothing that stops the answer: remove it.
	ans.eachText(func(t string) string { return redact(t, pii.Find(t)) })
	cleaned, err := json.Marshal(ans.doc)
	if err != nil {
		replace(w, http.StatusInternalServerError, "", "gateway_error", "internal error")
		return
	}
	reason := "personal data removed from the answer: " + strings.Join(kinds(found), ", ")
	if !c.record(ctx, pipeline.Modify, reason, version) {
		replace(w, http.StatusServiceUnavailable, "", "gateway_error", "audit log unavailable; answer withheld")
		return
	}
	w.Header().Set("X-Aigov-Decision", string(pipeline.Modify))
	send(w, status, cleaned)
}

// afterStream checks an answer that has already been streamed. It can
// only record what it finds.
func (c checker) afterStream(ctx context.Context, text string) {
	if text == "" {
		return
	}
	found := pii.Find(text)
	deny, version, err := c.evaluate(ctx, text, kinds(found))
	if err != nil {
		deny = []string{"answer policy could not be evaluated"}
	}
	var problems []string
	if len(found) > 0 {
		problems = append(problems, "personal data in the answer: "+strings.Join(kinds(found), ", "))
	}
	problems = append(problems, deny...)
	if len(problems) == 0 {
		return
	}
	reason := "found after the answer was streamed: " + strings.Join(problems, "; ")
	c.log.Warn("outputguard: problem in a streamed answer", "request_id", c.req.ID,
		"ai_system", c.req.System.Name, "reason", reason)
	c.record(ctx, flag, reason, version)
}

func (c checker) evaluate(ctx context.Context, text string, piiKinds []string) ([]string, string, error) {
	input := map[string]any{
		"system": map[string]any{
			"name":      c.req.System.Name,
			"owner":     c.req.System.Owner,
			"risk_tier": string(c.req.System.RiskTier),
		},
		"model": c.req.Model,
		"text":  text,
		"pii":   piiKinds,
	}
	res, version, err := c.p.EvaluateResponse(ctx, input)
	return res.Deny, version, err
}

// record writes the audit entry for this answer and reports whether it
// was saved.
func (c checker) record(ctx context.Context, action pipeline.Action, reason, version string) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	err := c.rec.Record(ctx, audit.Entry{
		RequestID:     c.req.ID,
		SystemID:      c.req.System.ID,
		SystemName:    c.req.System.Name,
		Model:         c.req.Model,
		Provider:      c.req.Provider,
		Region:        c.req.Region,
		PolicyVersion: version,
		Action:        string(action),
		Check:         checkName,
		Reason:        reason,
	})
	if err != nil {
		c.log.Error("outputguard: audit record failed", "request_id", c.req.ID, "error", err)
		return false
	}
	c.log.Info("answer checked", "request_id", c.req.ID, "ai_system", c.req.System.Name,
		"action", action, "reason", reason)
	return true
}

// send writes a held answer, with a Content-Length that fits the body.
func send(w http.ResponseWriter, status int, body []byte) {
	if w.Header().Get("Content-Length") != "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}
	w.WriteHeader(status)
	w.Write(body)
}

// replace throws away the answer and sends an error instead, clearing the
// provider's headers first (same as in the tool guard).
func replace(w http.ResponseWriter, status int, action pipeline.Action, errType, message string) {
	h := w.Header()
	for k := range h {
		if k != "X-Request-Id" && !strings.HasPrefix(k, "X-Ratelimit-") {
			delete(h, k)
		}
	}
	if action != "" {
		h.Set("X-Aigov-Decision", string(action))
	}
	apierr.Write(w, status, errType, message)
}

// guardWriter decides at the first WriteHeader what to do with a
// response: hold it (a successful normal answer), or let it through
// (a stream, which it reads on the way, or an error).
type guardWriter struct {
	w         http.ResponseWriter
	status    int
	holding   bool
	streaming bool
	body      bytes.Buffer
	stream    streamText
}

func (g *guardWriter) Header() http.Header { return g.w.Header() }

func (g *guardWriter) WriteHeader(code int) {
	if g.status != 0 {
		return
	}
	g.status = code
	if code != http.StatusOK {
		g.w.WriteHeader(code) // errors pass through unchecked
		return
	}
	if strings.HasPrefix(g.w.Header().Get("Content-Type"), "text/event-stream") {
		g.streaming = true
		g.w.WriteHeader(code)
		return
	}
	g.holding = true
}

func (g *guardWriter) Write(p []byte) (int, error) {
	if g.status == 0 {
		g.WriteHeader(http.StatusOK)
	}
	if g.holding {
		return g.body.Write(p)
	}
	if g.streaming {
		g.stream.Write(p)
	}
	return g.w.Write(p)
}

// Flush passes on for streams and errors; a held answer is not sent yet.
func (g *guardWriter) Flush() {
	if !g.holding {
		http.NewResponseController(g.w).Flush()
	}
}
