package toolguard

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// fakeApprovals keeps one held answer under "tc-1"; "req-ap" is a request
// approval (something else); anything else can't be used.
type fakeApprovals struct {
	held     []pipeline.Held
	stored   []byte
	ctype    string
	openErr  error
	approved bool
	used     bool
}

func (f *fakeApprovals) OpenToolCalls(_ context.Context, h pipeline.Held, response []byte, contentType string) (string, error) {
	if f.openErr != nil {
		return "", f.openErr
	}
	f.held = append(f.held, h)
	f.stored, f.ctype = append([]byte(nil), response...), contentType
	return "tc-1", nil
}

func (f *fakeApprovals) UseToolCalls(_ context.Context, id, _, _, _ string) (string, []byte, string, error) {
	switch {
	case id == "req-ap":
		return "", nil, "", pipeline.ErrOtherKind
	case id != "tc-1":
		return "", nil, "", errors.New("approval not found")
	case !f.approved:
		return "", nil, "", errors.New("approval is still waiting for review")
	case f.used:
		return "", nil, "", errors.New("approval has already been used")
	}
	f.used = true
	return "anna", f.stored, f.ctype, nil
}

// sendWith sends a tool request through the guard; the fake provider
// answers with a refund tool call and counts how often it was asked.
func sendWith(t *testing.T, ap Approvals, rec *fakeRecorder, header string, providerCalls *int) *httptest.ResponseRecorder {
	t.Helper()
	req, _ := pipeline.ParseRequest([]byte(withTools))
	req.ID, req.BodyHash = "req-1", "hash-1"
	req.System = registry.System{ID: "sys-1", Name: "support-bot", RiskTier: registry.RiskLimited}

	provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*providerCalls++
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, jsonResponse("issue_refund"))
	})
	h := Middleware(&fakePolicy{}, rec, ap, slog.New(slog.NewTextHandler(io.Discard, nil)))(provider)
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r = r.WithContext(pipeline.WithRequest(r.Context(), req))
	if header != "" {
		r.Header.Set(pipeline.ApprovalHeader, header)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHeldToolCallIsApprovedAndGivenBack(t *testing.T) {
	ap, rec, calls := &fakeApprovals{}, &fakeRecorder{}, 0

	// 1. The refund is held; the answer is kept for the reviewer.
	w := sendWith(t, ap, rec, "", &calls)
	if w.Code != http.StatusForbidden || w.Result().Header.Get("X-Aigov-Approval-Id") != "tc-1" {
		t.Fatalf("hold: %d, headers sent %v", w.Code, w.Result().Header)
	}
	if !strings.Contains(w.Body.String(), pipeline.ApprovalHeader+": tc-1") {
		t.Errorf("body should say how to send it again: %s", w.Body)
	}
	if len(ap.held) != 1 || ap.held[0].ToolCalls[0].Name != "issue_refund" || string(ap.stored) != jsonResponse("issue_refund") {
		t.Fatalf("opened = %+v, stored = %s", ap.held, ap.stored)
	}
	if !strings.Contains(rec.entries[0].Reason, "approval tc-1") {
		t.Errorf("audit = %+v, want the hold to name the approval", rec.entries[0])
	}

	// 2. Before review: refused, and the model is not asked again.
	if w := sendWith(t, ap, rec, "tc-1", &calls); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "approval_invalid") {
		t.Errorf("before review: %d %s", w.Code, w.Body)
	}

	// 3. After approval: exactly the approved answer, without the model.
	ap.approved = true
	w = sendWith(t, ap, rec, "tc-1", &calls)
	if w.Code != http.StatusOK || w.Body.String() != jsonResponse("issue_refund") {
		t.Fatalf("after approval: %d %s", w.Code, w.Body)
	}
	if calls != 1 {
		t.Errorf("the model was asked %d times, want 1 (only the first time)", calls)
	}
	last := rec.entries[len(rec.entries)-1]
	if last.Action != "allow" || last.Check != "tool_calls" || !strings.Contains(last.Reason, "approved by anna") {
		t.Errorf("audit = %+v", last)
	}

	// 4. Once more: refused.
	if w := sendWith(t, ap, rec, "tc-1", &calls); w.Code != http.StatusForbidden {
		t.Errorf("second replay: %d, want 403", w.Code)
	}
}

func TestRequestApprovalIsLeftToThePipeline(t *testing.T) {
	calls := 0
	ap := &fakeApprovals{}
	sendWith(t, ap, &fakeRecorder{}, "req-ap", &calls)
	if calls != 1 {
		t.Errorf("a request approval should let the request go to the model; calls = %d", calls)
	}
}

func TestHoldWhenApprovalsAreDown(t *testing.T) {
	calls := 0
	w := sendWith(t, &fakeApprovals{openErr: errors.New("db down")}, &fakeRecorder{}, "", &calls)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "issue_refund") {
		t.Errorf("got %d %s, want 503 without the tool call", w.Code, w.Body)
	}
}
