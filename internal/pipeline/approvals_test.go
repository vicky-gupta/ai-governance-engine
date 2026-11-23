package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// fakeApprovals opens approval "ap-1" and lets "ap-1" be used once.
type fakeApprovals struct {
	opened  []Held
	openErr error
	used    bool
	useHash string
}

func (f *fakeApprovals) Open(_ context.Context, h Held) (string, error) {
	if f.openErr != nil {
		return "", f.openErr
	}
	f.opened = append(f.opened, h)
	return "ap-1", nil
}

func (f *fakeApprovals) Use(_ context.Context, id, _, requestHash, _ string) (string, error) {
	f.useHash = requestHash
	if id != "ap-1" {
		return "", errors.New("approval not found")
	}
	if f.used {
		return "", errors.New("approval has already been used")
	}
	f.used = true
	return "anna", nil
}

// send runs one request through a pipeline that holds everything, with an
// optional approval header.
func send(t *testing.T, ap Approvals, rec *fakeRecorder, approvalHeader string) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })
	p := New(fakeCheck{name: "policy", action: Hold})
	h := Middleware(p, rec, ap, slog.New(slog.NewTextHandler(io.Discard, nil)))(next)

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(validBody))
	req = req.WithContext(auth.WithSystem(req.Context(), registry.System{ID: "sys-1", Name: "loan-agent"}))
	if approvalHeader != "" {
		req.Header.Set(ApprovalHeader, approvalHeader)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w, reached
}

func TestHoldOpensAnApproval(t *testing.T) {
	ap, rec := &fakeApprovals{}, &fakeRecorder{}
	w, reached := send(t, ap, rec, "")

	if reached || w.Code != http.StatusForbidden || w.Result().Header.Get("X-Aigov-Approval-Id") != "ap-1" {
		t.Fatalf("reached=%v status=%d headers=%v", reached, w.Code, w.Header())
	}
	if !strings.Contains(w.Body.String(), ApprovalHeader+": ap-1") {
		t.Errorf("body should tell the caller how to send it again: %s", w.Body)
	}
	if len(ap.opened) != 1 || ap.opened[0].Messages[0].Text != "hello" || ap.opened[0].RequestHash == "" {
		t.Errorf("opened = %+v", ap.opened)
	}
	if e := rec.entries[0]; e.Action != "hold" || !strings.Contains(e.Reason, "approval ap-1") {
		t.Errorf("audit = %+v, want a hold naming the approval", e)
	}
}

func TestApprovedRequestGoesThroughOnce(t *testing.T) {
	ap, rec := &fakeApprovals{}, &fakeRecorder{}
	w, reached := send(t, ap, rec, "ap-1")
	if !reached {
		t.Fatalf("approved request did not reach the provider: %d %s", w.Code, w.Body)
	}
	e := rec.entries[0]
	if e.Action != "allow" || e.Check != "approval" || !strings.Contains(e.Reason, "approved by anna") || e.ForwardedHash == "" {
		t.Errorf("audit = %+v", e)
	}
	if ap.useHash != e.RequestHash {
		t.Error("the approval was checked against a different request hash than the one audited")
	}

	// The same approval a second time: refused.
	w, reached = send(t, ap, rec, "ap-1")
	if reached || w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "approval_invalid") {
		t.Errorf("second use: reached=%v %d %s", reached, w.Code, w.Body)
	}
}

func TestApprovalHeaderDoesNotSkipABlock(t *testing.T) {
	ap := &fakeApprovals{}
	p := New(fakeCheck{name: "rule", action: Block})
	h := Middleware(p, &fakeRecorder{}, ap, slog.New(slog.NewTextHandler(io.Discard, nil)))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("blocked request reached the provider") }))
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(validBody))
	req = req.WithContext(auth.WithSystem(req.Context(), registry.System{ID: "sys-1"}))
	req.Header.Set(ApprovalHeader, "ap-1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || ap.used {
		t.Errorf("status=%d used=%v; an approval must not turn a block into an allow", w.Code, ap.used)
	}
}

func TestHoldWhenApprovalsAreDown(t *testing.T) {
	ap, rec := &fakeApprovals{openErr: errors.New("db down")}, &fakeRecorder{}
	if w, reached := send(t, ap, rec, ""); reached || w.Code != http.StatusServiceUnavailable {
		t.Errorf("reached=%v status=%d, want 503", reached, w.Code)
	}
}
