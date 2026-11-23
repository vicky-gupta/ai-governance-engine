package approval

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
)

type fakeRecorder struct {
	entries []audit.Entry
	err     error
}

func (f *fakeRecorder) Record(_ context.Context, e audit.Entry) error {
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, e)
	return nil
}

func call(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestReviewFlow(t *testing.T) {
	s, pool := testStore(t, time.Hour)
	rec := &fakeRecorder{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	adminAPI, reviewAPI := AdminAPI(s, rec, log), ReviewAPI(s, rec, log)

	// An admin creates a reviewer; the token is in the response once.
	name := "clara-" + time.Now().Format("150405.000000000")
	w := call(t, adminAPI, "POST", "/admin/reviewers", "", `{"name":"`+name+`"}`)
	var created struct {
		Reviewer Reviewer
		Token    string
	}
	json.Unmarshal(w.Body.Bytes(), &created)
	if w.Code != http.StatusCreated || created.Token == "" {
		t.Fatalf("create reviewer: %d %s", w.Code, w.Body)
	}

	h := held(t, pool)
	id, err := s.Open(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}

	if w := call(t, reviewAPI, "GET", "/review/approvals", "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", w.Code)
	}
	if w := call(t, reviewAPI, "GET", "/review/approvals", "aigov_not-a-reviewer", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d, want 401", w.Code)
	}
	if w := call(t, reviewAPI, "GET", "/review/approvals", created.Token, ""); !strings.Contains(w.Body.String(), id) {
		t.Errorf("pending list does not contain the new approval: %s", w.Body)
	}

	// The reviewer opens it and sees the redacted request.
	w = call(t, reviewAPI, "GET", "/review/approvals/"+id, created.Token, "")
	var shown struct {
		Approval Approval
		Content  Content
	}
	json.Unmarshal(w.Body.Bytes(), &shown)
	if shown.Content.Messages[0].Text != h.Messages[0].Text || shown.Approval.ContentHash == "" {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}

	// Deciding needs the hash of what was seen.
	if w := call(t, reviewAPI, "POST", "/review/approvals/"+id+"/approve", created.Token, `{"note":"ok"}`); w.Code != http.StatusBadRequest {
		t.Errorf("no seen_hash: %d, want 400", w.Code)
	}
	if w := call(t, reviewAPI, "POST", "/review/approvals/"+id+"/approve", created.Token, `{"seen_hash":"abc"}`); w.Code != http.StatusConflict {
		t.Errorf("wrong seen_hash: %d, want 409", w.Code)
	}
	body := `{"seen_hash":"` + shown.Approval.ContentHash + `","note":"spoke to the applicant's advisor"}`
	if w := call(t, reviewAPI, "POST", "/review/approvals/"+id+"/approve", created.Token, body); w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if w := call(t, reviewAPI, "POST", "/review/approvals/"+id+"/reject", created.Token, body); w.Code != http.StatusConflict {
		t.Errorf("decide twice: %d, want 409", w.Code)
	}

	// The audit entry: the held request's ID, the reviewer, the content hash; not the note.
	last := rec.entries[len(rec.entries)-1]
	if last.RequestID != h.RequestID || last.Action != "approve" || last.Check != "approval" ||
		!strings.Contains(last.Reason, name) || !strings.Contains(last.Reason, shown.Approval.ContentHash) {
		t.Errorf("audit entry = %+v", last)
	}
	if strings.Contains(last.Reason, "advisor") {
		t.Error("the free-text note ended up in the audit log")
	}

	// A revoked reviewer can't do anything any more.
	if w := call(t, adminAPI, "DELETE", "/admin/reviewers/"+created.Reviewer.ID, "", ""); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d", w.Code)
	}
	if w := call(t, reviewAPI, "GET", "/review/approvals", created.Token, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("revoked reviewer: %d, want 401", w.Code)
	}
}

func TestDecisionNotAuditedIsReported(t *testing.T) {
	s, pool := testStore(t, time.Hour)
	ctx := context.Background()
	rec := &fakeRecorder{err: errors.New("db down")}
	_, token, _ := s.CreateReviewer(ctx, "dora-"+time.Now().Format("150405.000000000"))
	id, _ := s.Open(ctx, held(t, pool))
	a, _, _ := s.Get(ctx, id)

	w := call(t, ReviewAPI(s, rec, slog.New(slog.NewTextHandler(io.Discard, nil))),
		"POST", "/review/approvals/"+id+"/approve", token, `{"seen_hash":"`+a.ContentHash+`"}`)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when the audit write fails", w.Code)
	}
}
