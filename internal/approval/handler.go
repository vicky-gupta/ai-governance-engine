package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
)

// Recorder writes audit entries. audit.Store implements it.
type Recorder interface {
	Record(ctx context.Context, e audit.Entry) error
}

type api struct {
	store *Store
	rec   Recorder
	log   *slog.Logger
}

// ReviewAPI is the reviewers' API under /review/. Every call needs a
// reviewer's own token, so every decision has a name on it.
func ReviewAPI(store *Store, rec Recorder, log *slog.Logger) http.Handler {
	a := &api{store: store, rec: rec, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /review/approvals", a.list)
	mux.HandleFunc("GET /review/approvals/{id}", a.get)
	mux.HandleFunc("POST /review/approvals/{id}/approve", a.decide(true))
	mux.HandleFunc("POST /review/approvals/{id}/reject", a.decide(false))
	return a.requireReviewer(mux)
}

// AdminAPI manages reviewers under /admin/reviewers. It must be wrapped
// in the admin token check.
func AdminAPI(store *Store, rec Recorder, log *slog.Logger) http.Handler {
	a := &api{store: store, rec: rec, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/reviewers", a.createReviewer)
	mux.HandleFunc("GET /admin/reviewers", a.listReviewers)
	mux.HandleFunc("DELETE /admin/reviewers/{id}", a.revokeReviewer)
	return mux
}

type reviewerKey struct{}

func (a *api) requireReviewer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			apierr.Write(w, http.StatusUnauthorized, "invalid_request_error", "missing reviewer token")
			return
		}
		rv, err := a.store.ReviewerByToken(r.Context(), token)
		if errors.Is(err, ErrNotFound) {
			apierr.Write(w, http.StatusUnauthorized, "invalid_request_error", "invalid reviewer token")
			return
		}
		if err != nil {
			a.internalError(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reviewerKey{}, rv)))
	})
}

// list: ?status=pending (the default), approved, rejected or used.
func (a *api) list(w http.ResponseWriter, r *http.Request) {
	status := Status(r.URL.Query().Get("status"))
	if status == "" {
		status = Pending
	}
	switch status {
	case Pending, Approved, Rejected, Used:
	default:
		apierr.Write(w, http.StatusBadRequest, "invalid_request_error",
			"status must be pending, approved, rejected or used")
		return
	}
	rows, err := a.store.List(r.Context(), status)
	if err != nil {
		a.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

// get shows one approval with the content to decide on. content_hash is
// what the reviewer sends back with their decision.
func (a *api) get(w http.ResponseWriter, r *http.Request) {
	ap, content, err := a.store.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		apierr.Write(w, http.StatusNotFound, "invalid_request_error", err.Error())
		return
	}
	if err != nil {
		a.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approval": ap, "content": content})
}

type decisionRequest struct {
	SeenHash string `json:"seen_hash"` // content_hash of what the reviewer looked at
	Note     string `json:"note"`
}

func (a *api) decide(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rv := r.Context().Value(reviewerKey{}).(Reviewer)
		var req decisionRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || req.SeenHash == "" {
			apierr.Write(w, http.StatusBadRequest, "invalid_request_error",
				"body must be JSON with seen_hash (the content_hash you reviewed) and an optional note")
			return
		}

		ap, err := a.store.Decide(r.Context(), r.PathValue("id"), rv.ID, approve, req.SeenHash, req.Note)
		switch {
		case errors.Is(err, ErrNotFound):
			apierr.Write(w, http.StatusNotFound, "invalid_request_error", err.Error())
			return
		case errors.Is(err, ErrNotPending), errors.Is(err, ErrExpired), errors.Is(err, ErrStaleView):
			apierr.Write(w, http.StatusConflict, "invalid_request_error", err.Error())
			return
		case err != nil:
			a.internalError(w, err)
			return
		}

		// The audit entry names the reviewer and the exact content they
		// decided on. The note stays in the approvals table: it is free text
		// and could contain personal data, which the audit log must not.
		action := "reject"
		if approve {
			action = "approve"
		}
		_, content, _ := a.store.Get(r.Context(), ap.ID)
		err = a.rec.Record(r.Context(), audit.Entry{
			RequestID:  ap.RequestID,
			SystemID:   ap.SystemID,
			SystemName: content.SystemName,
			Model:      content.Model,
			Action:     action,
			Check:      "approval",
			Reason: fmt.Sprintf("approval %s: %sd by reviewer %s after seeing content sha256:%s",
				ap.ID, action, rv.Name, ap.ContentHash),
		})
		if err != nil {
			a.log.Error("approval decided but not audited", "approval", ap.ID, "error", err)
			apierr.Write(w, http.StatusInternalServerError, "gateway_error",
				"decision saved, but the audit record failed")
			return
		}
		a.log.Info("approval decided", "approval", ap.ID, "action", action, "reviewer", rv.Name)
		writeJSON(w, http.StatusOK, ap)
	}
}

func (a *api) createReviewer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		apierr.Write(w, http.StatusBadRequest, "invalid_request_error", `body must be {"name": "..."}`)
		return
	}
	rv, token, err := a.store.CreateReviewer(r.Context(), strings.TrimSpace(req.Name))
	if errors.Is(err, ErrDuplicate) {
		apierr.Write(w, http.StatusConflict, "invalid_request_error", err.Error())
		return
	}
	if err != nil {
		a.internalError(w, err)
		return
	}
	if err := a.recordAdmin(r.Context(), "admin.create_reviewer", "reviewer "+rv.Name+" created"); err != nil {
		apierr.Write(w, http.StatusInternalServerError, "gateway_error", "reviewer created, but the audit record failed")
		return
	}
	// The token is shown once and never again.
	writeJSON(w, http.StatusCreated, map[string]any{"reviewer": rv, "token": token})
}

func (a *api) listReviewers(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.ListReviewers(r.Context())
	if err != nil {
		a.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (a *api) revokeReviewer(w http.ResponseWriter, r *http.Request) {
	err := a.store.RevokeReviewer(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		apierr.Write(w, http.StatusNotFound, "invalid_request_error", "reviewer not found or already revoked")
		return
	}
	if err != nil {
		a.internalError(w, err)
		return
	}
	if err := a.recordAdmin(r.Context(), "admin.revoke_reviewer", "reviewer "+r.PathValue("id")+" revoked"); err != nil {
		apierr.Write(w, http.StatusInternalServerError, "gateway_error", "reviewer revoked, but the audit record failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *api) recordAdmin(ctx context.Context, action, reason string) error {
	err := a.rec.Record(ctx, audit.Entry{
		RequestID: newID(), SystemName: "admin", Action: action, Reason: reason,
	})
	if err != nil {
		a.log.Error("admin action not audited", "action", action, "error", err)
	}
	return err
}

// newID makes an ID for audit entries that don't belong to a chat request
// (the same as the admin API's).
func newID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *api) internalError(w http.ResponseWriter, err error) {
	a.log.Error("approval API error", "error", err)
	apierr.Write(w, http.StatusInternalServerError, "gateway_error", "internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
