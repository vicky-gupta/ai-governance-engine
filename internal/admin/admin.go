// Package admin is the management API for the AI system registry:
// registering systems and issuing or revoking their API keys.
package admin

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// Store is what the admin API needs from the registry.
type Store interface {
	CreateSystem(ctx context.Context, sys registry.System) (registry.System, error)
	ListSystems(ctx context.Context) ([]registry.System, error)
	CreateKey(ctx context.Context, systemID string) (string, registry.Key, error)
	RevokeKey(ctx context.Context, keyID string) error
}

// AuditLog is what the admin API needs from the audit log.
type AuditLog interface {
	List(ctx context.Context, limit int) ([]audit.Entry, error)
	Verify(ctx context.Context) (audit.VerifyResult, error)
}

type handler struct {
	store Store
	audit AuditLog
	log   *slog.Logger
}

// New returns the admin API. Every route requires
// 'Authorization: Bearer <admin token>'.
func New(store Store, auditLog AuditLog, token string, log *slog.Logger) http.Handler {
	h := &handler{store: store, audit: auditLog, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/systems", h.createSystem)
	mux.HandleFunc("GET /admin/systems", h.listSystems)
	mux.HandleFunc("POST /admin/systems/{id}/keys", h.createKey)
	mux.HandleFunc("DELETE /admin/keys/{id}", h.revokeKey)
	mux.HandleFunc("GET /admin/audit", h.listAudit)
	mux.HandleFunc("GET /admin/audit/verify", h.verifyAudit)
	return requireToken(token, mux)
}

func requireToken(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		// Constant-time comparison: the time taken doesn't reveal how many
		// characters of a guess were right.
		if subtle.ConstantTimeCompare(got, want) != 1 {
			apierr.Write(w, http.StatusUnauthorized, "invalid_request_error", "invalid admin token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type createSystemRequest struct {
	Name     string            `json:"name"`
	Owner    string            `json:"owner"`
	Purpose  string            `json:"purpose"`
	RiskTier registry.RiskTier `json:"risk_tier"`
}

func (h *handler) createSystem(w http.ResponseWriter, r *http.Request) {
	var req createSystemRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB is plenty
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierr.Write(w, http.StatusBadRequest, "invalid_request_error", "invalid JSON: "+err.Error())
		return
	}
	if req.Name == "" || req.Owner == "" || req.Purpose == "" {
		apierr.Write(w, http.StatusBadRequest, "invalid_request_error", "name, owner and purpose are required")
		return
	}
	if !req.RiskTier.Valid() {
		apierr.Write(w, http.StatusBadRequest, "invalid_request_error",
			"risk_tier must be one of: minimal, limited, high, unacceptable")
		return
	}

	sys, err := h.store.CreateSystem(r.Context(), registry.System{
		Name: req.Name, Owner: req.Owner, Purpose: req.Purpose, RiskTier: req.RiskTier,
	})
	if errors.Is(err, registry.ErrDuplicate) {
		apierr.Write(w, http.StatusConflict, "invalid_request_error", "an AI system with this name already exists")
		return
	}
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sys)
}

func (h *handler) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			apierr.Write(w, http.StatusBadRequest, "invalid_request_error", "limit must be between 1 and 500")
			return
		}
		limit = n
	}
	entries, err := h.audit.List(r.Context(), limit)
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": entries})
}

func (h *handler) verifyAudit(w http.ResponseWriter, r *http.Request) {
	res, err := h.audit.Verify(r.Context())
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *handler) listSystems(w http.ResponseWriter, r *http.Request) {
	systems, err := h.store.ListSystems(r.Context())
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": systems})
}

func (h *handler) createKey(w http.ResponseWriter, r *http.Request) {
	plain, key, err := h.store.CreateKey(r.Context(), r.PathValue("id"))
	if errors.Is(err, registry.ErrNotFound) {
		apierr.Write(w, http.StatusNotFound, "invalid_request_error", "AI system not found")
		return
	}
	if err != nil {
		h.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"key":     plain,
		"details": key,
		"warning": "Store this key now. It cannot be shown again.",
	})
}

func (h *handler) revokeKey(w http.ResponseWriter, r *http.Request) {
	err := h.store.RevokeKey(r.Context(), r.PathValue("id"))
	if errors.Is(err, registry.ErrNotFound) {
		apierr.Write(w, http.StatusNotFound, "invalid_request_error", "key not found or already revoked")
		return
	}
	if err != nil {
		h.internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) internalError(w http.ResponseWriter, err error) {
	h.log.Error("admin request failed", "error", err)
	apierr.Write(w, http.StatusInternalServerError, "gateway_error", "internal error")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
