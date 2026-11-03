package admin

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// fakeStore records what the handler asked for, with no database.
type fakeStore struct {
	created registry.System
}

func (f *fakeStore) CreateSystem(_ context.Context, sys registry.System) (registry.System, error) {
	if sys.Name == "taken" {
		return registry.System{}, registry.ErrDuplicate
	}
	sys.ID, sys.Status = "sys-1", "active"
	f.created = sys
	return sys, nil
}

func (f *fakeStore) ListSystems(context.Context) ([]registry.System, error) {
	return []registry.System{{ID: "sys-1", Name: "loan-agent"}}, nil
}

func (f *fakeStore) CreateKey(_ context.Context, id string) (string, registry.Key, error) {
	if id != "sys-1" {
		return "", registry.Key{}, registry.ErrNotFound
	}
	return "aigov_secret", registry.Key{ID: "key-1", SystemID: id, Prefix: "aigov_secre"}, nil
}

func (f *fakeStore) RevokeKey(_ context.Context, id string) error {
	if id != "key-1" {
		return registry.ErrNotFound
	}
	return nil
}

const token = "test-admin-token-123"

func do(t *testing.T, h http.Handler, method, path, body, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func newHandler() (http.Handler, *fakeStore) {
	store := &fakeStore{}
	return New(store, token, slog.New(slog.NewTextHandler(io.Discard, nil))), store
}

func TestRequiresAdminToken(t *testing.T) {
	h, _ := newHandler()
	for _, auth := range []string{"", "wrong-token"} {
		if rec := do(t, h, "GET", "/admin/systems", "", auth); rec.Code != http.StatusUnauthorized {
			t.Errorf("auth %q: status = %d, want 401", auth, rec.Code)
		}
	}
	if rec := do(t, h, "GET", "/admin/systems", "", token); rec.Code != http.StatusOK {
		t.Errorf("correct token: status = %d, want 200", rec.Code)
	}
}

func TestCreateSystem(t *testing.T) {
	h, store := newHandler()

	valid := `{"name":"loan-agent","owner":"credit-team","purpose":"credit scoring","risk_tier":"high"}`
	rec := do(t, h, "POST", "/admin/systems", valid, token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %s)", rec.Code, rec.Body)
	}
	if store.created.Name != "loan-agent" || store.created.RiskTier != registry.RiskHigh {
		t.Errorf("store received %+v", store.created)
	}

	cases := map[string]struct {
		body string
		want int
	}{
		"bad JSON":       {`{`, http.StatusBadRequest},
		"unknown field":  {`{"name":"a","owner":"b","purpose":"c","risk_tier":"high","x":1}`, http.StatusBadRequest},
		"missing owner":  {`{"name":"a","purpose":"c","risk_tier":"high"}`, http.StatusBadRequest},
		"invalid tier":   {`{"name":"a","owner":"b","purpose":"c","risk_tier":"medium"}`, http.StatusBadRequest},
		"duplicate name": {`{"name":"taken","owner":"b","purpose":"c","risk_tier":"high"}`, http.StatusConflict},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if rec := do(t, h, "POST", "/admin/systems", tc.body, token); rec.Code != tc.want {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

func TestCreateAndRevokeKey(t *testing.T) {
	h, _ := newHandler()

	rec := do(t, h, "POST", "/admin/systems/sys-1/keys", "", token)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	var body struct {
		Key string `json:"key"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if body.Key != "aigov_secret" {
		t.Errorf("key = %q, want the plaintext key in the response", body.Key)
	}

	if rec := do(t, h, "POST", "/admin/systems/unknown/keys", "", token); rec.Code != http.StatusNotFound {
		t.Errorf("unknown system: status = %d, want 404", rec.Code)
	}
	if rec := do(t, h, "DELETE", "/admin/keys/key-1", "", token); rec.Code != http.StatusNoContent {
		t.Errorf("revoke: status = %d, want 204", rec.Code)
	}
	if rec := do(t, h, "DELETE", "/admin/keys/unknown", "", token); rec.Code != http.StatusNotFound {
		t.Errorf("revoke unknown: status = %d, want 404", rec.Code)
	}
}
