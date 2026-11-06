package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouter(t *testing.T) {
	var hit string
	providers := map[string]http.Handler{
		"groq":    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = "groq" }),
		"mistral": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = "mistral" }),
	}
	// In tests, the chosen provider comes from a header.
	pick := func(r *http.Request) string { return r.Header.Get("X-Test-Provider") }
	router := NewRouter(providers, pick, discardLogger())

	for _, name := range []string{"groq", "mistral"} {
		hit = ""
		req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
		req.Header.Set("X-Test-Provider", name)
		router.ServeHTTP(httptest.NewRecorder(), req)
		if hit != name {
			t.Errorf("routed to %q, want %q", hit, name)
		}
	}

	hit = ""
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", nil))
	if hit != "" || rec.Code != http.StatusInternalServerError {
		t.Errorf("no provider: hit=%q status=%d, want nothing hit and 500", hit, rec.Code)
	}
}
