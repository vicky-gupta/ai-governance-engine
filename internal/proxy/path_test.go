package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestKeepsUpstreamPathPrefix(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer upstream.Close()

	target, _ := url.Parse(upstream.URL + "/openai")
	New(target, "k", discardLogger()).ServeHTTP(httptest.NewRecorder(),
		httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`)))

	if gotPath != "/openai/v1/chat/completions" {
		t.Errorf("provider got path %q, want /openai/v1/chat/completions", gotPath)
	}
}
