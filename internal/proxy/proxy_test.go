package proxy

import (
	"bufio"
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestForwardsRequestAndSwapsKey(t *testing.T) {
	var gotAuth, gotPath, gotBody string

	// A fake provider that records what it received.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"chatcmpl-123"}`)
	}))
	defer upstream.Close()

	target, _ := url.Parse(upstream.URL)
	p := New(target, "sk-provider-key", discardLogger())

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"test"}`))
	req.Header.Set("Authorization", "Bearer caller-key")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotAuth != "Bearer sk-provider-key" {
		t.Errorf("provider got Authorization %q, want the gateway's key", gotAuth)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("provider got path %q", gotPath)
	}
	if gotBody != `{"model":"test"}` {
		t.Errorf("provider got body %q", gotBody)
	}
	if rec.Body.String() != `{"id":"chatcmpl-123"}` {
		t.Errorf("client got body %q", rec.Body.String())
	}
}

func TestStreamsWithoutBuffering(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }

	// A fake provider that sends one chunk, then waits before finishing.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()

	target, _ := url.Parse(upstream.URL)
	gateway := httptest.NewServer(New(target, "k", discardLogger()))
	defer gateway.Close()
	defer unblock() // runs first, so the servers can shut down

	resp, err := http.Post(gateway.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// The first chunk must reach us while the provider is still waiting.
	// If the gateway buffered the response, this would time out.
	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(resp.Body).ReadString('\n')
		lines <- line
	}()

	select {
	case line := <-lines:
		if line != "data: first\n" {
			t.Errorf("first line = %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first chunk did not arrive: the gateway is buffering the stream")
	}
}

func TestProviderDownReturns502(t *testing.T) {
	// Start and immediately stop a server, so its address refuses connections.
	dead := httptest.NewServer(http.NotFoundHandler())
	target, _ := url.Parse(dead.URL)
	dead.Close()

	rec := httptest.NewRecorder()
	New(target, "k", discardLogger()).ServeHTTP(rec,
		httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`)))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "gateway_error") {
		t.Errorf("body = %q, want an OpenAI-style error", rec.Body.String())
	}
}
func TestRenamesUpstreamRequestID(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "provider-123")
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)

	// The gateway has already set its own ID before the proxy runs.
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "gateway-abc")
	New(target, "k", discardLogger()).ServeHTTP(rec,
		httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`)))

	if got := rec.Header().Values("X-Request-ID"); len(got) != 1 || got[0] != "gateway-abc" {
		t.Errorf("X-Request-ID = %v, want only the gateway's ID", got)
	}
	if got := rec.Header().Get("X-Upstream-Request-ID"); got != "provider-123" {
		t.Errorf("X-Upstream-Request-ID = %q, want the provider's ID", got)
	}
}

// The gateway reads provider responses (token usage, tool calls), so it
// must get them uncompressed, even when the caller asks for gzip.
func TestResponsesReachTheGatewayUncompressed(t *testing.T) {
	const body = `{"usage":{"total_tokens":42}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			io.WriteString(gz, body)
			gz.Close()
			return
		}
		io.WriteString(w, body)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Accept-Encoding", "gzip, deflate") // what the OpenAI Python SDK sends
	rec := httptest.NewRecorder()
	New(target, "k", discardLogger()).ServeHTTP(rec, req)

	if rec.Body.String() != body || rec.Header().Get("Content-Encoding") != "" {
		t.Errorf("gateway saw %q (Content-Encoding %q), want the plain JSON",
			rec.Body.String(), rec.Header().Get("Content-Encoding"))
	}
}
