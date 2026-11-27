package health

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func up(context.Context) error   { return nil }
func down(context.Context) error { return errors.New("dial tcp 10.0.0.5:6379: connection refused") }

func TestReadyz(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name       string
		probes     []Probe
		wantCode   int
		wantStatus string
	}{
		{"all up", []Probe{{"postgres", true, up}, {"redis", false, up}}, 200, "ready"},
		{"optional down", []Probe{{"postgres", true, up}, {"redis", false, down}}, 200, "degraded"},
		{"required down", []Probe{{"postgres", true, down}, {"redis", false, up}}, 503, "not ready"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			Handler(tc.probes, log).ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
			var body struct {
				Status string
				Checks map[string]string
			}
			json.Unmarshal(w.Body.Bytes(), &body)
			if w.Code != tc.wantCode || body.Status != tc.wantStatus {
				t.Errorf("got %d %q, want %d %q", w.Code, body.Status, tc.wantCode, tc.wantStatus)
			}
			if strings.Contains(w.Body.String(), "10.0.0.5") {
				t.Error("an internal address leaked into the public response")
			}
		})
	}
}

// A slow dependency times out on its own; it doesn't hold up the others
// or the answer.
func TestSlowProbeTimesOut(t *testing.T) {
	slow := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	start := time.Now()
	res := Run(context.Background(), []Probe{{"ner", true, slow}, {"postgres", true, up}}, 50*time.Millisecond)
	if time.Since(start) > time.Second {
		t.Fatal("Run waited far longer than the timeout")
	}
	if res[0].Err == nil || res[1].Err != nil {
		t.Errorf("results = %+v", res)
	}
}
