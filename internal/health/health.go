// Package health checks the services the gateway depends on (Postgres,
// Redis, the NER sidecar), for /readyz and for the metrics.
package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Probe checks one dependency.
//
// Required says what happens when it is down. Without a required
// dependency the gateway can't serve requests safely (it blocks them), so
// it should get no traffic: /readyz answers 503. Without an optional one
// it still works, with less protection (no rate limits without Redis), so
// /readyz answers 200 with status "degraded".
type Probe struct {
	Name     string
	Required bool
	Check    func(ctx context.Context) error
}

// Result is what one probe found.
type Result struct {
	Name     string
	Required bool
	Err      error // nil means up
}

// Run runs every probe at the same time, each with its own timeout, so
// one slow dependency can't hide the state of the others.
func Run(ctx context.Context, probes []Probe, timeout time.Duration) []Result {
	results := make([]Result, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			results[i] = Result{Name: p.Name, Required: p.Required, Err: p.Check(pctx)}
		}()
	}
	wg.Wait()
	return results
}

// Status sums results up: "ready", "degraded" (an optional dependency is
// down) or "not ready" (a required one is down).
func Status(results []Result) string {
	status := "ready"
	for _, r := range results {
		if r.Err == nil {
			continue
		}
		if r.Required {
			return "not ready"
		}
		status = "degraded"
	}
	return status
}

// Handler serves /readyz. The response says which dependency is down but
// not why: error messages contain internal addresses, and /readyz is on
// the public port. The reasons go to the log.
func Handler(probes []Probe, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		results := Run(r.Context(), probes, 2*time.Second)
		checks := map[string]string{}
		for _, res := range results {
			checks[res.Name] = "ok"
			if res.Err != nil {
				checks[res.Name] = "down"
				log.Warn("readiness: dependency down", "dependency", res.Name,
					"required", res.Required, "error", res.Err)
			}
		}
		status := Status(results)
		code := http.StatusOK
		if status == "not ready" {
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]any{"status": status, "checks": checks})
	})
}
