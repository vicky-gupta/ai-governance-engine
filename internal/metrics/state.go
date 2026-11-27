package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vicky-gupta/ai-governance-engine/internal/health"
)

// Some numbers are not events to count but a state to look up: is Redis
// up, how many requests wait for a reviewer. These are read when
// Prometheus scrapes, so they are never stale and need no background job.

var (
	dependencyUpDesc = prometheus.NewDesc("aigov_dependency_up",
		"1 if the dependency answered its health check, 0 if not.",
		[]string{"dependency", "required"}, nil)
	approvalsPendingDesc = prometheus.NewDesc("aigov_approvals_pending",
		"Held requests and tool calls waiting for a reviewer, not yet expired.",
		nil, nil)
	policyDesc = prometheus.NewDesc("aigov_policy_info",
		"The policy version in force (always 1; the version is the label).",
		[]string{"version"}, nil)
)

// State reads the current state at scrape time. Every field is optional.
type State struct {
	Probes        []health.Probe
	Pending       func(ctx context.Context) (int, error)
	PolicyVersion func() string
}

// WatchState adds the state metrics.
func (m *Metrics) WatchState(s State) {
	m.reg.MustRegister(stateCollector(s))
}

type stateCollector State

func (c stateCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- dependencyUpDesc
	ch <- approvalsPendingDesc
	ch <- policyDesc
}

func (c stateCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	for _, r := range health.Run(ctx, c.Probes, 2*time.Second) {
		up := 1.0
		if r.Err != nil {
			up = 0
		}
		required := "false"
		if r.Required {
			required = "true"
		}
		ch <- prometheus.MustNewConstMetric(dependencyUpDesc, prometheus.GaugeValue, up, r.Name, required)
	}
	if c.Pending != nil {
		// If the count can't be read, leave the metric out rather than
		// report 0: "nothing waiting" would be a false all-clear.
		if n, err := c.Pending(ctx); err == nil {
			ch <- prometheus.MustNewConstMetric(approvalsPendingDesc, prometheus.GaugeValue, float64(n))
		}
	}
	if c.PolicyVersion != nil {
		ch <- prometheus.MustNewConstMetric(policyDesc, prometheus.GaugeValue, 1, c.PolicyVersion())
	}
}
