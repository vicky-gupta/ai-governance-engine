// Package metrics exposes the gateway's numbers in the Prometheus format:
// traffic and latency, every governance decision, the time each check
// adds, provider latency, tokens, and the state of the dependencies.
//
// Labels are kept to things there are few of (routes, AI systems,
// checks, providers), never request IDs, users or prompt text: every
// distinct label value is a new time series held in memory.
package metrics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/usage"
)

// Metrics holds every metric. It uses its own registry instead of the
// global one, so tests can make a fresh one each time.
type Metrics struct {
	reg *prometheus.Registry

	httpRequests      *prometheus.CounterVec
	httpDuration      *prometheus.HistogramVec
	decisions         *prometheus.CounterVec
	auditFailures     prometheus.Counter
	checkDuration     *prometheus.HistogramVec
	upstreamDuration  *prometheus.HistogramVec
	upstreamResponses *prometheus.CounterVec
	tokens            *prometheus.CounterVec
	rateLimitFailOpen *prometheus.CounterVec
}

// Model calls take seconds, sometimes minutes; checks take microseconds
// to milliseconds. They need different buckets.
var (
	slowBuckets = []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}
	fastBuckets = []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5}
)

func New() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aigov_http_requests_total",
			Help: "HTTP requests handled, by route and status code.",
		}, []string{"route", "code"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "aigov_http_request_duration_seconds",
			Help:    "Time to handle an HTTP request, including the provider's time.",
			Buckets: slowBuckets,
		}, []string{"route"}),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aigov_decisions_total",
			Help: "Governance decisions written to the audit log, by AI system, check and action.",
		}, []string{"ai_system", "check", "action"}),
		auditFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "aigov_audit_write_failures_total",
			Help: "Audit log writes that failed. Each one is a request or response withheld.",
		}),
		checkDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "aigov_check_duration_seconds",
			Help:    "Time each governance check adds to a request.",
			Buckets: fastBuckets,
		}, []string{"check"}),
		upstreamDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "aigov_upstream_duration_seconds",
			Help:    "Time the provider took, until its response was complete.",
			Buckets: slowBuckets,
		}, []string{"provider"}),
		upstreamResponses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aigov_upstream_responses_total",
			Help: "Provider responses, by provider and status code.",
		}, []string{"provider", "code"}),
		tokens: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aigov_tokens_total",
			Help: "Tokens used, as reported by the provider, by AI system, provider and kind.",
		}, []string{"ai_system", "provider", "kind"}),
		rateLimitFailOpen: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "aigov_ratelimit_fail_open_total",
			Help: "Requests let through without a rate limit check because the counter (Redis) was unavailable.",
		}, []string{"ai_system"}),
	}
	m.reg.MustRegister(
		m.httpRequests, m.httpDuration, m.decisions, m.auditFailures, m.checkDuration,
		m.upstreamDuration, m.upstreamResponses, m.tokens, m.rateLimitFailOpen,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Handler serves /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// ObserveHTTP counts one finished request. route is the pattern that
// matched ("POST /v1/chat/completions"), never the raw path: raw paths
// contain IDs, and anyone can send any path.
func (m *Metrics) ObserveHTTP(route string, code int, d time.Duration) {
	if route == "" {
		route = "unmatched"
	}
	m.httpRequests.WithLabelValues(route, strconv.Itoa(code)).Inc()
	m.httpDuration.WithLabelValues(route).Observe(d.Seconds())
}

// ObserveStep records how long one pipeline check took.
func (m *Metrics) ObserveStep(s pipeline.Step) {
	m.checkDuration.WithLabelValues(s.Check).Observe(s.Duration.Seconds())
}

// RateLimitFailOpen counts a request that skipped the rate limit.
func (m *Metrics) RateLimitFailOpen(aiSystem string) {
	m.rateLimitFailOpen.WithLabelValues(aiSystem).Inc()
}

// AuditRecorder is the audit log as the checks use it.
type AuditRecorder interface {
	Record(ctx context.Context, e audit.Entry) error
}

// Audit wraps the audit log so every decision written to it is counted.
// Only written decisions are counted: the metric never shows something
// the audit log doesn't have.
func (m *Metrics) Audit(next AuditRecorder) AuditRecorder {
	return auditRecorder{next: next, m: m}
}

type auditRecorder struct {
	next AuditRecorder
	m    *Metrics
}

func (a auditRecorder) Record(ctx context.Context, e audit.Entry) error {
	if err := a.next.Record(ctx, e); err != nil {
		a.m.auditFailures.Inc()
		return err
	}
	check := e.Check
	if check == "" {
		check = "pipeline" // allowed or modified: no single check decided
	}
	a.m.decisions.WithLabelValues(e.SystemName, check, e.Action).Inc()
	return nil
}

// Usage wraps the usage store so recorded tokens are counted too.
func (m *Metrics) Usage(next usage.Recorder) usage.Recorder {
	return usageRecorder{next: next, m: m}
}

type usageRecorder struct {
	next usage.Recorder
	m    *Metrics
}

func (u usageRecorder) Record(ctx context.Context, r usage.Record) error {
	if err := u.next.Record(ctx, r); err != nil {
		return err
	}
	u.m.tokens.WithLabelValues(r.SystemName, r.Provider, "prompt").Add(float64(r.PromptTokens))
	u.m.tokens.WithLabelValues(r.SystemName, r.Provider, "completion").Add(float64(r.CompletionTokens))
	return nil
}

// Upstream wraps one provider's proxy to time it. For a streamed
// response this is the time until the last chunk.
func (m *Metrics) Upstream(provider string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		m.upstreamDuration.WithLabelValues(provider).Observe(time.Since(start).Seconds())
		m.upstreamResponses.WithLabelValues(provider, strconv.Itoa(sw.code())).Inc()
	})
}

// statusWriter remembers the status code. It passes Flush on, so
// streamed responses still stream.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(p)
}

func (s *statusWriter) Flush()                      { http.NewResponseController(s.ResponseWriter).Flush() }
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) code() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}
