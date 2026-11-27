package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vicky-gupta/ai-governance-engine/internal/admin"
	"github.com/vicky-gupta/ai-governance-engine/internal/approval"
	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
	"github.com/vicky-gupta/ai-governance-engine/internal/catalog"
	"github.com/vicky-gupta/ai-governance-engine/internal/checks"
	"github.com/vicky-gupta/ai-governance-engine/internal/config"
	"github.com/vicky-gupta/ai-governance-engine/internal/db"
	"github.com/vicky-gupta/ai-governance-engine/internal/health"
	"github.com/vicky-gupta/ai-governance-engine/internal/metrics"
	"github.com/vicky-gupta/ai-governance-engine/internal/ner"
	"github.com/vicky-gupta/ai-governance-engine/internal/outputguard"
	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/policy"
	"github.com/vicky-gupta/ai-governance-engine/internal/proxy"
	"github.com/vicky-gupta/ai-governance-engine/internal/ratelimit"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
	"github.com/vicky-gupta/ai-governance-engine/internal/report"
	"github.com/vicky-gupta/ai-governance-engine/internal/server"
	"github.com/vicky-gupta/ai-governance-engine/internal/toolguard"
	"github.com/vicky-gupta/ai-governance-engine/internal/usage"
	"github.com/vicky-gupta/ai-governance-engine/internal/vault"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	log.Info("database ready")

	// Metrics: wrapped around the audit log, usage store and providers
	// below, so every decision, token and provider call is counted.
	m := metrics.New()

	store := registry.NewStore(pool)
	auditLog := audit.NewStore(pool)
	decisions := m.Audit(auditLog) // the audit log, counting what it records
	vaultKeys, err := vault.NewKeys(cfg.VaultKey)
	if err != nil {
		return err
	}
	piiVault := vault.NewStore(pool, vaultKeys)
	usageStore := usage.NewStore(pool)
	approvals := approval.NewStore(pool, vaultKeys, cfg.ApprovalTTL)
	cat, err := catalog.Load(cfg.ProvidersFile, os.Getenv)
	if err != nil {
		return err
	}

	// One reverse proxy per provider; the router picks one per request.
	providers := map[string]http.Handler{}
	for _, prov := range cat.Providers {
		providers[prov.Name] = m.Upstream(prov.Name, proxy.New(prov.URL, prov.APIKey, log))
		log.Info("provider configured", "name", prov.Name, "region", prov.Region, "models", prov.Models)
	}
	router := proxy.NewRouter(providers, pipeline.ProviderFrom, log)

	// The rules in policies/*.rego. Checked for changes every 2 seconds;
	// a version with errors is rejected and the previous one stays active.
	rules, err := policy.Load(ctx, cfg.PolicyDir, log)
	if err != nil {
		return err
	}
	go rules.Watch(ctx, 2*time.Second)
	log.Info("policy loaded", "dir", cfg.PolicyDir, "version", rules.Version())

	// The governance checks, in the order they run. ModelPolicy rejects
	// unapproved models and chooses the provider. PII redaction comes next,
	// so the policy (and everything after it) only sees redacted text.
	// Names and places need the NER sidecar (ner/). Without it, the
	// gateway still redacts everything its patterns find.
	var names pii.Detector
	var nerPing func(context.Context) error // for the readiness check
	if cfg.NERURL != "" {
		client := ner.New(cfg.NERURL, 3*time.Second)
		nerCtx, nerCancel := context.WithTimeout(ctx, 3*time.Second)
		if err := client.Ping(nerCtx); err != nil {
			log.Warn("ner sidecar unreachable; requests are blocked until it is up", "url", cfg.NERURL, "error", err)
		} else {
			log.Info("ner sidecar ready", "url", cfg.NERURL)
		}
		nerCancel()
		names = client
		nerPing = client.Ping
	} else {
		log.Warn("NER_URL not set: names and places are not detected")
	}

	checkPipeline := pipeline.New(
		checks.ModelPolicy{Catalog: cat},
		checks.TokenBudget{Usage: usageStore},
		checks.PIIRedaction{Vault: piiVault, Names: names},
		checks.Policy{Engine: rules},
	)
	checkPipeline.Observe(m.ObserveStep)
	log.Info("checks configured", "allowed_regions", cat.AllowedRegions)
	// Rate limits: counters live in Redis, shared by every gateway instance.
	// If Redis is down at startup we still start; requests are then
	// allowed without a limit check (see ratelimit.Limiter).
	redisOpts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("REDIS_URL: %w", err)
	}
	rdb := redis.NewClient(redisOpts)
	defer rdb.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		log.Warn("redis unreachable; rate limits are not enforced until it is back", "error", err)
	} else {
		log.Info("redis ready", "default_rate_limit_rpm", cfg.DefaultRPM)
	}
	cancel()
	limiter := &ratelimit.Limiter{
		Counter:    ratelimit.NewRedisCounter(rdb),
		DefaultRPM: cfg.DefaultRPM,
		Log:        log,
		FailOpen:   m.RateLimitFailOpen,
	}

	requireKey := auth.Middleware(store, log)
	limit := limiter.Middleware
	runChecks := pipeline.Middleware(checkPipeline, decisions, approvals, log)
	meter := usage.Middleware(m.Usage(usageStore), log)
	guardTools := toolguard.Middleware(rules, decisions, approvals, log)
	guardOutput := outputguard.Middleware(rules, decisions, log)

	// The admin API, plus reviewer management behind the same admin token.
	reviewerAdmin := admin.RequireToken(cfg.AdminToken, approval.AdminAPI(approvals, decisions, log))
	adminAPI := http.NewServeMux()
	adminAPI.Handle("/admin/", admin.New(store, auditLog, piiVault, usageStore, cfg.AdminToken, log))
	adminAPI.Handle("/admin/reviewers", reviewerAdmin)
	adminAPI.Handle("/admin/reviewers/", reviewerAdmin)
	adminAPI.Handle("/admin/reports/", admin.RequireToken(cfg.AdminToken,
		report.Handler(report.NewBuilder(pool, auditLog), auditLog, log)))

	// What the gateway depends on. Without Postgres (audit log) or the
	// NER sidecar it blocks every request, so they are required. Without
	// Redis it still works, minus rate limits.
	probes := []health.Probe{
		{Name: "postgres", Required: true, Check: pool.Ping},
		{Name: "redis", Required: false, Check: func(ctx context.Context) error { return rdb.Ping(ctx).Err() }},
	}
	if nerPing != nil {
		probes = append(probes, health.Probe{Name: "ner", Required: true, Check: nerPing})
	}
	m.WatchState(metrics.State{
		Probes:        probes,
		Pending:       approvals.CountPending,
		PolicyVersion: rules.Version,
	})

	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: server.New(server.Deps{
			Log:     log,
			Ready:   health.Handler(probes, log),
			Chat:    requireKey(limit(runChecks(guardOutput(guardTools(meter(router)))))),
			Models:  requireKey(limit(catalog.ModelsHandler(cat))),
			Admin:   adminAPI,
			Review:  approval.ReviewAPI(approvals, decisions, log),
			Observe: m.ObserveHTTP,
		}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		log.Info("gateway starting", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// /metrics gets its own port, so it can stay off the public network:
	// it names every AI system and shows how much each one is used.
	var metricsSrv *http.Server
	if cfg.MetricsAddr != "off" {
		if cfg.MetricsToken == "" && !metrics.IsLoopback(cfg.MetricsAddr) {
			log.Warn("METRICS_ADDR is reachable from other machines and METRICS_TOKEN is not set: anyone who can reach it can read the metrics",
				"addr", cfg.MetricsAddr)
		}
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", metrics.RequireToken(cfg.MetricsToken, m.Handler()))
		metricsSrv = &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Info("metrics listening", "addr", cfg.MetricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("metrics server: %w", err)
			}
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if metricsSrv != nil {
		metricsSrv.Shutdown(shutdownCtx)
	}
	return srv.Shutdown(shutdownCtx)
}
