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
	"github.com/vicky-gupta/ai-governance-engine/internal/ratelimit"

	"github.com/vicky-gupta/ai-governance-engine/internal/admin"
	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
	"github.com/vicky-gupta/ai-governance-engine/internal/catalog"
	"github.com/vicky-gupta/ai-governance-engine/internal/checks"
	"github.com/vicky-gupta/ai-governance-engine/internal/config"
	"github.com/vicky-gupta/ai-governance-engine/internal/db"
	"github.com/vicky-gupta/ai-governance-engine/internal/outputguard"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/policy"
	"github.com/vicky-gupta/ai-governance-engine/internal/proxy"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
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

	store := registry.NewStore(pool)
	auditLog := audit.NewStore(pool)

	vaultKeys, err := vault.NewKeys(cfg.VaultKey)
	if err != nil {
		return err
	}
	piiVault := vault.NewStore(pool, vaultKeys)
	usageStore := usage.NewStore(pool)

	cat, err := catalog.Load(cfg.ProvidersFile, os.Getenv)
	if err != nil {
		return err
	}

	// One reverse proxy per provider; the router picks one per request.
	providers := map[string]http.Handler{}
	for _, prov := range cat.Providers {
		providers[prov.Name] = proxy.New(prov.URL, prov.APIKey, log)
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
	checkPipeline := pipeline.New(
		checks.ModelPolicy{Catalog: cat},
		checks.TokenBudget{Usage: usageStore}, // new, second
		checks.PIIRedaction{Vault: piiVault},
		checks.Policy{Engine: rules},
	)
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
	}

	requireKey := auth.Middleware(store, log)
	limit := limiter.Middleware
	runChecks := pipeline.Middleware(checkPipeline, auditLog, log)
	meter := usage.Middleware(usageStore, log)
	guardTools := toolguard.Middleware(rules, auditLog, log)
	guardOutput := outputguard.Middleware(rules, auditLog, log) // new

	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: server.New(server.Deps{
			Log:    log,
			DB:     pool,
			Chat:   requireKey(limit(runChecks(guardOutput(guardTools(meter(router)))))),
			Models: requireKey(limit(catalog.ModelsHandler(cat))),
			Admin:  admin.New(store, auditLog, piiVault, usageStore, cfg.AdminToken, log),
		}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("gateway starting", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
