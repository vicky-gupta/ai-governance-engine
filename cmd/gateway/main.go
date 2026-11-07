package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/admin"
	"github.com/vicky-gupta/ai-governance-engine/internal/audit"
	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
	"github.com/vicky-gupta/ai-governance-engine/internal/catalog"
	"github.com/vicky-gupta/ai-governance-engine/internal/checks"
	"github.com/vicky-gupta/ai-governance-engine/internal/config"
	"github.com/vicky-gupta/ai-governance-engine/internal/db"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/proxy"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
	"github.com/vicky-gupta/ai-governance-engine/internal/server"
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

	// The governance checks, in the order they run. ModelPolicy goes first:
	// it rejects unapproved models and chooses the provider. PII redaction
	// comes next, so every later step only ever sees redacted text.
	checkPipeline := pipeline.New(
		checks.ModelPolicy{Catalog: cat},
		checks.PIIRedaction{},
		checks.BlockedTerms{Terms: cfg.BlockedTerms},
		checks.MaxTokens{Limit: cfg.MaxTokens},
	)
	log.Info("checks configured", "blocked_terms", cfg.BlockedTerms, "max_tokens", cfg.MaxTokens,
		"allowed_regions", cat.AllowedRegions)
	requireKey := auth.Middleware(store, log)
	runChecks := pipeline.Middleware(checkPipeline, auditLog, log)

	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: server.New(server.Deps{
			Log:    log,
			DB:     pool,
			Chat:   requireKey(runChecks(router)),
			Models: requireKey(catalog.ModelsHandler(cat)),
			Admin:  admin.New(store, auditLog, cfg.AdminToken, log),
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
