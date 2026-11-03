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
	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
	"github.com/vicky-gupta/ai-governance-engine/internal/config"
	"github.com/vicky-gupta/ai-governance-engine/internal/db"
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
	upstream, _ := cfg.Upstream()
	p := proxy.New(upstream, cfg.UpstreamAPIKey, log)

	srv := &http.Server{
		Addr: cfg.Addr,
		Handler: server.New(server.Deps{
			Log:   log,
			DB:    pool,
			Proxy: auth.Middleware(store, log)(p),
			Admin: admin.New(store, cfg.AdminToken, log),
		}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("gateway starting", "addr", cfg.Addr, "upstream", upstream.String())
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
