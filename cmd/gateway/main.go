package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/config"
	"github.com/vicky-gupta/ai-governance-engine/internal/proxy"
	"github.com/vicky-gupta/ai-governance-engine/internal/server"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		log.Error("invalid config", "error", err)
		os.Exit(1)
	}
	dbAddr, _ := cfg.DatabaseHostPort()
	upstream, _ := cfg.Upstream()

	p := proxy.New(upstream, cfg.UpstreamAPIKey, log)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           server.New(log, dbAddr, p).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Stop cleanly on Ctrl+C.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		log.Info("gateway starting", "addr", cfg.Addr, "upstream", upstream.String())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
}
