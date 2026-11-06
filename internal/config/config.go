package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addr          string // where the gateway listens, e.g. ":8080"
	DatabaseURL   string // Postgres connection string
	ProvidersFile string // path to the provider and model catalog
	AdminToken    string // protects the /admin API

	BlockedTerms []string // requests mentioning any of these are blocked
	MaxTokens    int      // upper limit for max_tokens on every request
}

func Load() (Config, error) {
	cfg := Config{
		Addr:          getEnv("GATEWAY_ADDR", ":8080"),
		DatabaseURL:   getEnv("DATABASE_URL", "postgres://aigov:aigov@localhost:5432/aigov?sslmode=disable"),
		ProvidersFile: getEnv("PROVIDERS_FILE", "providers.json"),
		AdminToken:    os.Getenv("ADMIN_TOKEN"),
	}

	for _, term := range strings.Split(os.Getenv("BLOCKED_TERMS"), ",") {
		if term = strings.TrimSpace(term); term != "" {
			cfg.BlockedTerms = append(cfg.BlockedTerms, term)
		}
	}

	maxTokens, err := strconv.Atoi(getEnv("MAX_TOKENS", "4096"))
	if err != nil || maxTokens <= 0 {
		return Config{}, fmt.Errorf("MAX_TOKENS must be a positive whole number")
	}
	cfg.MaxTokens = maxTokens

	if len(cfg.AdminToken) < 16 {
		return Config{}, fmt.Errorf("ADMIN_TOKEN is required and must be at least 16 characters")
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
