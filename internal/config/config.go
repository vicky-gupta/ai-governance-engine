package config

import (
	"fmt"
	"net/url"
	"os"
)

type Config struct {
	Addr           string // where the gateway listens, e.g. ":8080"
	DatabaseURL    string // Postgres connection string
	UpstreamURL    string // LLM provider base URL, e.g. https://api.groq.com/openai
	UpstreamAPIKey string // the provider API key; only the gateway knows it
	AdminToken     string // protects the /admin API
}

func Load() (Config, error) {
	cfg := Config{
		Addr:           getEnv("GATEWAY_ADDR", ":8080"),
		DatabaseURL:    getEnv("DATABASE_URL", "postgres://aigov:aigov@localhost:5432/aigov?sslmode=disable"),
		UpstreamURL:    getEnv("UPSTREAM_URL", "https://api.openai.com"),
		UpstreamAPIKey: os.Getenv("UPSTREAM_API_KEY"),
		AdminToken:     os.Getenv("ADMIN_TOKEN"),
	}
	if _, err := cfg.Upstream(); err != nil {
		return Config{}, err
	}
	if cfg.UpstreamAPIKey == "" {
		return Config{}, fmt.Errorf("UPSTREAM_API_KEY is required")
	}
	if len(cfg.AdminToken) < 16 {
		return Config{}, fmt.Errorf("ADMIN_TOKEN is required and must be at least 16 characters")
	}
	return cfg, nil
}

// Upstream parses and validates the provider URL.
func (c Config) Upstream() (*url.URL, error) {
	u, err := url.Parse(c.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("UPSTREAM_URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("UPSTREAM_URL: must look like https://api.openai.com, got %q", c.UpstreamURL)
	}
	return u, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
