package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
)

type Config struct {
	Addr           string // where the gateway listens, e.g. ":8080"
	DatabaseURL    string // Postgres connection string
	UpstreamURL    string // LLM provider base URL, e.g. https://api.openai.com
	UpstreamAPIKey string // the provider API key; only the gateway knows it
}

func Load() (Config, error) {
	cfg := Config{
		Addr:           getEnv("GATEWAY_ADDR", ":8080"),
		DatabaseURL:    getEnv("DATABASE_URL", "postgres://aigov:aigov@localhost:5432/aigov?sslmode=disable"),
		UpstreamURL:    getEnv("UPSTREAM_URL", "https://api.openai.com"),
		UpstreamAPIKey: os.Getenv("UPSTREAM_API_KEY"),
	}
	if _, err := cfg.DatabaseHostPort(); err != nil {
		return Config{}, err
	}
	if _, err := cfg.Upstream(); err != nil {
		return Config{}, err
	}
	if cfg.UpstreamAPIKey == "" {
		return Config{}, fmt.Errorf("UPSTREAM_API_KEY is required")
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

// DatabaseHostPort pulls "host:port" out of the database URL.
func (c Config) DatabaseHostPort() (string, error) {
	u, err := url.Parse(c.DatabaseURL)
	if err != nil {
		return "", fmt.Errorf("DATABASE_URL: %w", err)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("DATABASE_URL: missing host")
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
