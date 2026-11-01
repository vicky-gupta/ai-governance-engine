package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
)

type Config struct {
	Addr        string // where the gateway listens, e.g. ":8080"
	DatabaseURL string // Postgres connection string
}

func Load() (Config, error) {
	cfg := Config{
		Addr:        getEnv("GATEWAY_ADDR", ":8080"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://aigov:aigov@localhost:5432/aigov?sslmode=disable"),
	}
	if _, err := cfg.DatabaseHostPort(); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
