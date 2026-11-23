package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr          string        // where the gateway listens, e.g. ":8080"
	DatabaseURL   string        // Postgres connection string
	ProvidersFile string        // path to the provider and model catalog
	AdminToken    string        // protects the /admin API
	VaultKey      []byte        // 32-byte master key for the PII vault
	PolicyDir     string        // folder with the Rego policy files
	RedisURL      string        // Redis for the rate limit counters
	DefaultRPM    int           // requests per minute for systems without their own limit
	ApprovalTTL   time.Duration // how long a held request can be approved and used
}

func Load() (Config, error) {
	cfg := Config{
		Addr:          getEnv("GATEWAY_ADDR", ":8080"),
		DatabaseURL:   getEnv("DATABASE_URL", "postgres://aigov:aigov@localhost:5432/aigov?sslmode=disable"),
		ProvidersFile: getEnv("PROVIDERS_FILE", "providers.json"),
		PolicyDir:     getEnv("POLICY_DIR", "policies"),
		AdminToken:    os.Getenv("ADMIN_TOKEN"),
		RedisURL:      getEnv("REDIS_URL", "redis://localhost:6379/0"),
	}

	rpm, err := strconv.Atoi(getEnv("DEFAULT_RATE_LIMIT_RPM", "60"))
	if err != nil || rpm < 1 {
		return Config{}, fmt.Errorf("DEFAULT_RATE_LIMIT_RPM must be a whole number of at least 1")
	}
	cfg.DefaultRPM = rpm

	ttl, err := time.ParseDuration(getEnv("APPROVAL_TTL", "24h"))
	if err != nil || ttl <= 0 {
		return Config{}, fmt.Errorf("APPROVAL_TTL must be a duration like 24h or 30m")
	}
	cfg.ApprovalTTL = ttl

	key, err := base64.StdEncoding.DecodeString(os.Getenv("PII_VAULT_KEY"))
	if err != nil || len(key) != 32 {
		return Config{}, fmt.Errorf("PII_VAULT_KEY is required: 32 random bytes, base64-encoded")
	}
	cfg.VaultKey = key

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
