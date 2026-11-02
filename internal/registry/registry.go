// Package registry stores AI systems and their gateway API keys.
package registry

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"
)

// RiskTier is an AI system's risk level under the EU AI Act.
type RiskTier string

const (
	RiskMinimal      RiskTier = "minimal"
	RiskLimited      RiskTier = "limited"
	RiskHigh         RiskTier = "high"
	RiskUnacceptable RiskTier = "unacceptable" // prohibited practices (Article 5)
)

// Valid reports whether t is one of the four EU AI Act tiers.
func (t RiskTier) Valid() bool {
	switch t {
	case RiskMinimal, RiskLimited, RiskHigh, RiskUnacceptable:
		return true
	}
	return false
}

// System is one registered AI application.
type System struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Owner     string    `json:"owner"`
	Purpose   string    `json:"purpose"`
	RiskTier  RiskTier  `json:"risk_tier"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// Key describes a gateway API key. It never contains the key itself.
type Key struct {
	ID        string    `json:"id"`
	SystemID  string    `json:"ai_system_id"`
	Prefix    string    `json:"prefix"`
	CreatedAt time.Time `json:"created_at"`
}

var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("already exists")
)

const keyPrefix = "aigov_"

// NewKey creates a random gateway key. It returns the key (shown to the
// user once), a short prefix that is safe to display, and the hash that
// gets stored.
func NewKey() (key, prefix string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", nil, err
	}
	key = keyPrefix + base64.RawURLEncoding.EncodeToString(b)
	return key, key[:len(keyPrefix)+6], HashKey(key), nil
}

// HashKey returns the SHA-256 hash of a key.
func HashKey(key string) []byte {
	sum := sha256.Sum256([]byte(key))
	return sum[:]
}
