// Package audit keeps a tamper-evident record of every governance
// decision. Each entry contains the hash of the entry before it, forming
// a chain: changing, removing or reordering any past entry breaks every
// link after it.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// GenesisHash is the "previous hash" of the very first entry.
var GenesisHash = strings.Repeat("0", 64)

// Entry is one audit record.
type Entry struct {
	ID            int64           `json:"id"`
	CreatedAt     time.Time       `json:"created_at"`
	RequestID     string          `json:"request_id"`
	SystemID      string          `json:"ai_system_id"`
	SystemName    string          `json:"ai_system_name"`
	Model         string          `json:"model"`
	Action        string          `json:"action"`
	Check         string          `json:"check,omitempty"`
	Reason        string          `json:"reason,omitempty"`
	Trace         json.RawMessage `json:"trace"`
	RequestHash   string          `json:"request_hash"`             // hash of the body as received
	ForwardedHash string          `json:"forwarded_hash,omitempty"` // hash of the body sent to the provider
	PrevHash      string          `json:"prev_hash"`
	Hash          string          `json:"hash"`
}

// ComputeHash returns the entry's hash: SHA-256 over every field except
// ID and Hash, in a fixed order. Changing any field changes the hash.
func (e Entry) ComputeHash() string {
	b, _ := json.Marshal(struct {
		PrevHash      string          `json:"prev_hash"`
		CreatedAt     string          `json:"created_at"`
		RequestID     string          `json:"request_id"`
		SystemID      string          `json:"ai_system_id"`
		SystemName    string          `json:"ai_system_name"`
		Model         string          `json:"model"`
		Action        string          `json:"action"`
		Check         string          `json:"check"`
		Reason        string          `json:"reason"`
		Trace         json.RawMessage `json:"trace"`
		RequestHash   string          `json:"request_hash"`
		ForwardedHash string          `json:"forwarded_hash"`
	}{
		e.PrevHash, e.CreatedAt.UTC().Format(time.RFC3339Nano), e.RequestID, e.SystemID,
		e.SystemName, e.Model, e.Action, e.Check, e.Reason, e.Trace, e.RequestHash, e.ForwardedHash,
	})
	return HashBytes(b)
}

// HashBytes returns the hex SHA-256 of b. The gateway stores hashes of
// request bodies instead of the bodies themselves, so the log proves what
// was sent without keeping any personal data.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
