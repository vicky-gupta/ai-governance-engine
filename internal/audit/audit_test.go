package audit

import (
	"encoding/json"
	"testing"
	"time"
)

func sampleEntry() Entry {
	return Entry{
		CreatedAt:   time.Date(2026, 11, 5, 10, 0, 0, 123456000, time.UTC),
		RequestID:   "req-1",
		SystemID:    "sys-1",
		SystemName:  "support-bot",
		Model:       "llama",
		Action:      "allow",
		Trace:       json.RawMessage(`[{"check":"max_tokens","action":"allow"}]`),
		RequestHash: HashBytes([]byte("body")),
		PrevHash:    GenesisHash,
	}
}

func TestComputeHashIsStable(t *testing.T) {
	e := sampleEntry()
	if e.ComputeHash() != e.ComputeHash() {
		t.Fatal("same entry gave two different hashes")
	}
	// The same moment in another time zone must hash the same.
	other := e
	other.CreatedAt = e.CreatedAt.In(time.FixedZone("CET", 3600))
	if other.ComputeHash() != e.ComputeHash() {
		t.Error("hash depends on the time zone")
	}
	// Whitespace inside the trace JSON must not matter.
	spaced := e
	spaced.Trace = json.RawMessage(`[ {"check": "max_tokens", "action": "allow"} ]`)
	if spaced.ComputeHash() != e.ComputeHash() {
		t.Error("hash depends on whitespace in the trace")
	}
}

func TestComputeHashDetectsEveryField(t *testing.T) {
	base := sampleEntry().ComputeHash()
	changes := map[string]func(*Entry){
		"prev hash": func(e *Entry) { e.PrevHash = "x" },
		"time":      func(e *Entry) { e.CreatedAt = e.CreatedAt.Add(time.Microsecond) },
		"system":    func(e *Entry) { e.SystemName = "other-bot" },
		"model":     func(e *Entry) { e.Model = "gpt" },
		"action":    func(e *Entry) { e.Action = "block" },
		"reason":    func(e *Entry) { e.Reason = "edited" },
		"trace":     func(e *Entry) { e.Trace = json.RawMessage(`[]`) },
		"body hash": func(e *Entry) { e.RequestHash = "y" },
		"provider":  func(e *Entry) { e.Provider = "mistral" },
		"region":    func(e *Entry) { e.Region = "eu" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			e := sampleEntry()
			change(&e)
			if e.ComputeHash() == base {
				t.Errorf("changing the %s did not change the hash", name)
			}
		})
	}
}

// TestHashFormatUnchanged pins the hash of sampleEntry as computed before
// provider and region existed. If this fails, entries already in the log
// would stop verifying. Never "fix" it by changing the expected value.
func TestHashFormatUnchanged(t *testing.T) {
	const want = "dd6cbc055c1b2ba0887a9bd26e4fc4096838c103f792db0d0a046115e560191a"
	if got := sampleEntry().ComputeHash(); got != want {
		t.Errorf("hash = %s, want %s: the hash format changed", got, want)
	}
}
