package registry

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewKey(t *testing.T) {
	key, prefix, hash, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "aigov_") {
		t.Errorf("key %q should start with aigov_", key)
	}
	if !strings.HasPrefix(key, prefix) || len(prefix) != len("aigov_")+6 {
		t.Errorf("prefix %q should be the first 12 characters of the key", prefix)
	}
	if !bytes.Equal(hash, HashKey(key)) {
		t.Error("hash does not match HashKey(key)")
	}

	other, _, _, _ := NewKey()
	if key == other {
		t.Error("two keys were identical")
	}
}

func TestRiskTierValid(t *testing.T) {
	for _, tier := range []RiskTier{RiskMinimal, RiskLimited, RiskHigh, RiskUnacceptable} {
		if !tier.Valid() {
			t.Errorf("%q should be valid", tier)
		}
	}
	if RiskTier("medium").Valid() {
		t.Error(`"medium" should not be valid`)
	}
}
