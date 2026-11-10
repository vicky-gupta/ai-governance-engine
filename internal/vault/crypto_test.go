package vault

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
)

func testKeys(t *testing.T, seed byte) *Keys {
	t.Helper()
	k, err := NewKeys(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNewKeysNeeds32Bytes(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := NewKeys(make([]byte, n)); err == nil {
			t.Errorf("%d-byte key accepted", n)
		}
	}
}

func TestEncryptRoundTrip(t *testing.T) {
	k := testKeys(t, 1)
	sealed, err := k.Encrypt("DE89 3704 0044 0532 0130 00", "req-1|[IBAN_1]")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "3704") {
		t.Fatal("ciphertext contains the plaintext")
	}
	got, err := k.Decrypt(sealed, "req-1|[IBAN_1]")
	if err != nil || got != "DE89 3704 0044 0532 0130 00" {
		t.Errorf("Decrypt = %q, %v", got, err)
	}

	// The same value encrypted twice looks different (random nonce), so
	// equal ciphertexts don't reveal equal values.
	again, _ := k.Encrypt("DE89 3704 0044 0532 0130 00", "req-1|[IBAN_1]")
	if bytes.Equal(sealed, again) {
		t.Error("two encryptions of the same value are identical")
	}
}

func TestDecryptRefusesTamperingAndWrongContext(t *testing.T) {
	k := testKeys(t, 1)
	sealed, _ := k.Encrypt("anna@example.com", "req-1|[EMAIL_1]")

	flipped := bytes.Clone(sealed)
	flipped[len(flipped)-1] ^= 1
	if _, err := k.Decrypt(flipped, "req-1|[EMAIL_1]"); err == nil {
		t.Error("a changed ciphertext decrypted")
	}
	// Copied onto another row: the bound context no longer matches.
	if _, err := k.Decrypt(sealed, "req-2|[EMAIL_1]"); err == nil {
		t.Error("a ciphertext decrypted with another row's context")
	}
	if _, err := testKeys(t, 2).Decrypt(sealed, "req-1|[EMAIL_1]"); err == nil {
		t.Error("a ciphertext decrypted with another key")
	}
}

func TestFingerprint(t *testing.T) {
	k := testKeys(t, 1)
	a := k.Fingerprint(pii.IBAN, "DE89 3704 0044 0532 0130 00")
	if !bytes.Equal(a, k.Fingerprint(pii.IBAN, "de89370400440532013000")) {
		t.Error("the same IBAN written differently gave different fingerprints")
	}
	if bytes.Equal(a, k.Fingerprint(pii.Card, "DE89 3704 0044 0532 0130 00")) {
		t.Error("fingerprint ignores the kind")
	}
	if bytes.Equal(a, testKeys(t, 2).Fingerprint(pii.IBAN, "DE89 3704 0044 0532 0130 00")) {
		t.Error("fingerprint does not depend on the key")
	}
}
