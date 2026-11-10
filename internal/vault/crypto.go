// Package vault stores the original values behind redaction tokens,
// encrypted, so authorised staff can look them up and a person's data can
// be erased on request. The audit log never contains these values.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
)

// Keys holds two keys derived from one master key: one for encryption,
// one for fingerprints. Using one key for two jobs is a classic mistake.
type Keys struct {
	aead   cipher.AEAD
	macKey []byte
}

// NewKeys derives the encryption and fingerprint keys from a 32-byte
// master key.
func NewKeys(master []byte) (*Keys, error) {
	if len(master) != 32 {
		return nil, fmt.Errorf("vault: master key must be 32 bytes, got %d", len(master))
	}
	block, err := aes.NewCipher(derive(master, "aigov vault encryption"))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Keys{aead: aead, macKey: derive(master, "aigov vault fingerprint")}, nil
}

func derive(master []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(purpose))
	return mac.Sum(nil)
}

// Encrypt seals value with AES-256-GCM. The output is nonce + ciphertext.
// context is bound to the ciphertext: decrypting with a different context
// fails, so a ciphertext copied onto another row can't be read there.
func (k *Keys) Encrypt(value, context string) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, []byte(value), []byte(context)), nil
}

// Decrypt opens what Encrypt sealed. It fails if a single bit was changed.
func (k *Keys) Decrypt(sealed []byte, context string) (string, error) {
	n := k.aead.NonceSize()
	if len(sealed) < n {
		return "", errors.New("vault: ciphertext too short")
	}
	plain, err := k.aead.Open(nil, sealed[:n], sealed[n:], []byte(context))
	if err != nil {
		return "", errors.New("vault: cannot decrypt (wrong key or tampered data)")
	}
	return string(plain), nil
}

// Fingerprint is a keyed hash (HMAC-SHA256) of a normalized value. The
// same value always gives the same fingerprint, so all of a person's rows
// can be found for erasure, but without the key nobody can test guesses
// against it.
func (k *Keys) Fingerprint(kind pii.Kind, value string) []byte {
	mac := hmac.New(sha256.New, k.macKey)
	mac.Write([]byte(string(kind) + ":" + pii.Normalize(value)))
	return mac.Sum(nil)
}
