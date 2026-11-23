// Package approval is the human-in-the-loop workflow: requests the policy
// holds wait here for a named reviewer to approve or reject them.
//
// What a reviewer saw is part of the record. The held request is stored
// with a hash of its content; a decision is only accepted with that hash,
// and the hash goes into the audit log. "A human approved it" then means:
// this person, at this time, about exactly this content.
package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
)

// Status of an approval. Expired is not stored; see Approval.Expired.
type Status string

const (
	Pending  Status = "pending"
	Approved Status = "approved"
	Rejected Status = "rejected"
	Used     Status = "used"
)

// Kind says what an approval is for.
type Kind string

const (
	KindRequest   Kind = "request"    // a request the policy held
	KindToolCalls Kind = "tool_calls" // the tool calls in a model's answer
)

// Reviewer is a person who may decide on held requests.
type Reviewer struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// Approval is one held request and what happened to it.
type Approval struct {
	ID              string     `json:"id"`
	Kind            Kind       `json:"kind"`
	RequestID       string     `json:"request_id"`
	RequestHash     string     `json:"-"`
	SystemID        string     `json:"ai_system_id"`
	Status          Status     `json:"status"`
	Expired         bool       `json:"expired"`
	ContentHash     string     `json:"content_hash"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	DecidedBy       string     `json:"decided_by,omitempty"` // reviewer name
	DecidedAt       *time.Time `json:"decided_at,omitempty"`
	Note            string     `json:"note,omitempty"`
	UsedAt          *time.Time `json:"used_at,omitempty"`
	UsedByRequestID string     `json:"used_by_request_id,omitempty"`
}

// Content is what a reviewer sees: the held request, redacted.
type Content struct {
	SystemName string                  `json:"ai_system"`
	Model      string                  `json:"model"`
	Reason     string                  `json:"held_because"`
	Messages   []pipeline.HeldMessage  `json:"messages"`
	ToolCalls  []pipeline.HeldToolCall `json:"tool_calls,omitempty"`
}

// Errors that explain why an approval can't be decided or used.
var (
	ErrNotFound     = errors.New("approval not found")
	ErrNotPending   = errors.New("approval has already been decided")
	ErrExpired      = errors.New("approval has expired")
	ErrPending      = errors.New("approval is still waiting for review")
	ErrRejected     = errors.New("approval was rejected")
	ErrAlreadyUsed  = errors.New("approval has already been used")
	ErrWrongRequest = errors.New("this request is not the one that was approved")
	ErrStaleView    = errors.New("seen_hash does not match the content of this approval")
	ErrDuplicate    = errors.New("a reviewer with this name already exists")
)

// newToken returns a reviewer token and its SHA-256 hash. Only the hash
// is stored, as with gateway keys.
func newToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token = "aigovr_" + base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token), nil
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}
