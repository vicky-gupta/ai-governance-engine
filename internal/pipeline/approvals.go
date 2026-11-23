package pipeline

import (
	"context"
	"errors"
)

// ApprovalHeader is how a caller sends a held request again after it was
// approved: the same request, with this header set to the approval ID.
const ApprovalHeader = "X-Aigov-Approval"

// Held is a request (or a model's tool calls) paused for human review.
type Held struct {
	RequestID   string
	SystemID    string
	SystemName  string
	Model       string
	Reason      string // why it was held
	RequestHash string // the resent request must have the same hash
	Messages    []HeldMessage
	ToolCalls   []HeldToolCall // set when the model's tool calls were held
}

// HeldToolCall is one tool call the model wanted the agent to make.
type HeldToolCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // the JSON text, as the model wrote it
}

// ErrOtherKind means an approval exists but is for something else: a
// request approval where a tool-call approval was expected, or the
// other way round.
var ErrOtherKind = errors.New("approval is for something else")

// HeldMessage is one message of a held request, as the model would have
// seen it: personal data already replaced by tokens.
type HeldMessage struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

// Approvals turns held requests into approvals, and lets an approved
// request through once. approval.Store implements it.
type Approvals interface {
	// Open records a held request for review and returns its approval ID.
	Open(ctx context.Context, h Held) (approvalID string, err error)

	// Use marks an approval as used by requestID, if it is approved, not
	// expired, not used yet, for this AI system, and for a request with
	// this hash. It returns the name of the reviewer who approved it. The
	// error says why an approval can't be used.
	//
	// An approved tool-call approval for this same request also lets the
	// request through, without being used up: it can only exist if the
	// request got through before. The tool guard then uses it.
	Use(ctx context.Context, approvalID, systemID, requestHash, requestID string) (reviewer string, err error)
}
