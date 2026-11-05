// Package pipeline runs governance checks on each request and combines
// their results into one decision: allow, modify, block or hold.
package pipeline

import (
	"context"
	"fmt"
	"time"
)

// Action is what the gateway does with a request.
type Action string

const (
	Allow  Action = "allow"  // send it on unchanged
	Modify Action = "modify" // send it on, changed (e.g. PII redacted)
	Block  Action = "block"  // reject it
	Hold   Action = "hold"   // pause it for a human to approve
)

// Decision is one check's verdict.
type Decision struct {
	Action Action
	Reason string // why; shown to the caller when a request is blocked
}

// Check is one governance rule. A check that returns Modify must have
// already changed the request it was given.
type Check interface {
	Name() string
	Check(ctx context.Context, req *Request) Decision
}

// Step records what one check decided and how long it took.
type Step struct {
	Check    string        `json:"check"`
	Action   Action        `json:"action"`
	Reason   string        `json:"reason,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

// Result is the pipeline's final verdict, plus a trace of every step.
type Result struct {
	Action Action
	Reason string // set for Block and Hold
	Check  string // the check that blocked or held, if any
	Trace  []Step
}

// Pipeline runs checks in order.
type Pipeline struct {
	checks []Check
}

func New(checks ...Check) *Pipeline {
	return &Pipeline{checks: checks}
}

// Run applies every check in order.
//   - Block or Hold stops the pipeline: later checks don't run.
//   - Modify carries on, so later checks see the changed request.
//   - The final action is Modify if any check modified, otherwise Allow.
func (p *Pipeline) Run(ctx context.Context, req *Request) Result {
	res := Result{Action: Allow}
	for _, c := range p.checks {
		start := time.Now()
		d := safeCheck(ctx, c, req)
		res.Trace = append(res.Trace, Step{
			Check: c.Name(), Action: d.Action, Reason: d.Reason, Duration: time.Since(start),
		})

		switch d.Action {
		case Block, Hold:
			res.Action, res.Reason, res.Check = d.Action, d.Reason, c.Name()
			return res
		case Modify:
			res.Action = Modify
		case Allow:
		default:
			// A check returned something we don't understand: fail closed.
			res.Action, res.Check = Block, c.Name()
			res.Reason = fmt.Sprintf("check returned unknown action %q", d.Action)
			return res
		}
	}
	return res
}

// safeCheck runs one check, turning a panic into a Block. A buggy check
// must never crash the gateway or let a request through unchecked.
func safeCheck(ctx context.Context, c Check, req *Request) (d Decision) {
	defer func() {
		if r := recover(); r != nil {
			d = Decision{Action: Block, Reason: fmt.Sprintf("internal error in check %s", c.Name())}
		}
	}()
	return c.Check(ctx, req)
}
