// Package checks holds the gateway's built-in governance checks.
package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
)

// BlockedTerms blocks requests whose messages contain any listed term
// (case-insensitive). A simple first rule; Module 7 replaces hardcoded
// rules like this with policy files.
type BlockedTerms struct {
	Terms []string
}

func (BlockedTerms) Name() string { return "blocked_terms" }

func (c BlockedTerms) Check(_ context.Context, req *pipeline.Request) pipeline.Decision {
	for _, m := range req.Messages {
		text := strings.ToLower(m.Text())
		for _, term := range c.Terms {
			if term != "" && strings.Contains(text, strings.ToLower(term)) {
				return pipeline.Decision{
					Action: pipeline.Block,
					Reason: fmt.Sprintf("message contains blocked term %q", term),
				}
			}
		}
	}
	return pipeline.Decision{Action: pipeline.Allow}
}

// MaxTokens caps how long a response can be, which caps the cost of each
// call. A missing or larger max_tokens is set to the limit.
type MaxTokens struct {
	Limit int
}

func (MaxTokens) Name() string { return "max_tokens" }

func (c MaxTokens) Check(_ context.Context, req *pipeline.Request) pipeline.Decision {
	if req.MaxTokens != nil && *req.MaxTokens <= c.Limit {
		return pipeline.Decision{Action: pipeline.Allow}
	}
	limit := c.Limit
	req.MaxTokens = &limit
	return pipeline.Decision{
		Action: pipeline.Modify,
		Reason: fmt.Sprintf("max_tokens set to %d", c.Limit),
	}
}
