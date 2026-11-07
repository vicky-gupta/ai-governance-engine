// Package checks holds the gateway's built-in governance checks.
package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/vicky-gupta/ai-governance-engine/internal/catalog"
	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
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

// ModelPolicy allows only models listed in the catalog, and only in the
// regions the calling system's risk tier permits. It also chooses which
// provider the request is sent to, so it must run before any check that
// depends on the route.
type ModelPolicy struct {
	Catalog *catalog.Catalog
}

func (ModelPolicy) Name() string { return "model_policy" }

func (c ModelPolicy) Check(_ context.Context, req *pipeline.Request) pipeline.Decision {
	m, ok := c.Catalog.Lookup(req.Model)
	if !ok {
		return pipeline.Decision{
			Action: pipeline.Block,
			Reason: fmt.Sprintf("model %q is not in the approved catalog", req.Model),
		}
	}
	tier := req.System.RiskTier
	if !c.Catalog.RegionAllowed(tier, m.Region) {
		return pipeline.Decision{
			Action: pipeline.Block,
			Reason: fmt.Sprintf("%s-risk systems may only use models hosted in %s; %q runs in %q",
				tier, strings.Join(c.Catalog.AllowedRegions[tier], ", "), m.ID, m.Region),
		}
	}
	req.Provider, req.Region = m.Provider, m.Region
	return pipeline.Decision{Action: pipeline.Allow}
}

// PIIRedaction replaces personal data in every message with tokens such as
// [IBAN_1] before the request leaves the company. The provider never sees
// the real values. The decision's reason lists only what kinds were found,
// never the values, so it is safe to log and audit.
type PIIRedaction struct{}

func (PIIRedaction) Name() string { return "pii_redaction" }

func (PIIRedaction) Check(_ context.Context, req *pipeline.Request) pipeline.Decision {
	r := pii.NewRedactor()
	changed := false
	for _, m := range req.Messages {
		c, err := m.MapText(r.Redact)
		if err != nil {
			// Content we can't read is content we can't check: fail closed.
			return pipeline.Decision{Action: pipeline.Block, Reason: "could not inspect message content: " + err.Error()}
		}
		changed = changed || c
	}
	if !changed {
		return pipeline.Decision{Action: pipeline.Allow}
	}
	return pipeline.Decision{Action: pipeline.Modify, Reason: "redacted " + r.Summary()}
}
