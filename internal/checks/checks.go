// Package checks holds the gateway's built-in governance checks.
package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/catalog"
	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
	"github.com/vicky-gupta/ai-governance-engine/internal/pipeline"
	"github.com/vicky-gupta/ai-governance-engine/internal/policy"
	"github.com/vicky-gupta/ai-governance-engine/internal/usage"
)

// BlockedTerms blocks requests whose messages contain any listed term
// (case-insensitive). A simple first rule; Module 7 replaces hardcoded
// rules like this with policy files.

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

// Vault stores the original values behind redaction tokens.
type Vault interface {
	Save(ctx context.Context, requestID string, reps []pii.Replacement) error
}

// PIIRedaction replaces personal data in every message with tokens such as
// [IBAN_1] before the request leaves the company. The provider never sees
// the real values. If a Vault is set, the originals are stored encrypted.
// The decision's reason lists only what kinds were found, never the
// values, so it is safe to log and audit.
type PIIRedaction struct {
	Vault Vault // optional
}

func (PIIRedaction) Name() string { return "pii_redaction" }

func (c PIIRedaction) Check(ctx context.Context, req *pipeline.Request) pipeline.Decision {
	r := pii.NewRedactor()
	changed := false
	for _, m := range req.Messages {
		ch, err := m.MapText(r.Redact)
		if err != nil {
			// Content we can't read is content we can't check: fail closed.
			return pipeline.Decision{Action: pipeline.Block, Reason: "could not inspect message content: " + err.Error()}
		}
		changed = changed || ch
	}
	if !changed {
		return pipeline.Decision{Action: pipeline.Allow}
	}

	if c.Vault != nil {
		if err := c.Vault.Save(ctx, req.ID, r.Replacements()); err != nil {
			// The request would still be safe to send, but its originals
			// would be lost for good. Refuse, like a failed audit write.
			return pipeline.Decision{Action: pipeline.Block, Reason: "could not store redacted values securely"}
		}
	}
	return pipeline.Decision{Action: pipeline.Modify, Reason: "redacted " + r.Summary()}
}

// PolicyEngine evaluates the Rego policy. policy.Engine implements it.
type PolicyEngine interface {
	Evaluate(ctx context.Context, input map[string]any) (policy.Result, string, error)
}

// Policy applies the rules in the policies/ folder: deny reasons block the
// request, hold reasons pause it for human review, and max_tokens caps
// the answer length. It runs after PII redaction, so the policy only ever
// sees redacted text.
type Policy struct {
	Engine PolicyEngine
}

func (Policy) Name() string { return "policy" }

func (c Policy) Check(ctx context.Context, req *pipeline.Request) pipeline.Decision {
	messages := make([]any, 0, len(req.Messages))
	for _, m := range req.Messages {
		messages = append(messages, map[string]any{"role": m.Role(), "text": m.Text()})
	}
	input := map[string]any{
		"system": map[string]any{
			"name":      req.System.Name,
			"owner":     req.System.Owner,
			"risk_tier": string(req.System.RiskTier),
		},
		"model":    req.Model,
		"provider": req.Provider,
		"region":   req.Region,
		"messages": messages,
		"tools":    req.ToolNames(),
	}
	if req.MaxTokens != nil {
		input["max_tokens"] = *req.MaxTokens
	}

	res, version, err := c.Engine.Evaluate(ctx, input)
	req.PolicyVersion = version
	if err != nil {
		// A policy that can't be evaluated can't approve anything.
		return pipeline.Decision{Action: pipeline.Block, Reason: "policy evaluation failed"}
	}
	if len(res.Deny) > 0 {
		return pipeline.Decision{Action: pipeline.Block, Reason: strings.Join(res.Deny, "; ")}
	}
	if len(res.Hold) > 0 {
		return pipeline.Decision{Action: pipeline.Hold, Reason: strings.Join(res.Hold, "; ")}
	}
	if res.MaxTokens != nil && (req.MaxTokens == nil || *req.MaxTokens > *res.MaxTokens) {
		limit := *res.MaxTokens
		req.MaxTokens = &limit
		return pipeline.Decision{Action: pipeline.Modify, Reason: fmt.Sprintf("max_tokens set to %d by policy", limit)}
	}
	return pipeline.Decision{Action: pipeline.Allow}
}

// UsageReader tells how many tokens a system has used this month.
type UsageReader interface {
	UsedThisMonth(ctx context.Context, systemID string, now time.Time) (int64, error)
}

// TokenBudget blocks a system that has used up its monthly token budget.
// It also makes sure streamed responses report their token usage, so
// every request can be metered.
type TokenBudget struct {
	Usage UsageReader
	Now   func() time.Time // nil means time.Now; tests set a fixed clock
}

func (TokenBudget) Name() string { return "token_budget" }

func (c TokenBudget) Check(ctx context.Context, req *pipeline.Request) pipeline.Decision {
	if budget := req.System.MonthlyTokenBudget; budget != nil {
		now := time.Now()
		if c.Now != nil {
			now = c.Now()
		}
		used, err := c.Usage.UsedThisMonth(ctx, req.System.ID, now)
		if err != nil {
			// Like every check in the pipeline: when unsure, block.
			return pipeline.Decision{Action: pipeline.Block, Reason: "token budget could not be checked"}
		}
		if used >= *budget {
			return pipeline.Decision{
				Action: pipeline.Block,
				Reason: fmt.Sprintf("monthly token budget of %d used up (%d used); it resets on %s",
					*budget, used, usage.MonthStart(now).AddDate(0, 1, 0).Format("2 January 2006")),
			}
		}
	}

	if req.Stream() && req.RequestStreamUsage() {
		return pipeline.Decision{Action: pipeline.Modify, Reason: "usage reporting turned on for the stream"}
	}
	return pipeline.Decision{Action: pipeline.Allow}
}
