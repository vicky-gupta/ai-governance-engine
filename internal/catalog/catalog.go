// Package catalog is the list of approved LLM providers and models, where
// each provider processes data, and which regions each EU AI Act risk
// tier may use. Only models in the catalog can be called.
package catalog

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sort"

	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// Provider is one LLM provider the gateway can forward to.
type Provider struct {
	Name      string   `json:"name"`
	BaseURL   string   `json:"base_url"`
	APIKeyEnv string   `json:"api_key_env"` // name of the env var holding the key
	Region    string   `json:"region"`      // where this provider processes data, e.g. "eu"
	Models    []string `json:"models"`

	APIKey string   `json:"-"` // read from APIKeyEnv at load time; never in the file
	URL    *url.URL `json:"-"`
}

// Model is one approved model and where it runs.
type Model struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Region   string `json:"region"`
}

// Catalog is the loaded, validated catalog.
type Catalog struct {
	Providers      []Provider                     `json:"providers"`
	AllowedRegions map[registry.RiskTier][]string `json:"allowed_regions"`

	models map[string]Model // model ID -> model
}

// Load reads and validates the catalog file. getenv looks up API keys
// (os.Getenv in production, a fake in tests).
func Load(path string, getenv func(string) string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	return Parse(data, getenv)
}

// Parse validates catalog JSON. Every problem stops startup: a gateway
// with a half-valid catalog could route data somewhere it shouldn't.
func Parse(data []byte, getenv func(string) string) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("catalog: invalid JSON: %w", err)
	}
	if len(c.Providers) == 0 {
		return nil, fmt.Errorf("catalog: no providers")
	}

	c.models = map[string]Model{}
	names := map[string]bool{}
	for i := range c.Providers {
		p := &c.Providers[i]
		if p.Name == "" || p.Region == "" || len(p.Models) == 0 {
			return nil, fmt.Errorf("catalog: provider #%d needs a name, a region and at least one model", i+1)
		}
		if names[p.Name] {
			return nil, fmt.Errorf("catalog: provider %q is listed twice", p.Name)
		}
		names[p.Name] = true

		u, err := url.Parse(p.BaseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("catalog: provider %q has an invalid base_url %q", p.Name, p.BaseURL)
		}
		p.URL = u

		if p.APIKeyEnv == "" {
			return nil, fmt.Errorf("catalog: provider %q needs api_key_env", p.Name)
		}
		if p.APIKey = getenv(p.APIKeyEnv); p.APIKey == "" {
			return nil, fmt.Errorf("catalog: provider %q: environment variable %s is not set", p.Name, p.APIKeyEnv)
		}

		for _, id := range p.Models {
			if other, dup := c.models[id]; dup {
				return nil, fmt.Errorf("catalog: model %q is listed under both %q and %q", id, other.Provider, p.Name)
			}
			c.models[id] = Model{ID: id, Provider: p.Name, Region: p.Region}
		}
	}

	// Every tier that may call models needs an explicit region rule. A
	// missing rule is an error, not "anything goes".
	for _, tier := range []registry.RiskTier{registry.RiskMinimal, registry.RiskLimited, registry.RiskHigh} {
		if len(c.AllowedRegions[tier]) == 0 {
			return nil, fmt.Errorf("catalog: allowed_regions has no entry for risk tier %q", tier)
		}
	}
	return &c, nil
}

// Lookup finds an approved model.
func (c *Catalog) Lookup(id string) (Model, bool) {
	m, ok := c.models[id]
	return m, ok
}

// RegionAllowed reports whether a system of this tier may use this region.
func (c *Catalog) RegionAllowed(tier registry.RiskTier, region string) bool {
	return slices.Contains(c.AllowedRegions[tier], region)
}

// ModelsFor lists the models a system of this tier may use, sorted by ID.
func (c *Catalog) ModelsFor(tier registry.RiskTier) []Model {
	var out []Model
	for _, m := range c.models {
		if c.RegionAllowed(tier, m.Region) {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
