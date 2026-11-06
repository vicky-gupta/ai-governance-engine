package catalog

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

const validJSON = `{
  "providers": [
    {"name": "groq", "base_url": "https://api.groq.com/openai", "api_key_env": "GROQ_API_KEY",
     "region": "us", "models": ["llama-small", "llama-large"]},
    {"name": "mistral", "base_url": "https://api.mistral.ai", "api_key_env": "MISTRAL_API_KEY",
     "region": "eu", "models": ["mistral-small"]}
  ],
  "allowed_regions": {"minimal": ["eu", "us"], "limited": ["eu", "us"], "high": ["eu"]}
}`

// fakeEnv returns a key for every variable name.
func fakeEnv(name string) string { return "key-for-" + name }

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(validJSON), fakeEnv)
	if err != nil {
		t.Fatal(err)
	}

	m, ok := c.Lookup("mistral-small")
	if !ok || m.Provider != "mistral" || m.Region != "eu" {
		t.Errorf("Lookup(mistral-small) = %+v, %v", m, ok)
	}
	if _, ok := c.Lookup("gpt-unknown"); ok {
		t.Error("an unlisted model was found")
	}
	if c.Providers[1].APIKey != "key-for-MISTRAL_API_KEY" {
		t.Errorf("API key = %q, want it read from the environment", c.Providers[1].APIKey)
	}

	if !c.RegionAllowed(registry.RiskLimited, "us") || c.RegionAllowed(registry.RiskHigh, "us") {
		t.Error("region rules not applied as configured")
	}

	var ids []string
	for _, m := range c.ModelsFor(registry.RiskHigh) {
		ids = append(ids, m.ID)
	}
	if strings.Join(ids, ",") != "mistral-small" {
		t.Errorf("high-risk models = %v, want only the EU one", ids)
	}
	if got := len(c.ModelsFor(registry.RiskMinimal)); got != 3 {
		t.Errorf("minimal-risk models = %d, want all 3", got)
	}
}

func TestParseRejectsBadCatalogs(t *testing.T) {
	cases := map[string]string{
		"not JSON":     `{`,
		"no providers": `{"providers": [], "allowed_regions": {}}`,
		"missing region": `{"providers": [{"name":"a","base_url":"https://a.com","api_key_env":"K","models":["m"]}],
			"allowed_regions": {"minimal":["eu"],"limited":["eu"],"high":["eu"]}}`,
		"bad URL": `{"providers": [{"name":"a","base_url":"not a url","api_key_env":"K","region":"eu","models":["m"]}],
			"allowed_regions": {"minimal":["eu"],"limited":["eu"],"high":["eu"]}}`,
		"duplicate model": `{"providers": [
			{"name":"a","base_url":"https://a.com","api_key_env":"K","region":"eu","models":["m"]},
			{"name":"b","base_url":"https://b.com","api_key_env":"K","region":"us","models":["m"]}],
			"allowed_regions": {"minimal":["eu"],"limited":["eu"],"high":["eu"]}}`,
		"missing tier rule": `{"providers": [{"name":"a","base_url":"https://a.com","api_key_env":"K","region":"eu","models":["m"]}],
			"allowed_regions": {"minimal":["eu"],"limited":["eu"]}}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(data), fakeEnv); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestParseRequiresAPIKey(t *testing.T) {
	noKeys := func(string) string { return "" }
	_, err := Parse([]byte(validJSON), noKeys)
	if err == nil || !strings.Contains(err.Error(), "GROQ_API_KEY") {
		t.Errorf("err = %v, want it to name the missing variable", err)
	}
}

func TestModelsHandlerFiltersByTier(t *testing.T) {
	c, err := Parse([]byte(validJSON), fakeEnv)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/v1/models", nil)
	req = req.WithContext(auth.WithSystem(req.Context(), registry.System{Name: "loan-agent", RiskTier: registry.RiskHigh}))
	rec := httptest.NewRecorder()
	ModelsHandler(c).ServeHTTP(rec, req)

	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if rec.Code != http.StatusOK || len(body.Data) != 1 || body.Data[0].ID != "mistral-small" {
		t.Errorf("status=%d models=%+v, want only mistral-small", rec.Code, body.Data)
	}
}
