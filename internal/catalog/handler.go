package catalog

import (
	"encoding/json"
	"net/http"

	"github.com/vicky-gupta/ai-governance-engine/internal/apierr"
	"github.com/vicky-gupta/ai-governance-engine/internal/auth"
)

// ModelsHandler answers GET /v1/models in OpenAI's format, listing only
// the models the calling AI system is allowed to use. It must sit after
// the auth middleware.
func ModelsHandler(c *Catalog) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sys, ok := auth.SystemFrom(r.Context())
		if !ok {
			apierr.Write(w, http.StatusInternalServerError, "gateway_error", "internal error")
			return
		}

		type model struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			OwnedBy string `json:"owned_by"`
			Region  string `json:"region"`
		}
		data := []model{}
		for _, m := range c.ModelsFor(sys.RiskTier) {
			data = append(data, model{ID: m.ID, Object: "model", OwnedBy: m.Provider, Region: m.Region})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": data})
	})
}
