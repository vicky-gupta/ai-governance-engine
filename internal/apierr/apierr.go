// Package apierr writes errors in the OpenAI error format, so client SDKs
// can parse errors from the gateway the same way as errors from a provider.
package apierr

import (
	"encoding/json"
	"net/http"
)

// Write sends {"error": {"message": ..., "type": ...}} with the given status.
func Write(w http.ResponseWriter, status int, errType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"message": message, "type": errType},
	})
}
