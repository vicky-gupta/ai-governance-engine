package pipeline

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/vicky-gupta/ai-governance-engine/internal/registry"
)

// Request is a chat completion request in a form checks can inspect and
// change. Fields the gateway doesn't model (temperature, tools, ...) are
// kept untouched in fields and sent on unchanged.
type Request struct {
	System    registry.System // who is calling (set by the auth middleware)
	Model     string
	Messages  []Message
	MaxTokens *int // nil when the caller didn't set it

	// Where the request goes. Set by a routing check (ModelPolicy); never
	// sent to the provider.
	Provider string
	Region   string

	fields map[string]json.RawMessage
}

// Message is one chat message. It is kept as raw JSON fields so that
// anything we don't model (tool calls, image parts, names) survives.
type Message map[string]json.RawMessage

// Role returns the message role, e.g. "user" or "system".
func (m Message) Role() string {
	var role string
	json.Unmarshal(m["role"], &role)
	return role
}

// Text returns the message's text. Content can be a plain string or a list
// of parts (text, images); for a list, the text parts are joined.
func (m Message) Text() string {
	raw := m["content"]
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var texts []string
	for _, p := range parts {
		if p.Type == "text" {
			texts = append(texts, p.Text)
		}
	}
	return strings.Join(texts, "\n")
}

// ParseRequest reads a chat completion request body.
func ParseRequest(body []byte) (*Request, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, errors.New("request body must be a JSON object")
	}

	req := &Request{fields: fields}
	if err := json.Unmarshal(fields["model"], &req.Model); err != nil || req.Model == "" {
		return nil, errors.New(`"model" is required and must be a string`)
	}
	if err := json.Unmarshal(fields["messages"], &req.Messages); err != nil || len(req.Messages) == 0 {
		return nil, errors.New(`"messages" is required and must be a non-empty list`)
	}
	if raw, ok := fields["max_tokens"]; ok {
		var n int
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, errors.New(`"max_tokens" must be an integer`)
		}
		req.MaxTokens = &n
	}
	return req, nil
}

// Encode turns the request back into JSON, including any changes checks
// made, plus all the fields that were never parsed.
func (r *Request) Encode() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(r.fields))
	for k, v := range r.fields {
		out[k] = v
	}
	var err error
	if out["model"], err = json.Marshal(r.Model); err != nil {
		return nil, err
	}
	if out["messages"], err = json.Marshal(r.Messages); err != nil {
		return nil, err
	}
	if r.MaxTokens != nil {
		if out["max_tokens"], err = json.Marshal(*r.MaxTokens); err != nil {
			return nil, err
		}
	}
	return json.Marshal(out)
}
