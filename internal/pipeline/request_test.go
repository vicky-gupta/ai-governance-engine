package pipeline

import (
	"encoding/json"
	"testing"
)

func TestParseRequest(t *testing.T) {
	body := `{
		"model": "llama",
		"temperature": 0.2,
		"max_tokens": 500,
		"messages": [
			{"role": "system", "content": "Be brief."},
			{"role": "user", "content": [
				{"type": "text", "text": "What is in"},
				{"type": "image_url", "image_url": {"url": "https://example.com/a.png"}},
				{"type": "text", "text": "this picture?"}
			]}
		]
	}`
	req, err := ParseRequest([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if req.Model != "llama" || *req.MaxTokens != 500 || len(req.Messages) != 2 {
		t.Fatalf("parsed %+v", req)
	}
	if got := req.Messages[0].Role(); got != "system" {
		t.Errorf("role = %q", got)
	}
	if got := req.Messages[1].Text(); got != "What is in\nthis picture?" {
		t.Errorf("text from parts = %q", got)
	}
}

func TestParseRequestErrors(t *testing.T) {
	cases := map[string]string{
		"not JSON":       `hello`,
		"JSON array":     `[]`,
		"missing model":  `{"messages":[{"role":"user","content":"hi"}]}`,
		"empty messages": `{"model":"m","messages":[]}`,
		"bad max_tokens": `{"model":"m","messages":[{"role":"user","content":"hi"}],"max_tokens":"lots"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRequest([]byte(body)); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestEncodeKeepsUnknownFields(t *testing.T) {
	req, err := ParseRequest([]byte(`{"model":"m","stream":true,"temperature":0.2,"messages":[{"role":"user","content":"hi","name":"bob"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	limit := 100
	req.MaxTokens = &limit

	out, err := req.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	json.Unmarshal(out, &got)

	if got["stream"] != true || got["temperature"] != 0.2 {
		t.Errorf("unknown top-level fields lost: %s", out)
	}
	if got["max_tokens"] != float64(100) {
		t.Errorf("max_tokens = %v, want 100", got["max_tokens"])
	}
	msg := got["messages"].([]any)[0].(map[string]any)
	if msg["name"] != "bob" {
		t.Errorf("unknown message field lost: %s", out)
	}
}
