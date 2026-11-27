// Package usage meters how many tokens each AI system uses, from the
// usage numbers providers put in their responses, and stores them so
// budgets can be enforced and costs reported per system.
package usage

import (
	"bytes"
	"encoding/json"
	"time"
)

// Usage is the token count of one request, as the provider reported it.
type Usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// Record is one metered request.
type Record struct {
	RequestID  string
	SystemID   string
	SystemName string // not stored (the ID is); for logs and metrics
	Model      string
	Provider   string
	Usage
	CreatedAt time.Time
}

// MonthStart returns the first moment of t's calendar month in UTC.
// Budgets reset then.
func MonthStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// chunk is the part of a response (or of one streamed chunk) we read.
// Groq also reports usage under x_groq when streaming.
type chunk struct {
	Model string `json:"model"`
	Usage *Usage `json:"usage"`
	XGroq *struct {
		Usage *Usage `json:"usage"`
	} `json:"x_groq"`
}

// parse reads model and usage from one JSON document. ok is false when it
// has no usage.
func parse(doc []byte) (model string, u Usage, ok bool) {
	var c chunk
	if json.Unmarshal(doc, &c) != nil {
		return "", Usage{}, false
	}
	switch {
	case c.Usage != nil:
		return c.Model, *c.Usage, true
	case c.XGroq != nil && c.XGroq.Usage != nil:
		return c.Model, *c.XGroq.Usage, true
	}
	return c.Model, Usage{}, false
}

// sseScanner reads a server-sent-events stream as it passes through,
// line by line, and keeps the last usage it sees. It never holds more
// than one line in memory.
type sseScanner struct {
	partial []byte
	model   string
	usage   Usage
	found   bool
}

func (s *sseScanner) Write(p []byte) {
	s.partial = append(s.partial, p...)
	for {
		i := bytes.IndexByte(s.partial, '\n')
		if i < 0 {
			return
		}
		s.line(s.partial[:i])
		s.partial = s.partial[i+1:]
	}
}

func (s *sseScanner) line(l []byte) {
	l = bytes.TrimSpace(l)
	data, ok := bytes.CutPrefix(l, []byte("data:"))
	if !ok {
		return
	}
	data = bytes.TrimSpace(data)
	// Most chunks carry a few words of text; only parse those that can
	// hold usage numbers.
	if !bytes.Contains(data, []byte(`"usage"`)) {
		return
	}
	if model, u, ok := parse(data); ok {
		s.model, s.usage, s.found = model, u, true
	}
}
