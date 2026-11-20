package outputguard

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
)

// maxStreamText caps how much answer text is kept from a stream for the
// check afterwards.
const maxStreamText = 1 << 20

// streamText collects the answer text of a streamed response as it
// passes through, from the "delta.content" of each chunk.
type streamText struct {
	partial []byte
	text    strings.Builder
}

func (s *streamText) Write(p []byte) {
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

func (s *streamText) line(l []byte) {
	data, ok := bytes.CutPrefix(bytes.TrimSpace(l), []byte("data:"))
	if !ok || s.text.Len() > maxStreamText {
		return
	}
	var chunk struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if json.Unmarshal(bytes.TrimSpace(data), &chunk) != nil {
		return // e.g. "[DONE]"
	}
	for _, c := range chunk.Choices {
		s.text.WriteString(c.Delta.Content)
	}
}

// String returns all text seen, including a last line without a newline.
func (s *streamText) String() string {
	if len(s.partial) > 0 {
		s.line(s.partial)
		s.partial = nil
	}
	return s.text.String()
}

// answer is a parsed non-streamed response, kept as generic JSON so that
// fields the gateway doesn't know about survive a rewrite.
type answer struct {
	doc map[string]any
}

func parseAnswer(body []byte) (*answer, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // keep numbers exactly as the provider wrote them
	var doc map[string]any
	if dec.Decode(&doc) != nil {
		return nil, false
	}
	return &answer{doc: doc}, true
}

// eachText calls f with the text of every choice's message. If f returns a
// different string, the message is changed to it.
func (a *answer) eachText(f func(string) string) {
	choices, _ := a.doc["choices"].([]any)
	for _, c := range choices {
		choice, _ := c.(map[string]any)
		msg, _ := choice["message"].(map[string]any)
		if text, ok := msg["content"].(string); ok {
			msg["content"] = f(text)
		}
	}
}

// text returns the text of all choices, joined.
func (a *answer) text() string {
	var parts []string
	a.eachText(func(t string) string {
		parts = append(parts, t)
		return t
	})
	return strings.Join(parts, "\n")
}

// redact replaces every piece of personal data in text with a marker
// such as [REDACTED_IBAN]. These are different from the request's tokens
// ([IBAN_1]): there is no stored value behind them.
func redact(text string, found []pii.Match) string {
	var b strings.Builder
	last := 0
	for _, m := range found {
		b.WriteString(text[last:m.Start])
		b.WriteString("[REDACTED_" + string(m.Kind) + "]")
		last = m.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// kinds returns the distinct kinds of personal data found, sorted.
func kinds(found []pii.Match) []string {
	seen := map[string]bool{}
	for _, m := range found {
		seen[string(m.Kind)] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
