// Package ner asks the NER sidecar (ner/, Presidio with spaCy models)
// for names and places in a text. It implements pii.Detector, so the
// redaction check can use it next to the pattern detectors.
package ner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vicky-gupta/ai-governance-engine/internal/pii"
)

// Client talks to the sidecar's HTTP API.
type Client struct {
	url  string
	http *http.Client
}

// New returns a client for the sidecar at baseURL, e.g. http://localhost:3000.
func New(baseURL string, timeout time.Duration) *Client {
	return &Client{url: strings.TrimRight(baseURL, "/"), http: &http.Client{Timeout: timeout}}
}

// kinds maps the sidecar's entity types to ours. Others are ignored.
var kinds = map[string]pii.Kind{
	"PERSON":   pii.Person,
	"LOCATION": pii.Location,
}

type entity struct {
	Type  string  `json:"type"`
	Start int     `json:"start"` // in characters, not bytes
	End   int     `json:"end"`
	Score float64 `json:"score"`
}

// Detect implements pii.Detector.
func (c *Client) Detect(ctx context.Context, text string) ([]pii.Match, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ner: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("ner: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out struct {
		Entities []entity `json:"entities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("ner: bad response: %w", err)
	}

	// The sidecar counts characters (Python), Go strings count bytes. In
	// "Jürgen", ü is one character but two bytes, so the offsets have to
	// be converted, or every name after an umlaut would be cut wrong.
	byteAt := byteOffsets(text)
	var matches []pii.Match
	for _, e := range out.Entities {
		kind, ok := kinds[e.Type]
		if !ok {
			continue
		}
		if e.Start < 0 || e.End > len(byteAt)-1 || e.Start >= e.End {
			return nil, fmt.Errorf("ner: entity offsets %d-%d out of range", e.Start, e.End)
		}
		start, end := byteAt[e.Start], byteAt[e.End]
		matches = append(matches, pii.Match{Kind: kind, Start: start, End: end, Value: text[start:end]})
	}
	return onlyAboutPeople(matches), nil
}

// onlyAboutPeople drops places when no person is named in the same text.
// A place on its own is not personal data ("What is the capital of
// France?"); next to a name it is ("Jürgen Müller from Munich"), because
// it helps to identify that person. Redacting every place would make
// harmless questions unanswerable.
func onlyAboutPeople(matches []pii.Match) []pii.Match {
	for _, m := range matches {
		if m.Kind == pii.Person {
			return matches
		}
	}
	var out []pii.Match
	for _, m := range matches {
		if m.Kind != pii.Location {
			out = append(out, m)
		}
	}
	return out
}

// byteOffsets returns, for each character position i (and the end), the
// byte position where that character starts. Go's range over a string
// steps through it one character (rune) at a time, like Python's str.
func byteOffsets(text string) []int {
	offsets := make([]int, 0, len(text)+1)
	for i := range text {
		offsets = append(offsets, i)
	}
	return append(offsets, len(text))
}

// Ping checks that the sidecar is up, for the startup log.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ner: health status %d", resp.StatusCode)
	}
	return nil
}
