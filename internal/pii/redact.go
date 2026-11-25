package pii

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Replacement records one value that was replaced, so it can be stored
// (encrypted) and looked up later.
type Replacement struct {
	Token string
	Kind  Kind
	Value string // the value as first written in the request
}

// Redactor replaces personal data with tokens. Use one Redactor per
// request, so the same value gets the same token everywhere in it: if a
// user mentions one IBAN twice, the model sees [IBAN_1] twice and can
// still reason about it.
type Redactor struct {
	tokens       map[string]string // kind + normalized value -> token
	counts       map[Kind]int
	replacements []Replacement

	// Optional: a Detector for names and places. Redact can't return an
	// error (it is used with Message.MapText), so a Detector failure is
	// kept in err; check Err after redacting.
	ctx      context.Context
	detector Detector
	err      error
}

func NewRedactor() *Redactor {
	return &Redactor{tokens: map[string]string{}, counts: map[Kind]int{}}
}

// WithDetector also uses d to find personal data, for this request's ctx.
func (r *Redactor) WithDetector(ctx context.Context, d Detector) *Redactor {
	r.ctx, r.detector = ctx, d
	return r
}

// Err returns the first Detector error, if any. If it is not nil, the
// redacted text may still contain personal data the Detector would have
// found.
func (r *Redactor) Err() error {
	return r.err
}

// Redact returns text with every match replaced by its token.
func (r *Redactor) Redact(text string) string {
	matches := Find(text)
	if r.detector != nil && r.err == nil {
		more, err := r.detector.Detect(r.ctx, text)
		if err != nil {
			r.err = err
		} else {
			matches = Merge(matches, more)
		}
	}
	if len(matches) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		b.WriteString(text[last:m.Start])
		b.WriteString(r.token(m))
		last = m.End
	}
	b.WriteString(text[last:])
	return b.String()
}

func (r *Redactor) token(m Match) string {
	key := string(m.Kind) + ":" + Normalize(m.Value)
	if t, ok := r.tokens[key]; ok {
		return t
	}
	r.counts[m.Kind]++
	t := fmt.Sprintf("[%s_%d]", m.Kind, r.counts[m.Kind])
	r.tokens[key] = t
	r.replacements = append(r.replacements, Replacement{Token: t, Kind: m.Kind, Value: m.Value})
	return t
}

// Replacements lists every distinct value replaced so far, in the order
// their tokens were created.
func (r *Redactor) Replacements() []Replacement {
	return r.replacements
}

// Summary describes what was redacted, without the values themselves,
// e.g. "1 EMAIL, 2 IBAN". It is safe to log and audit.
func (r *Redactor) Summary() string {
	kinds := make([]string, 0, len(r.counts))
	for k := range r.counts {
		kinds = append(kinds, string(k))
	}
	sort.Strings(kinds)
	parts := make([]string, len(kinds))
	for i, k := range kinds {
		parts[i] = fmt.Sprintf("%d %s", r.counts[Kind(k)], k)
	}
	return strings.Join(parts, ", ")
}
