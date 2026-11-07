package pii

import (
	"fmt"
	"sort"
	"strings"
)

// Redactor replaces personal data with tokens. Use one Redactor per
// request, so the same value gets the same token everywhere in it: if a
// user mentions one IBAN twice, the model sees [IBAN_1] twice and can
// still reason about it.
type Redactor struct {
	tokens map[string]string // kind + normalized value -> token
	counts map[Kind]int
}

func NewRedactor() *Redactor {
	return &Redactor{tokens: map[string]string{}, counts: map[Kind]int{}}
}

// Redact returns text with every match replaced by its token.
func (r *Redactor) Redact(text string) string {
	matches := Find(text)
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
	key := string(m.Kind) + ":" + normalize(m.Value)
	if t, ok := r.tokens[key]; ok {
		return t
	}
	r.counts[m.Kind]++
	t := fmt.Sprintf("[%s_%d]", m.Kind, r.counts[m.Kind])
	r.tokens[key] = t
	return t
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
