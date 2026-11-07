// Package pii finds personal data in text and replaces it with tokens like
// [IBAN_1]. Detection is pattern-based: each kind has a regular expression
// to find candidates, and most have a checksum to reject look-alikes.
package pii

import (
	"regexp"
	"sort"
	"strings"
)

// Kind is a type of personal data.
type Kind string

const (
	IBAN    Kind = "IBAN"      // bank account (all EU countries)
	Card    Kind = "CARD"      // payment card number
	Email   Kind = "EMAIL"     // email address
	Phone   Kind = "PHONE"     // phone number in international format
	DETaxID Kind = "DE_TAX_ID" // German tax ID (Steuer-ID)
	ESDNI   Kind = "ES_DNI"    // Spanish national ID (DNI)
)

// Match is one piece of personal data found in a text.
type Match struct {
	Kind       Kind
	Start, End int // byte positions in the text
	Value      string
}

type detector struct {
	kind  Kind
	re    *regexp.Regexp
	valid func(string) bool // nil means the pattern alone is enough

	// claimsWhenInvalid: a hit with a failed checksum still "owns" its text,
	// so other detectors can't report pieces of it. An IBAN-shaped string
	// with a typo is not redacted, but its digits aren't a card number either.
	claimsWhenInvalid bool
}

// detectors in priority order: when two matches overlap and start at the
// same place with the same length, the earlier detector wins.
var detectors = []detector{
	{IBAN, regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`), validIBAN, true},
	{Card, regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`), validCard, false},
	{Email, regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`), nil, false},
	{Phone, regexp.MustCompile(`\+[1-9]\d{0,2}(?:[ .\-/]?(?:\(\d{1,5}\)|\d{1,5})){2,6}`), validPhone, false},
	{DETaxID, regexp.MustCompile(`\b[1-9]\d{10}\b`), validDETaxID, false},
	{ESDNI, regexp.MustCompile(`(?i)\b\d{8}-?[A-Z]\b`), validESDNI, false},
}

// Find returns all personal data in text, in order, without overlaps.
func Find(text string) []Match {
	type candidate struct {
		Match
		priority int
		report   bool // false: claims its text but isn't reported
	}
	var cands []candidate
	for p, d := range detectors {
		for _, loc := range d.re.FindAllStringIndex(text, -1) {
			value := text[loc[0]:loc[1]]
			valid := d.valid == nil || d.valid(value)
			if valid || d.claimsWhenInvalid {
				cands = append(cands, candidate{Match{d.kind, loc[0], loc[1], value}, p, valid})
			}
		}
	}

	// Earliest first; for the same start, the longest; then by priority.
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.Start != b.Start {
			return a.Start < b.Start
		}
		if a.End-a.Start != b.End-b.Start {
			return a.End-a.Start > b.End-b.Start
		}
		return a.priority < b.priority
	})

	// Keep a match only if it doesn't overlap one already kept.
	var out []Match
	end := -1
	for _, c := range cands {
		if c.Start >= end {
			if c.report {
				out = append(out, c.Match)
			}
			end = c.End
		}
	}
	return out
}

// normalize removes separators and upper-cases, so "DE89 3704…" and
// "de893704…" count as the same value.
func normalize(s string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "", ".", "", "/", "", "(", "", ")", "").Replace(s))
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
