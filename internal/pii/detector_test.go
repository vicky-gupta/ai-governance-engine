package pii

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeDetector reports every occurrence of the given names as PERSON.
type fakeDetector struct {
	names []string
	err   error
}

func (f fakeDetector) Detect(_ context.Context, text string) ([]Match, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []Match
	for _, n := range f.names {
		for i := 0; ; {
			j := strings.Index(text[i:], n)
			if j < 0 {
				break
			}
			out = append(out, Match{Kind: Person, Start: i + j, End: i + j + len(n), Value: n})
			i += j + len(n)
		}
	}
	return out, nil
}

func TestMergePatternsWin(t *testing.T) {
	patterns := []Match{{Kind: Email, Start: 10, End: 30}}
	more := []Match{
		{Kind: Person, Start: 0, End: 5},   // before: kept
		{Kind: Person, Start: 12, End: 18}, // inside the email: dropped
		{Kind: Location, Start: 40, End: 46},
	}
	got := Merge(patterns, more)
	if len(got) != 3 || got[0].Kind != Person || got[1].Kind != Email || got[2].Kind != Location {
		t.Errorf("Merge = %+v, want person, email, location in order", got)
	}
}

func TestRedactorWithDetector(t *testing.T) {
	r := NewRedactor().WithDetector(context.Background(), fakeDetector{names: []string{"Jürgen Müller", "JÜRGEN MÜLLER"}})
	got := r.Redact("Jürgen Müller (juergen@example.de) und JÜRGEN MÜLLER")
	// The same name, written differently, gets the same token, like IBANs do.
	if want := "[PERSON_1] ([EMAIL_1]) und [PERSON_1]"; got != want {
		t.Errorf("Redact = %q, want %q", got, want)
	}
	if r.Err() != nil || r.Summary() != "1 EMAIL, 1 PERSON" {
		t.Errorf("Err = %v, Summary = %q", r.Err(), r.Summary())
	}
}

func TestRedactorKeepsDetectorError(t *testing.T) {
	r := NewRedactor().WithDetector(context.Background(), fakeDetector{err: errors.New("ner down")})
	got := r.Redact("mail juergen@example.de")
	if got != "mail [EMAIL_1]" {
		t.Errorf("patterns should still work: %q", got)
	}
	if r.Err() == nil {
		t.Error("the detector error was lost")
	}
}

func TestNewKindsAreValid(t *testing.T) {
	for _, k := range []Kind{Person, Location, IBAN} {
		if !ValidKind(k) {
			t.Errorf("ValidKind(%s) = false", k)
		}
	}
}
