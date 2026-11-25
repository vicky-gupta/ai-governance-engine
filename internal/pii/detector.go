package pii

import (
	"context"
	"sort"
)

// Detector finds personal data that patterns can't: names and places,
// which have no fixed shape and need a language model.
type Detector interface {
	Detect(ctx context.Context, text string) ([]Match, error)
}

// Merge combines pattern matches with a Detector's matches, in order and
// without overlaps. Where they overlap, the pattern match wins: it was
// checked with a checksum, the model's guess was not.
func Merge(patterns, more []Match) []Match {
	out := append([]Match(nil), patterns...)
	for _, m := range more {
		overlaps := false
		for _, p := range out {
			if m.Start < p.End && p.Start < m.End {
				overlaps = true
				break
			}
		}
		if !overlaps {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}
