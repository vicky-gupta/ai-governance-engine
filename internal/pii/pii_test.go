package pii

import (
	"strings"
	"testing"
)

func TestDetectsValidValues(t *testing.T) {
	cases := []struct {
		text string
		kind Kind
	}{
		{"Pay to DE89 3704 0044 0532 0130 00 please", IBAN},
		{"IBAN: DE89370400440532013000", IBAN},
		{"UK account GB82 WEST 1234 5698 7654 32", IBAN},
		{"Card 4111 1111 1111 1111 expires soon", Card},
		{"Card 4111-1111-1111-1111", Card},
		{"Write to anna.schmidt@example.com today", Email},
		{"Call +49 30 12345678", Phone},
		{"Call +33 1 23 45 67 89", Phone},
		{"Call +49 (30) 12345678", Phone},
		{"Steuer-ID 86095742719", DETaxID},
		{"DNI 12345678Z", ESDNI},
		{"DNI 12345678-z", ESDNI},
	}
	for _, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			m := Find(tc.text)
			if len(m) != 1 || m[0].Kind != tc.kind {
				t.Errorf("Find(%q) = %+v, want one %s", tc.text, m, tc.kind)
			}
		})
	}
}

func TestIgnoresLookAlikes(t *testing.T) {
	cases := []string{
		"IBAN DE89 3704 0044 0532 0130 01", // wrong IBAN checksum
		"Card 4111 1111 1111 1112",         // fails Luhn
		"Order 0000 0000 0000 0000",        // all the same digit
		"Steuer-ID 86095742718",            // wrong check digit
		"DNI 12345678A",                    // wrong letter
		"Call +49 123",                     // too few digits for a phone
		"Meeting on 2026-11-06 at 10:30",   // a date and time
		"Invoice 12345, quantity 250",      // short numbers
	}
	for _, text := range cases {
		t.Run(text, func(t *testing.T) {
			if m := Find(text); len(m) != 0 {
				t.Errorf("Find(%q) = %+v, want nothing", text, m)
			}
		})
	}
}

func TestOverlapsKeepTheLongestMatch(t *testing.T) {
	// The digits inside an IBAN must not also be reported as a card or
	// tax ID: one value, one match.
	m := Find("DE89 3704 0044 0532 0130 00")
	if len(m) != 1 || m[0].Kind != IBAN {
		t.Errorf("got %+v, want a single IBAN", m)
	}
}

func TestRedactorUsesConsistentTokens(t *testing.T) {
	r := NewRedactor()
	first := r.Redact("Send from DE89 3704 0044 0532 0130 00 to GB82 WEST 1234 5698 7654 32.")
	second := r.Redact("Confirm DE89370400440532013000 (no spaces) and email a@b.eu.")

	if first != "Send from [IBAN_1] to [IBAN_2]." {
		t.Errorf("first = %q", first)
	}
	// Same IBAN written differently, in another message: same token.
	if second != "Confirm [IBAN_1] (no spaces) and email [EMAIL_1]." {
		t.Errorf("second = %q", second)
	}
	if got := r.Summary(); got != "1 EMAIL, 2 IBAN" {
		t.Errorf("summary = %q", got)
	}
}

func TestRedactLeavesCleanTextAlone(t *testing.T) {
	text := "What are the opening hours of the Berlin office?"
	if got := NewRedactor().Redact(text); got != text {
		t.Errorf("got %q", got)
	}
}

func TestRedactKeepsSurroundingText(t *testing.T) {
	got := NewRedactor().Redact("Hi, I'm Anna (anna@example.com), card 4111111111111111, thanks!")
	want := "Hi, I'm Anna ([EMAIL_1]), card [CARD_1], thanks!"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if strings.Contains(got, "4111") {
		t.Error("card digits leaked")
	}
}

func TestRedactKeepsBrackets(t *testing.T) {
	got := NewRedactor().Redact("Reach me (+49 30 12345678).")
	if got != "Reach me ([PHONE_1])." {
		t.Errorf("got %q: the closing bracket must stay", got)
	}
}
