package pii

import "strings"

// validIBAN checks the ISO 13616 checksum: move the first four characters
// to the end, turn letters into numbers (A=10 … Z=35), and the result
// mod 97 must be 1. A random typo fails this almost every time.
func validIBAN(s string) bool {
	s = normalize(s)
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]
	rem := 0
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			rem = (rem*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			rem = (rem*100 + int(r-'A'+10)) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// validCard checks the Luhn checksum used by all payment cards.
func validCard(s string) bool {
	d := digitsOnly(s)
	if len(d) < 13 || len(d) > 19 || strings.Count(d, d[:1]) == len(d) {
		return false // wrong length, or all the same digit
	}
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// validPhone accepts 8 to 15 digits, the range allowed by E.164.
func validPhone(s string) bool {
	n := len(digitsOnly(s))
	return n >= 8 && n <= 15
}

// validDETaxID checks the German Steuer-ID check digit (ISO 7064 MOD 11,10).
func validDETaxID(s string) bool {
	if len(s) != 11 {
		return false
	}
	product := 10
	for i := 0; i < 10; i++ {
		sum := (int(s[i]-'0') + product) % 10
		if sum == 0 {
			sum = 10
		}
		product = (sum * 2) % 11
	}
	check := 11 - product
	if check == 10 {
		check = 0
	}
	return check == int(s[10]-'0')
}

// validESDNI checks the Spanish DNI letter: the number mod 23 picks it.
func validESDNI(s string) bool {
	s = normalize(s)
	if len(s) != 9 {
		return false
	}
	n := 0
	for _, r := range s[:8] {
		n = n*10 + int(r-'0')
	}
	return "TRWAGMYFPDXBNJZSQVHLCKE"[n%23] == s[8]
}
