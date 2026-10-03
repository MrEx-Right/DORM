package bypassers

import (
	"math/rand"
	"unicode"
)

// CaseAlternate randomly flips the case of each letter in payload,
// leaving digits, punctuation, and symbols untouched.
//
// Many WAF signature rules match keywords case-sensitively, or only
// normalize a single fixed casing before comparison. SQL keywords and
// HTML tag/attribute/event names are case-insensitive to their real
// interpreters, so a payload like "sElEcT" or "<ScRiPt>" still executes
// correctly on the backend while slipping past a naive "select"/"script"
// pattern match.
func CaseAlternate(payload string) string {
	if payload == "" {
		return ""
	}
	runes := []rune(payload)
	for i, r := range runes {
		if !unicode.IsLetter(r) {
			continue
		}
		if rand.Intn(2) == 0 {
			runes[i] = unicode.ToUpper(r)
		} else {
			runes[i] = unicode.ToLower(r)
		}
	}
	return string(runes)
}
