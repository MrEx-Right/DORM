package plugins

import (
	"regexp"
	"strings"
	"unicode"
)

// Filters shared by the secret/API-key plugins (secretharvester.go,
// apikey.go). Prefix rules like `sk-...` and the entropy scan matched
// ordinary identifiers in real bundles: `plesk-ext-social-login-jwt-session`
// (a Plesk setting name) as an "OpenAI key", and RequireJS module paths
// (`Magento_Ui/js/lib/knockout/...`, `jquery/ui-modules/widgets/...`) as
// "high-entropy tokens" — 180 of them on one storefront.

// atTokenStart reports whether a match at body[i] starts a standalone token
// rather than continuing a word (`plesk-ext-...` must not yield `sk-ext-...`).
func atTokenStart(body string, i int) bool {
	if i <= 0 {
		return true
	}
	c := body[i-1]
	return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')
}

// mixesCharClasses reports whether s mixes at least two of upper/lower/digit
// with two or more characters each — true for random key material (base62,
// base64, even letters-only Hugging Face tokens), false for lowercase
// identifiers such as `ext-social-login-jwt-session`.
func mixesCharClasses(s string) bool {
	var upper, lower, digit int
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= 'a' && r <= 'z':
			lower++
		case r >= '0' && r <= '9':
			digit++
		}
	}
	classes := 0
	for _, n := range []int{upper, lower, digit} {
		if n >= 2 {
			classes++
		}
	}
	return classes >= 2
}

// identifierLike reports whether s reads as words — a path, module id, CSS
// class or camelCase name — rather than random key material.
func identifierLike(s string) bool {
	segs := strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '_' || r == '-' || r == '.' })
	// A long random segment makes it a key, whatever its prefix segments
	// look like (`gsk_8Hn2Kd9Lq4...`, `sk-ant-api03-...`).
	for _, seg := range segs {
		if len(seg) >= 12 && mixesCharClasses(seg) && strings.IndexFunc(seg, unicode.IsDigit) >= 0 && !camelWords(seg) {
			return false
		}
	}
	// Separator-delimited: half or more segments are plain words (≥3 letters).
	if len(segs) >= 2 {
		words := 0
		for _, seg := range segs {
			if len(seg) >= 3 && isLetters(seg) {
				words++
			}
		}
		if words*2 >= len(segs) {
			return true
		}
	}
	return camelWords(s)
}

// camelWords reports whether s splits into word-length humps. A hump starts
// at the first letter, at an upper-case letter after a lower-case one, and at
// any letter after a digit or separator. Random base62/base64 breaks into
// ~2-letter humps; names into 3+ (enable32bitAppOnWin64True →
// enable/bit/App/On/Win/True, getElementsByClassName → get/Elements/By/...).
func camelWords(s string) bool {
	humps, letters := 0, 0
	prev := rune(0)
	for _, r := range s {
		if unicode.IsLetter(r) {
			if prev == 0 || !unicode.IsLetter(prev) || (unicode.IsUpper(r) && unicode.IsLower(prev)) {
				humps++
			}
			letters++
		}
		prev = r
	}
	return humps > 0 && float64(letters)/float64(humps) >= 3
}

func isLetters(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// plausibleKey is the shape check for a prefixed key's random part.
func plausibleKey(random string) bool {
	return mixesCharClasses(random) && !identifierLike(random)
}

// plausibleEntropyToken is the stricter check for un-prefixed tokens found
// only by entropy: they must also contain a digit, since nothing else says
// they are a credential.
func plausibleEntropyToken(token string) bool {
	return shannonEntropy(token) >= 4.0 && strings.IndexFunc(token, unicode.IsDigit) >= 0 && plausibleKey(token)
}

// findKeys returns the matches of re in body that start a standalone token
// and, when prefixes are given, whose part after the longest matching prefix
// looks like random key material (list longer prefixes first, e.g.
// "sk-proj-" before "sk-").
func findKeys(re *regexp.Regexp, body string, prefixes ...string) []string {
	var out []string
	for _, loc := range re.FindAllStringIndex(body, -1) {
		if !atTokenStart(body, loc[0]) {
			continue
		}
		m := body[loc[0]:loc[1]]
		if len(prefixes) > 0 {
			random := ""
			for _, p := range prefixes {
				if strings.HasPrefix(m, p) {
					random = m[len(p):]
					break
				}
			}
			if random == "" || !plausibleKey(random) {
				continue
			}
		}
		out = append(out, m)
	}
	return out
}
