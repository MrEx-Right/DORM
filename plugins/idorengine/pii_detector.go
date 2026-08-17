package idorengine

import "strings"

// ============================================================
//  PII DETECTOR — Sensitive Information Leak Detection
// ============================================================

// DetectPII analyzes text to see if it contains Personally Identifiable Information.
func DetectPII(text string) bool {
	lowerText := strings.ToLower(text)
	piiKeywords := []string{
		"\"email\":", "email_address", "\"ssn\":", "\"phone\":", "\"phone_number\":",
		"\"credit_card\"", "\"card_number\"", "\"dob\"", "\"date_of_birth\"",
		"\"address\"", "\"passport\"", "\"national_id\"", "\"salary\"",
		"\"bank_account\"", "\"iban\"", "\"cvv\"", "\"password_hash\"",
	}

	score := 0
	for _, kw := range piiKeywords {
		if strings.Contains(lowerText, kw) {
			score++
		}
	}

	// Also check common formatting (like JSON keys for personal data)
	if strings.Contains(lowerText, "\"first_name\":") && strings.Contains(lowerText, "\"last_name\":") {
		score++
	}

	// We need a score of at least 1 to flag it as PII leak
	return score > 0
}
