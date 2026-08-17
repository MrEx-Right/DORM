package wafengine

// ============================================================
//  BYPASS ADVISOR — WAF-specific bypass recommendations
// ============================================================

// bypassHint holds bypass strategies for a specific WAF.
type bypassHint struct {
	WAFName    string
	Strategies string
}

var bypassHints = []bypassHint{
	{
		WAFName: "Cloudflare",
		Strategies: "1) Use chunked transfer encoding\n" +
			"2) Unicode normalization bypass (e.g., ＜script＞)\n" +
			"3) HTTP/2 header manipulation\n" +
			"4) Payload fragmentation across parameters\n" +
			"5) Try /*!50000*/ MySQL comment obfuscation\n" +
			"6) Use case alternation: sElEcT, ScRiPt\n" +
			"7) Double URL encoding on key characters",
	},
	{
		WAFName: "AWS WAF",
		Strategies: "1) HTTP Parameter Pollution (HPP)\n" +
			"2) JSON-based injection (switch Content-Type)\n" +
			"3) Unicode escape sequences in payloads\n" +
			"4) Chunked transfer encoding\n" +
			"5) Overlong UTF-8 encoding\n" +
			"6) Try payloads in HTTP headers (X-Forwarded-For, Referer)",
	},
	{
		WAFName: "AWS CloudFront",
		Strategies: "1) Origin IP discovery + direct access\n" +
			"2) HTTP Parameter Pollution\n" +
			"3) Unicode normalization tricks\n" +
			"4) Cache poisoning to bypass WAF rules",
	},
	{
		WAFName: "Akamai",
		Strategies: "1) Null byte injection (%00)\n" +
			"2) Payload in multipart/form-data\n" +
			"3) HTTP verb tampering (use PUT/PATCH instead of POST)\n" +
			"4) Overlong UTF-8 sequences\n" +
			"5) Try payloads via WebSocket upgrade\n" +
			"6) Case alternation + inline comments",
	},
	{
		WAFName: "Imperva (Incapsula)",
		Strategies: "1) Request splitting via HTTP/1.1 keep-alive\n" +
			"2) Unicode fullwidth characters\n" +
			"3) Payload fragmentation with comments (/**/)\n" +
			"4) JSON body injection\n" +
			"5) Try exotic event handlers (ontoggle, onpageshow)",
	},
	{
		WAFName: "Sucuri",
		Strategies: "1) Payload in Cookie header\n" +
			"2) Double URL encoding\n" +
			"3) HTML entity encoding\n" +
			"4) Case variation bypass\n" +
			"5) Try tab/newline characters between keywords",
	},
	{
		WAFName: "F5 BIG-IP ASM",
		Strategies: "1) HTTP Parameter Pollution\n" +
			"2) Content-Type switching (JSON ↔ form-urlencoded)\n" +
			"3) Chunked transfer encoding\n" +
			"4) Try HEAD method with body\n" +
			"5) Unicode encoding bypass",
	},
	{
		WAFName: "ModSecurity",
		Strategies: "1) MySQL comment obfuscation (/*!50000*/)\n" +
			"2) Case alternation + whitespace obfuscation\n" +
			"3) Tab (%09) and newline (%0a) between SQL keywords\n" +
			"4) Scientific notation for numeric payloads\n" +
			"5) Rule set level detection (CRS paranoia level)\n" +
			"6) Payload padding to exceed rule inspection limits",
	},
	{
		WAFName: "Azure Front Door",
		Strategies: "1) JSON body injection\n" +
			"2) Unicode normalization\n" +
			"3) HTTP verb override (X-HTTP-Method-Override)\n" +
			"4) Content-Type manipulation",
	},
	{
		WAFName: "Google Cloud Armor",
		Strategies: "1) Double URL encoding\n" +
			"2) Unicode fullwidth characters\n" +
			"3) Payload in less-inspected headers\n" +
			"4) JSON nested object injection",
	},
	{
		WAFName: "Wordfence (WordPress)",
		Strategies: "1) Base64 encoded payloads\n" +
			"2) Double URL encoding\n" +
			"3) Payload in Referer header\n" +
			"4) Unicode escape sequences\n" +
			"5) Comment-based obfuscation",
	},
}

// GetBypassAdvisory returns WAF-specific bypass strategies.
func GetBypassAdvisory(wafName string) string {
	for _, hint := range bypassHints {
		if hint.WAFName == wafName {
			return hint.Strategies
		}
	}

	// Generic bypass strategies for unknown WAFs
	return "1) Try double URL encoding on payload characters\n" +
		"2) Use case alternation (e.g., sElEcT, sCrIpT)\n" +
		"3) Try inline SQL comments (/**/)\n" +
		"4) Switch Content-Type between JSON and form-urlencoded\n" +
		"5) Try payloads in HTTP headers (User-Agent, Referer, X-Forwarded-For)\n" +
		"6) Use chunked transfer encoding\n" +
		"7) HTTP Parameter Pollution"
}
