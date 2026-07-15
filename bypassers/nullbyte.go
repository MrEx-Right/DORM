package bypassers

import (
	"strings"
)

// InjectNullByte appends a safe null byte (%00) to the provided string.
// This is typically used for exploiting logic flaws in backend parsing,
// specifically file path truncation in older systems (like PHP < 5.3) or specific WAF bypasses.
//
// CAUTION: Use this ONLY on specific query parameters or path segments.
// Never append this to the entire raw URL or host, as it will corrupt the HTTP request.
func InjectNullByte(target string) string {
	if strings.HasSuffix(target, "%00") {
		return target
	}
	return target + "%00"
}
