package models

import (
	"regexp"
	"strings"
)

// Plesk 18 login pages print a telemetry block for the vendor's own UX
// tracking:
//
//	Jsw.UAT.init({"versionInfo":"18.0.72", ..., "firehose":{"stream":"plesk-18.0-ux",
//	    "region":"us-west-2","accessKeyId":"AKIA...","secretAccessKey":"..."}});
//
// Older releases (18.0.72 seen) embed Plesk's real AWS Kinesis Firehose key
// there; newer ones (18.0.81 seen) send "00000000000000000000" and post
// through uat-proxy.plesk.com. The key belongs to Plesk, not to the site, so
// it is not the site's leaked credential.

var (
	pleskAccessKeyIDRe = regexp.MustCompile(`"accessKeyId"\s*:\s*"$`)
	pleskVersionRe     = regexp.MustCompile(`"versionInfo"\s*:\s*"([^"]*)"`)
)

// PleskUATKey reports whether the AWS key that starts at body[at] is the
// firehose accessKeyId of a Plesk Jsw.UAT.init block, and returns the Plesk
// version that block names ("" when it names none).
func PleskUATKey(body string, at int) (version string, ok bool) {
	start := strings.LastIndex(body[:at], "Jsw.UAT.init(")
	if start < 0 {
		return "", false
	}
	end := strings.Index(body[start:], "});")
	if end < 0 || start+end < at {
		return "", false
	}
	block := body[start : start+end]
	if !strings.Contains(block, `"firehose"`) || !pleskAccessKeyIDRe.MatchString(body[start:at]) {
		return "", false
	}
	if m := pleskVersionRe.FindStringSubmatch(block); m != nil {
		version = m[1]
	}
	return version, true
}
