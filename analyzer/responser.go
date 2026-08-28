package analyzer

import (
	"DORM/models"
	"net/http"
	"regexp"
	"strconv"
)

// Regex patterns for Information Leakage
var (
	awsKeyRegex       = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	privateKeyRegex   = regexp.MustCompile(`-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----`)
)

// AnalyzeResponse parses the HTTP response to detect passive vulnerabilities
func AnalyzeResponse(req *http.Request, resp *http.Response, bodyBytes []byte) {
	if OnVulnFound == nil {
		return
	}

	target := getTarget(req)
	bodyStr := string(bodyBytes)

	// 1. Missing Security Headers (Disabled by user request to avoid OSINT noise)
	// checkSecurityHeaders(target, resp)

	// 2. Information Leakage in Body (Critical/High findings only)
	checkInformationLeakage(target, bodyStr)

	// 3. Server Information Disclosure (Disabled by user request)
	// checkServerDisclosure(target, resp)
}


func checkInformationLeakage(target models.ScanTarget, bodyStr string) {
	if awsKeyRegex.MatchString(bodyStr) {
		reportVuln(target, "AWS Access Key Leakage", "CRITICAL", 9.0, "An AWS Access Key was found exposed in the response body.", "Remove the key and rotate it immediately.")
	}
	if privateKeyRegex.MatchString(bodyStr) {
		reportVuln(target, "Private Key Disclosure", "CRITICAL", 9.5, "A cryptographic private key was found exposed in the response body.", "Remove the key and regenerate a new pair immediately.")
	}
	// Note: Emails can be noisy, so we might want to skip or make it INFO.
}


func reportVuln(target models.ScanTarget, name, severity string, cvss float64, desc, solution string) {
	OnVulnFound(&models.Vulnerability{
		Target:      target,
		Name:        "Analyzer: " + name,
		Severity:    severity,
		CVSS:        cvss,
		Description: desc,
		Solution:    solution,
		Reference:   "Native Passive Analyzer",
		Status:      "Open",
	})
}

func getTarget(req *http.Request) models.ScanTarget {
	host := req.URL.Hostname()
	portStr := req.URL.Port()
	port := 80
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err == nil {
			port = p
		}
	} else if req.URL.Scheme == "https" {
		port = 443
	}

	return models.ScanTarget{
		IP:   host,
		Port: port,
	}
}
