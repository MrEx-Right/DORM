package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// 45. DANGEROUS HTTP METHODS - v2
type DangerousMethodsPlugin struct{}

func (p *DangerousMethodsPlugin) Name() string { return "Dangerous HTTP Methods" }

func (p *DangerousMethodsPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	// Redirects are not followed: a redirected TRACE/PUT is not the method
	// being accepted here (Go turns PUT into GET on 301/302/303).
	client := models.NoRedirectClient()

	// TRACE: only a server that actually echoes the request is vulnerable to
	// XST. The OPTIONS "Allow" header is not evidence — IIS lists TRACE in
	// Allow/Public by default and still answers TRACE with 501.
	marker := "dorm-trace-" + models.RandomToken()
	if reqTrace, err := http.NewRequest("TRACE", getURL(target, "/"), nil); err == nil {
		reqTrace.Header.Set("X-Dorm-Trace", marker)
		if respTrace, err := client.Do(reqTrace); err == nil {
			body := readBody(respTrace, 65536)
			if respTrace.StatusCode == 200 && strings.Contains(body, marker) {
				return &models.Vulnerability{
					Target:      target,
					Name:        "Dangerous Method (TRACE)",
					Severity:    "MEDIUM",
					CVSS:        5.0,
					Description: "The server answers TRACE and echoes the request back (a custom X-Dorm-Trace header was reflected in the response body), which can lead to Cross-Site Tracing (XST) attacks.",
					Solution:    "Disable the TRACE method in web server configuration.",
					Reference:   "OWASP XST",
				}
			}
		}
	}

	randomID := fmt.Sprintf("%d", time.Now().UnixNano())
	testFileName := fmt.Sprintf("/dorm_test_%s.txt", randomID)
	testContent := fmt.Sprintf("DORM_SECURITY_CHECK_%s", randomID)

	reqPut, _ := http.NewRequest("PUT", getURL(target, testFileName), strings.NewReader(testContent))
	reqPut.Header.Set("Content-Type", "text/plain")

	respPut, err := client.Do(reqPut)
	if err != nil {
		return nil
	}
	_ = respPut.Body.Close()

	if respPut.StatusCode == 201 || respPut.StatusCode == 200 {

		reqGet, _ := http.NewRequest("GET", getURL(target, testFileName), nil)
		respGet, err := client.Do(reqGet)

		if err == nil {
			defer func() { _ = respGet.Body.Close() }()

			bodyBytes, _ := io.ReadAll(io.LimitReader(respGet.Body, 65536))
			uploadedContent := string(bodyBytes)

			if respGet.StatusCode == 200 && strings.Contains(uploadedContent, testContent) {

				reqDel, _ := http.NewRequest("DELETE", getURL(target, testFileName), nil)
				if respDel, errDel := client.Do(reqDel); errDel == nil {
					_ = respDel.Body.Close()
				}

				return &models.Vulnerability{
					Target:      target,
					Name:        "Arbitrary File Upload (PUT)",
					Severity:    "CRITICAL",
					CVSS:        9.1,
					Description: fmt.Sprintf("Confirmed file upload via PUT method.\nFile: %s\nContent Verified: Yes", testFileName),
					Solution:    "Disable the PUT method or implement strict authentication/authorization.",
					Reference:   "CWE-434: Unrestricted Upload",
				}
			}
		}
	}

	return nil
}
