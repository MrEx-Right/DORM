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

	reqOptions, _ := http.NewRequest("OPTIONS", getURL(target, "/"), nil)
	respOptions, err := models.GetClient().Do(reqOptions)
	if err == nil {
		defer respOptions.Body.Close()
		allowHeader := respOptions.Header.Get("Allow")

		if strings.Contains(allowHeader, "TRACE") {
			return &models.Vulnerability{
				Target:      target,
				Name:        "Dangerous Method (TRACE)",
				Severity:    "MEDIUM",
				CVSS:        5.0,
				Description: "The server supports the TRACE method, which can lead to Cross-Site Tracing (XST) attacks.",
				Solution:    "Disable the TRACE method in web server configuration.",
				Reference:   "OWASP XST",
			}
		}
	}

	randomID := fmt.Sprintf("%d", time.Now().UnixNano())
	testFileName := fmt.Sprintf("/dorm_test_%s.txt", randomID)
	testContent := fmt.Sprintf("DORM_SECURITY_CHECK_%s", randomID)

	reqPut, _ := http.NewRequest("PUT", getURL(target, testFileName), strings.NewReader(testContent))
	reqPut.Header.Set("Content-Type", "text/plain")

	respPut, err := models.GetClient().Do(reqPut)
	if err != nil {
		return nil
	}
	respPut.Body.Close()

	if respPut.StatusCode == 201 || respPut.StatusCode == 200 {

		reqGet, _ := http.NewRequest("GET", getURL(target, testFileName), nil)
		respGet, err := models.GetClient().Do(reqGet)

		if err == nil {
			defer respGet.Body.Close()

			bodyBytes, _ := io.ReadAll(respGet.Body)
			uploadedContent := string(bodyBytes)

			if strings.Contains(uploadedContent, testContent) {

				reqDel, _ := http.NewRequest("DELETE", getURL(target, testFileName), nil)
				models.GetClient().Do(reqDel)

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
