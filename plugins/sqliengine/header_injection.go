package sqliengine

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ============================================================
//  HEADER INJECTION SQLi
//  User-Agent · X-Forwarded-For · Referer · Cookie · Custom
// ============================================================

// RunHeaderInjection tests SQL injection via HTTP headers.
func RunHeaderInjection(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	headerPayloads := []string{
		"'",
		"' OR '1'='1'--",
		"1' AND SLEEP(0)--",
		`" OR "1"="1"--`,
		"' UNION SELECT NULL--",
	}

	headerNames := []string{
		"User-Agent",
		"X-Forwarded-For",
		"Referer",
		"X-Real-IP",
		"X-Custom-IP-Authorization",
		"X-Originating-IP",
		"X-Client-IP",
		"X-Forwarded-Host",
		"Cookie",
	}

	testEndpoints := []string{"/", "/index.php", "/login", "/search", "/api/v1/"}

	for _, ep := range testEndpoints {
		targetURL := baseURL + ep
		for _, hdr := range headerNames {
			for _, payload := range headerPayloads {
				req, err := http.NewRequest("GET", targetURL, nil)
				if err != nil {
					continue
				}

				if hdr == "Cookie" {
					req.Header.Set("Cookie", fmt.Sprintf("session=%s; id=%s", payload, payload))
				} else {
					req.Header.Set(hdr, payload)
				}
				req.Header.Set("User-Agent", "DORM-Scanner/Enterprise")

				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
				resp.Body.Close()
				bodyStr := string(bodyBytes)

				for _, errMsg := range DBErrors {
					if strings.Contains(bodyStr, errMsg) {
						db := FingerprintDB(bodyStr)
						return &models.Vulnerability{
							Target:   target,
							Name:     "SQL Injection (Header Injection)",
							Severity: "HIGH",
							CVSS:     8.5,
							Description: fmt.Sprintf(
								"SQL injection successfully triggered via HTTP header.\n"+
									"Endpoint: %s\nHeader: %s\nPayload: %s\nError: %s  DB: %s",
								targetURL, hdr, payload, errMsg, db,
							),
							Solution:  "Treat all HTTP header values as untrusted user inputs and use parameterized queries.",
							Reference: "CWE-89: SQL Injection via HTTP Headers",
						}
					}
				}
			}
		}
	}

	return nil
}
