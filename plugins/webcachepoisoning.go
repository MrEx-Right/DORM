package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type WebCachePoisoningPlugin struct{}

func (p *WebCachePoisoningPlugin) Name() string { return "Web Cache Poisoning (Smart Verification)" }

func (p *WebCachePoisoningPlugin) Run(target models.ScanTarget) *models.Vulnerability {

	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	endpoints := []string{"/", "/login", "/about", "/faq", "/assets/"}

	headersToTest := []string{
		"X-Forwarded-Host",
		"X-Host",
		"X-Original-URL",
		"X-Rewrite-URL",
		"Forwarded",
	}

	canary := "dorm-cache-test-1337.local"

	for _, ep := range endpoints {
		targetURL := baseURL + ep

		for _, header := range headersToTest {

			cacheBuster := fmt.Sprintf("?cb=%d", time.Now().UnixNano())

			req1, _ := http.NewRequest("GET", targetURL+cacheBuster, nil)

			switch header {
			case "Forwarded":
				req1.Header.Set(header, fmt.Sprintf("host=%s", canary))
			case "X-Original-URL", "X-Rewrite-URL":
				req1.Header.Set(header, "/dorm-poison-path")
			default:
				req1.Header.Set(header, canary)
			}

			resp1, err := client.Do(req1)
			if err != nil {
				continue
			}

			bodyBytes1, _ := io.ReadAll(resp1.Body)
			bodyStr1 := string(bodyBytes1)
			resp1.Body.Close()

			if !strings.Contains(bodyStr1, canary) && !strings.Contains(bodyStr1, "dorm-poison-path") {
				continue
			}

			req2, _ := http.NewRequest("GET", targetURL+cacheBuster, nil)
			resp2, err := client.Do(req2)
			if err != nil {
				continue
			}

			bodyBytes2, _ := io.ReadAll(resp2.Body)
			bodyStr2 := string(bodyBytes2)
			resp2.Body.Close()

			cacheHeaders := []string{"X-Cache", "CF-Cache-Status", "X-Varnish", "Age"}
			isCached := false
			cacheEvidence := ""
			for _, ch := range cacheHeaders {
				if val := resp2.Header.Get(ch); val != "" {
					isCached = true
					cacheEvidence = fmt.Sprintf("%s: %s", ch, val)
					break
				}
			}

			if strings.Contains(bodyStr2, canary) || strings.Contains(bodyStr2, "dorm-poison-path") {

				severity := "HIGH"
				cvss := 8.5
				desc := fmt.Sprintf("Web Cache Poisoning detected!\nEndpoint: %s\nUnkeyed Header Injected: %s\n", ep, header)
				desc += "The backend server reflected our payload, and a subsequent NORMAL request served the poisoned cached response."

				if isCached {

					desc += fmt.Sprintf("\n\nConfirmation: Explicit CDN Cache header found -> %s", cacheEvidence)
					severity = "CRITICAL"
					cvss = 9.1
				} else {
					desc += "\n\nNote: No explicit CDN cache headers found, but behavioral caching was successfully verified."
				}

				return &models.Vulnerability{
					Target:      target,
					Name:        "Web Cache Poisoning (Unkeyed Header)",
					Severity:    severity,
					CVSS:        cvss,
					Description: desc,
					Solution:    "Disable unkeyed headers if not strictly necessary. If they are required for routing, ensure they are explicitly added to the 'Vary' header (Cache-Key) to prevent caching malicious inputs.",
					Reference:   "PortSwigger: Web Cache Poisoning / CWE-444",
				}
			}
		}
	}

	return nil
}
