package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"strings"
)

// 83. SHADOW API DISCOVERY
type ShadowAPIPlugin struct{}

func (p *ShadowAPIPlugin) Name() string { return "Shadow API Discovery" }

func (p *ShadowAPIPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	prefixes := []string{"/api/v2", "/api/mobile", "/api/internal", "/api/private", "/v1/admin"}
	for _, prefix := range prefixes {
		resp, err := models.GetClient().Get(getURL(target, prefix))
		if err != nil {
			continue
		}

		// 401 alone is a reasonable signal — a generic SPA/catch-all router
		// serving 200s for everything wouldn't selectively 401 one specific
		// API-shaped path. A 200, however, needs to actually look like an
		// API response (JSON), not just any page a catch-all router returns.
		if resp.StatusCode == 401 {
			_ = resp.Body.Close()
			return &models.Vulnerability{
				Target: target, Name: "Shadow API Endpoint Found", Severity: "INFO", CVSS: 0.0,
				Description: fmt.Sprintf("Potentially undocumented API endpoint found: %s", prefix),
				Solution:    "Audit and document all API routes.", Reference: "OWASP API Security",
			}
		}
		if resp.StatusCode == 200 {
			ct := resp.Header.Get("Content-Type")
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			body := strings.TrimSpace(string(bodyBytes))
			looksLikeJSON := strings.Contains(ct, "json") || strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[")
			if looksLikeJSON {
				return &models.Vulnerability{
					Target: target, Name: "Shadow API Endpoint Found", Severity: "INFO", CVSS: 0.0,
					Description: fmt.Sprintf("Potentially undocumented API endpoint found: %s", prefix),
					Solution:    "Audit and document all API routes.", Reference: "OWASP API Security",
				}
			}
			continue
		}
		_ = resp.Body.Close()
	}
	return nil
}
