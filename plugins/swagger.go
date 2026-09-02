package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 33. SWAGGER UI FINDER
type SwaggerPlugin struct{}

func (p *SwaggerPlugin) Name() string { return "Swagger UI Detection" }

func (p *SwaggerPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	paths := []string{"/swagger-ui.html", "/api/docs", "/v2/api-docs", "/docs"}
	for _, path := range paths {
		resp, err := models.GetClient().Get(getURL(target, path))
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		_ = resp.Body.Close()
		// A bare 200 isn't enough — SPA catch-all routers 200 every path.
		// Require an actual Swagger/OpenAPI signature in the body.
		bodyLow := strings.ToLower(string(body))
		if strings.Contains(bodyLow, "swagger") || strings.Contains(bodyLow, "openapi") || strings.Contains(bodyLow, `"paths"`) {
			return &models.Vulnerability{
				Target: target, Name: "API Documentation (Swagger)", Severity: "INFO", CVSS: 0.0,
				Description: "API endpoints are exposed: " + path,
				Solution:    "Restrict public access.",
				Reference:   "",
			}
		}
	}
	return nil
}
