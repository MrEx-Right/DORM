package plugins

import "DORM/models"

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
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			return &models.Vulnerability{
				Target: target, Name: "API Documentation (Swagger)", Severity: "LOW", CVSS: 4.0,
				Description: "API endpoints are exposed: " + path,
				Solution:    "Restrict public access.",
				Reference:   "",
			}
		}
	}
	return nil
}
