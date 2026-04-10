package plugins

import (
	"DORM/models"
	"io"
	"net/http"
	"strings"
)

// 47. NODE.JS PROTOTYPE POLLUTION - v2
type PrototypePollutionPlugin struct{}

func (p *PrototypePollutionPlugin) Name() string { return "Node.js Prototype Pollution" }

func (p *PrototypePollutionPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "/")

	payload := `{"__proto__":{"dorm_check": "polluted"}, "constructor": {"prototype": {"dorm_check": "polluted"}}}`

	req, _ := http.NewRequest("POST", baseURL, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			bodyBytes, _ := io.ReadAll(resp.Body)

			if strings.Contains(string(bodyBytes), "dorm_check") {
				return &models.Vulnerability{
					Target:      target,
					Name:        "Prototype Pollution Suspected",
					Severity:    "MEDIUM",
					CVSS:        6.5,
					Description: "Server accepts and reflects special keys (__proto__, constructor) in JSON body.",
					Solution:    "Implement strict JSON schema validation and freeze Object.prototype.",
					Reference:   "CWE-1321",
				}
			}
		}
	}
	return nil
}
