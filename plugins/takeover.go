package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 64. SUBDOMAIN TAKEOVER (CNAME)
type TakeoverPlugin struct{}

func (p *TakeoverPlugin) Name() string { return "Subdomain Takeover Risk" }

func (p *TakeoverPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	resp, err := models.GetClient().Get(getURL(target, "/"))
	if err == nil {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		body := string(bodyBytes)

		signatures := []string{
			"There is no app configured at that hostname",
			"NoSuchBucket",
			"The specified bucket does not exist",
			"Fastly error: unknown domain",
		}

		for _, sig := range signatures {
			if strings.Contains(body, sig) {
				return &models.Vulnerability{
					Target: target, Name: "Subdomain Takeover", Severity: "HIGH", CVSS: 8.0,
					Description: "Domain points to an unclaimed cloud resource.",
					Solution:    "Delete DNS record or claim resource.",
					Reference:   "",
				}
			}
		}
	}
	return nil
}
