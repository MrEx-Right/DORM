package plugins

import "DORM/models"

// 26. COOKIE SECURITY FLAGS
type CookieSecPlugin struct{}

func (p *CookieSecPlugin) Name() string { return "Cookie Security" }

func (p *CookieSecPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	for _, cookie := range resp.Cookies() {
		if !cookie.HttpOnly || !cookie.Secure {
			return &models.Vulnerability{Target: target, Name: "Insecure Cookie", Severity: "LOW", CVSS: 3.0, Description: "HttpOnly or Secure flag missing.", Solution: "Harden cookie settings.", Reference: ""}
		}
	}
	return nil
}
