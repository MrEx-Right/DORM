package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 22. ADMIN PANEL (V2 - BROAD SCOPE)
type AdminPanelPlugin struct{}

func (p *AdminPanelPlugin) Name() string { return "Admin Panel Finder (Pro)" }

// adminPanelSignatures are login/panel-specific markers checked in the body
// of a 200 response. A bare 200 is not enough on its own — SPA frameworks
// (React/Vue/Next.js) very commonly serve their index.html with a 200 for
// ANY unmatched path, which would otherwise flag every single scan target
// running one as having 15 different "admin panels".
var adminPanelSignatures = []string{
	"login", "log in", "sign in", "signin", "password", "username",
	"admin panel", "control panel", "dashboard", "administration",
}

func (p *AdminPanelPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	panels := []string{
		"/admin/", "/administrator/", "/cp/", "/controlpanel/",
		"/wp-admin/", "/vhost/", "/magento/admin/", "/backend/",
		"/directadmin/", "/plesk/", "/cpanel/", "/webmin/",
		"/monitor/", "/manager/html", "/server-manager/",
	}

	for _, path := range panels {
		vuln := checkAdminPanelPath(target, path)
		if vuln != nil {
			return vuln
		}
	}
	return nil
}

func checkAdminPanelPath(target models.ScanTarget, path string) *models.Vulnerability {
	resp, err := models.GetClient().Get(getURL(target, path))
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	// 401 means something IS gating this exact path — that's signal enough
	// on its own, no content check needed (a generic SPA fallback wouldn't
	// selectively 401 an admin-shaped path while 200'ing everything else).
	if resp.StatusCode == 401 {
		return &models.Vulnerability{
			Target:      target,
			Name:        "Admin Panel Detection",
			Severity:    "MEDIUM",
			CVSS:        5.0,
			Description: "Potential panel found (authentication required): " + path,
			Solution:    "Restrict public access or use IP whitelisting.",
			Reference:   "",
		}
	}

	if resp.StatusCode != 200 {
		return nil
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyLow := strings.ToLower(string(bodyBytes))
	for _, sig := range adminPanelSignatures {
		if strings.Contains(bodyLow, sig) {
			return &models.Vulnerability{
				Target:      target,
				Name:        "Admin Panel Detection",
				Severity:    "MEDIUM",
				CVSS:        5.0,
				Description: "Potential panel found: " + path,
				Solution:    "Restrict public access or use IP whitelisting.",
				Reference:   "",
			}
		}
	}
	return nil
}
