package plugins

import "DORM/models"

// 22. ADMIN PANEL (V2 - BROAD SCOPE)
type AdminPanelPlugin struct{}

func (p *AdminPanelPlugin) Name() string { return "Admin Panel Finder (Pro)" }

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

	for _, p := range panels {
		resp, err := models.GetClient().Get(getURL(target, p))
		if err == nil {
			defer resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 401 {
				return &models.Vulnerability{
					Target:      target,
					Name:        "Admin Panel Detection",
					Severity:    "MEDIUM",
					CVSS:        5.0,
					Description: "Potential panel found: " + p,
					Solution:    "Restrict public access or use IP whitelisting.",
					Reference:   "",
				}
			}
		}
	}
	return nil
}
