package plugins

import "DORM/models"

// 70. NGINX ALIAS TRAVERSAL (Off-by-slash)
type NginxTraversalPlugin struct{}

func (p *NginxTraversalPlugin) Name() string { return "Nginx Alias Traversal" }

func (p *NginxTraversalPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	resp, err := models.GetClient().Get(getURL(target, "/static../"))
	if err == nil {
		defer resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 403 {

			return nil
		}
	}
	return nil
}
