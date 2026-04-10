package plugins

import "DORM/models"

// 18. DS_STORE
type DSStorePlugin struct{}

func (p *DSStorePlugin) Name() string { return "DS_Store Disclosure" }

func (p *DSStorePlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/.DS_Store"))
	if err == nil && resp.StatusCode == 200 && resp.ContentLength > 0 {
		resp.Body.Close()
		return &models.Vulnerability{Target: target, Name: ".DS_Store File", Severity: "LOW", CVSS: 2.5, Description: "Mac file index found.", Solution: "Delete it.", Reference: ""}
	}
	return nil
}
