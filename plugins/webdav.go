package plugins

import (
	"DORM/models"
	"net/http"
	"strings"
)

// 28. WEBDAV CHECK
type WebDAVPlugin struct{}

func (p *WebDAVPlugin) Name() string { return "WebDAV Methods" }

func (p *WebDAVPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	req, _ := http.NewRequest("OPTIONS", getURL(target, ""), nil)
	resp, err := models.GetClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	allow := resp.Header.Get("Allow")
	if strings.Contains(allow, "PROPFIND") || strings.Contains(allow, "PUT") || strings.Contains(allow, "DELETE") {
		return &models.Vulnerability{Target: target, Name: "Dangerous HTTP Methods", Severity: "MEDIUM", CVSS: 6.5, Description: "WebDAV or PUT/DELETE methods enabled.", Solution: "Disable unnecessary HTTP methods.", Reference: ""}
	}
	return nil
}
