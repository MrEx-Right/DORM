package plugins

import (
	"DORM/models"
	"net/http"
	"strings"
)

// 28. WEBDAV CHECK
type WebDAVPlugin struct{}

func (p *WebDAVPlugin) Name() string { return "WebDAV Methods" }

// Run confirms WebDAV with a real PROPFIND instead of trusting the OPTIONS
// "Allow" header, which many servers fill with methods they then refuse
// (IIS lists PUT/DELETE/TRACE by default). A PUT that actually writes is
// confirmed separately by the Dangerous HTTP Methods plugin.
func (p *WebDAVPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	req, err := http.NewRequest("PROPFIND", getURL(target, "/"), strings.NewReader(
		`<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/></D:prop></D:propfind>`))
	if err != nil {
		return nil
	}
	req.Header.Set("Depth", "0")
	req.Header.Set("Content-Type", "application/xml")
	resp, err := models.NoRedirectClient().Do(req)
	if err != nil {
		return nil
	}
	body := strings.ToLower(readBody(resp, 65536))

	if resp.StatusCode == 207 && strings.Contains(body, "multistatus") {
		return &models.Vulnerability{Target: target, Name: "Dangerous HTTP Methods", Severity: "MEDIUM", CVSS: 6.5, Description: "WebDAV is enabled: PROPFIND on / answered 207 Multi-Status with a DAV multistatus body.", Solution: "Disable WebDAV and unnecessary HTTP methods.", Reference: ""}
	}
	return nil
}
