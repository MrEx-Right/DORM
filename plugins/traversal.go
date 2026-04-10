package plugins

import (
	"DORM/models"
	"strings"
)

// 48. DIRECTORY TRAVERSAL (DotDotPwn)
type TraversalPlugin struct{}

func (p *TraversalPlugin) Name() string { return "Directory Traversal" }

func (p *TraversalPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	payloads := []string{"/../../../../etc/passwd", "/..%2f..%2f..%2f..%2fetc%2fpasswd", "/windows/win.ini"}

	for _, pay := range payloads {
		resp, err := models.GetClient().Get(getURL(target, pay))
		if err == nil {
			defer resp.Body.Close()
			buf := make([]byte, 2048)
			resp.Body.Read(buf)
			content := string(buf)
			if strings.Contains(content, "root:x:0:0") || strings.Contains(content, "[fonts]") {
				return &models.Vulnerability{
					Target: target, Name: "Directory Traversal", Severity: "CRITICAL", CVSS: 9.3,
					Description: "System files are readable.",
					Solution:    "Sanitize file path inputs.",
					Reference:   "OWASP Path Traversal",
				}
			}
		}
	}
	return nil
}
