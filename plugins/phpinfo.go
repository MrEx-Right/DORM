package plugins

import (
	"DORM/models"
	"strings"
)

// 8. PHP INFO
type PHPInfoPlugin struct{}

func (p *PHPInfoPlugin) Name() string { return "PHP Info Check" }

func (p *PHPInfoPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	files := []string{"/phpinfo.php", "/info.php"}
	for _, f := range files {
		resp, err := models.GetClient().Get(getURL(target, f))
		if err == nil && resp.StatusCode == 200 {
			buf := make([]byte, 500)
			resp.Body.Read(buf)
			resp.Body.Close()
			if strings.Contains(string(buf), "PHP Version") {
				return &models.Vulnerability{Target: target, Name: "PHP Info File", Severity: "HIGH", CVSS: 7.5, Description: f + " is accessible.", Solution: "Delete it.", Reference: ""}
			}
		}
	}
	return nil
}
