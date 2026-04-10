package plugins

import (
	"DORM/models"
	"fmt"
)

// 21. CMS DETECTION - v1.5.0 DEEP FINGERPRINT INTEGRATED
type CMSTestPlugin struct{}

func (p *CMSTestPlugin) Name() string { return "CMS & Technology Analysis" }

func (p *CMSTestPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	profile := models.DeepScanTarget(getURL(target, ""))

	if profile.CMS != "" {
		return &models.Vulnerability{
			Target:      target,
			Name:        "CMS Detection: " + profile.CMS,
			Severity:    "INFO",
			CVSS:        0.0,
			Description: fmt.Sprintf("Target site is using %s CMS system.", profile.CMS),
			Solution:    "Hide version info and keep it updated.",
			Reference:   "Wappalyzer Methodology",
		}
	}
	return nil
}
