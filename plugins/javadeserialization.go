package plugins

import (
	"DORM/models"
	"strings"
)

// 46. JAVA DESERIALIZATION (Header Check)
type JavaDeserializationPlugin struct{}

func (p *JavaDeserializationPlugin) Name() string { return "Java Deserialization Risk" }

func (p *JavaDeserializationPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	resp, err := models.GetClient().Get(getURL(target, "/"))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	for _, cookie := range resp.Cookies() {

		if strings.HasPrefix(cookie.Value, "rO0AB") {
			return &models.Vulnerability{
				Target: target, Name: "Java Serialized Object", Severity: "HIGH", CVSS: 8.1,
				Description: "Java object detected in Cookie. RCE risk.",
				Solution:    "Do not use insecure deserialization.",
				Reference:   "OWASP Deserialization",
			}
		}
	}
	return nil
}
