package plugins

import (
	"DORM/models"
	"strings"
)

// 59. ELASTICSEARCH INFO LEAK
type ElasticPlugin struct{}

func (p *ElasticPlugin) Name() string { return "Elasticsearch Disclosure" }

func (p *ElasticPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if target.Port != 9200 {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/_cat/indices?v"))
	if err == nil {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "health") && strings.Contains(string(buf), "index") {
			return &models.Vulnerability{
				Target: target, Name: "Elasticsearch Data Leak", Severity: "HIGH", CVSS: 7.5,
				Description: "Index list visible without auth.",
				Solution:    "Enable X-Pack Security.",
				Reference:   "",
			}
		}
	}
	return nil
}
