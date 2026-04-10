package plugins

import (
	"DORM/models"
	"strings"
)

// 32. GRAPHQL INTROSPECTION
type GraphQLPlugin struct{}

func (p *GraphQLPlugin) Name() string { return "GraphQL Schema Disclosure" }

func (p *GraphQLPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	payload := `{"query": "{__schema{types{name}}}"}`
	resp, err := models.GetClient().Post(getURL(target, "/graphql"), "application/json", strings.NewReader(payload))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		buf := make([]byte, 1024)
		resp.Body.Read(buf)
		if strings.Contains(string(buf), "__schema") {
			return &models.Vulnerability{
				Target: target, Name: "GraphQL Introspection Enabled", Severity: "MEDIUM", CVSS: 5.0,
				Description: "API schema is publicly exposed.",
				Solution:    "Disable introspection in production.",
				Reference:   "GraphQL Security",
			}
		}
	}
	return nil
}
