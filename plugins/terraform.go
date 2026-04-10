package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 80. TERRAFORM STATE EXPOSURE
type TerraformPlugin struct{}

func (p *TerraformPlugin) Name() string { return "Terraform State Exposure" }

func (p *TerraformPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	paths := []string{"/.terraform/terraform.tfstate", "/terraform.tfstate", "/.terraform.lock.hcl"}
	for _, path := range paths {
		resp, err := models.GetClient().Get(getURL(target, path))
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == 200 && (strings.Contains(string(body), "\"version\":") && strings.Contains(string(body), "\"resources\":")) {
				return &models.Vulnerability{
					Target: target, Name: "Terraform State Leaked", Severity: "HIGH", CVSS: 7.5,
					Description: "Terraform state file exposed, revealing infrastructure secrets.",
					Solution:    "Block access to .tfstate files.", Reference: "IaC Security",
				}
			}
		}
	}
	return nil
}
