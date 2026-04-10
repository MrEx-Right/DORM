package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 30. S3 BUCKET LEAK
type S3BucketPlugin struct{}

func (p *S3BucketPlugin) Name() string { return "S3 Bucket Detection" }

func (p *S3BucketPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, ""))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	if strings.Contains(content, ".s3.amazonaws.com") {
		return &models.Vulnerability{Target: target, Name: "S3 Bucket Link", Severity: "LOW", CVSS: 4.0, Description: "Amazon S3 link detected. Check permissions.", Solution: "Disable public access to bucket.", Reference: ""}
	}
	return nil
}
