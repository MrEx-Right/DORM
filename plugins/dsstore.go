package plugins

import (
	"DORM/models"
	"io"
	"strings"
)

// 18. DS_STORE
type DSStorePlugin struct{}

func (p *DSStorePlugin) Name() string { return "DS_Store Disclosure" }

func (p *DSStorePlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	resp, err := models.GetClient().Get(getURL(target, "/.DS_Store"))
	if err != nil {
		return nil
	}
	if resp.StatusCode != 200 {
		_ = resp.Body.Close()
		return nil
	}
	header := make([]byte, 8)
	n, _ := io.ReadFull(resp.Body, header)
	_ = resp.Body.Close()
	// Real .DS_Store files start with the "Bud1" magic signature at offset
	// 4 — ContentLength > 0 alone (the old check) is true for literally any
	// non-empty 200 response, e.g. a SPA catch-all's index.html.
	if n >= 8 && strings.HasPrefix(string(header[4:8]), "Bud1") {
		return &models.Vulnerability{Target: target, Name: ".DS_Store File", Severity: "INFO", CVSS: 0.0, Description: "Mac file index found.", Solution: "Delete it.", Reference: ""}
	}
	return nil
}
