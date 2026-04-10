package plugins

import (
	"DORM/models"
	"fmt"
	"strings"
)

// 16. BACKUP FILE DISCLOSURE (Verified via Magic Bytes)
type BackupFilePlugin struct{}

func (p *BackupFilePlugin) Name() string { return "Sensitive Backup File Discovery (Verified)" }

func (p *BackupFilePlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()

	commonBackups := []string{
		"/index.php.bak",
		"/config.php.bak",
		"/wp-config.php.bak",
		"/web.config.old",
		"/backup.zip",
		"/backup.sql",
		"/www.zip",
		"/site.tar.gz",
		"/.env.save",
	}

	for _, path := range commonBackups {
		fullURL := getURL(target, path)
		resp, err := client.Get(fullURL)

		if err == nil {
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				continue
			}

			header := make([]byte, 512)
			n, _ := resp.Body.Read(header)
			content := string(header[:n])

			isVerified := false
			fileType := "Unknown"

			if strings.HasSuffix(path, ".zip") {

				if strings.HasPrefix(content, "PK") {
					isVerified = true
					fileType = "ZIP Archive"
				}
			} else if strings.HasSuffix(path, ".tar.gz") || strings.HasSuffix(path, ".tgz") {

				if len(content) > 2 && header[0] == 0x1f && header[1] == 0x8b {
					isVerified = true
					fileType = "GZIP Archive"
				}
			} else if strings.HasSuffix(path, ".sql") {

				if strings.Contains(content, "INSERT INTO") || strings.Contains(content, "CREATE TABLE") || strings.Contains(content, "-- MySQL dump") {
					isVerified = true
					fileType = "SQL Database Dump"
				}
			} else if strings.HasSuffix(path, ".php.bak") || strings.HasSuffix(path, ".old") || strings.HasSuffix(path, ".save") {

				if strings.Contains(content, "<?php") && !strings.Contains(strings.ToLower(content), "<html") {
					isVerified = true
					fileType = "Source Code Backup"
				}
			}

			if isVerified {
				return &models.Vulnerability{
					Target:      target,
					Name:        fmt.Sprintf("Sensitive Backup File Found (%s)", fileType),
					Severity:    "HIGH",
					CVSS:        7.5,
					Description: fmt.Sprintf("A publicly accessible backup file was discovered and verified.\nFile: %s\nType: %s", path, fileType),
					Solution:    "Remove backup files from the public web directory or restrict access via web server configuration.",
					Reference:   "OWASP Sensitive Data Exposure",
				}
			}
		}
	}
	return nil
}
