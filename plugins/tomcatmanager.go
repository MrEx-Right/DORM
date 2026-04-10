package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// 38. TOMCAT MANAGER (Fingerprinting & Default Creds) - v2
type TomcatManagerPlugin struct{}

func (p *TomcatManagerPlugin) Name() string { return "Tomcat Manager Panel (Verified)" }

func (p *TomcatManagerPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	targetPath := "/manager/html"
	fullURL := getURL(target, targetPath)

	req, _ := http.NewRequest("GET", fullURL, nil)
	resp, err := client.Do(req)

	if err == nil {
		defer resp.Body.Close()

		authHeader := resp.Header.Get("WWW-Authenticate")
		isTomcat := strings.Contains(authHeader, "Tomcat Manager") || strings.Contains(authHeader, "Tomcat")

		bodyBytes, _ := io.ReadAll(resp.Body)
		bodyString := string(bodyBytes)
		isUnprotected := resp.StatusCode == 200 && strings.Contains(bodyString, "Tomcat Web Application Manager")

		if isUnprotected {

			return &models.Vulnerability{
				Target:      target,
				Name:        "Tomcat Manager (Unauthenticated)",
				Severity:    "CRITICAL",
				CVSS:        9.8,
				Description: "Tomcat Manager panel is accessible without authentication.",
				Solution:    "Enable authentication or restrict access by IP.",
				Reference:   "OWASP Misconfiguration",
			}
		}

		if resp.StatusCode == 401 && isTomcat {

			creds := []struct {
				User string
				Pass string
			}{
				{"tomcat", "s3cret"},
				{"admin", "admin"},
				{"manager", "manager"},
			}

			for _, cred := range creds {
				reqAuth, _ := http.NewRequest("GET", fullURL, nil)
				reqAuth.SetBasicAuth(cred.User, cred.Pass)

				respAuth, errAuth := client.Do(reqAuth)
				if errAuth == nil {
					respAuth.Body.Close()

					if respAuth.StatusCode == 200 {
						return &models.Vulnerability{
							Target:      target,
							Name:        "Tomcat Manager (Default Credentials)",
							Severity:    "CRITICAL",
							CVSS:        9.8,
							Description: fmt.Sprintf("Access gained using default credentials.\nUser: %s\nPass: %s", cred.User, cred.Pass),
							Solution:    "Change default passwords in tomcat-users.xml immediately.",
							Reference:   "CVE-1999-0508",
						}
					}
				}
			}

			return &models.Vulnerability{
				Target:      target,
				Name:        "Tomcat Manager Panel Exposed",
				Severity:    "HIGH",
				CVSS:        7.5,
				Description: "Tomcat Manager login panel is exposed to the internet.",
				Solution:    "Restrict access to the /manager endpoint via firewall/IP whitelisting.",
				Reference:   "OWASP Security Misconfiguration",
			}
		}
	}
	return nil
}
