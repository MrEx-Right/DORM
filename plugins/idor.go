package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"math"
	"strings"
)

// 50. IDOR / BROKEN ACCESS - V2.1 (SMART)
type IDORPlugin struct{}

func (p *IDORPlugin) Name() string { return "IDOR (Smart Pattern Check)" }

func (p *IDORPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	patterns := []string{
		"/profile?id={ID}",
		"/users/{ID}",
		"/api/v1/user/{ID}",
		"/my-account?uid={ID}",
		"/order/view/{ID}",
		"/invoice?id={ID}",
		"/tickets/{ID}",
		"/messages/{ID}",
	}

	for _, pattern := range patterns {

		endpointBase := strings.Replace(pattern, "{ID}", "1", 1)
		respBase, err := client.Get(baseURL + endpointBase)
		if err != nil || respBase.StatusCode != 200 {
			continue
		}

		bodyBase, _ := io.ReadAll(respBase.Body)
		respBase.Body.Close()
		lenBase := len(bodyBase)

		endpointTarget := strings.Replace(pattern, "{ID}", "2", 1)
		respTarget, err := client.Get(baseURL + endpointTarget)

		if err == nil {
			defer respTarget.Body.Close()
			bodyTarget, _ := io.ReadAll(respTarget.Body)
			lenTarget := len(bodyTarget)

			endpointNoise := strings.Replace(pattern, "{ID}", "999999", 1)
			respNoise, _ := client.Get(baseURL + endpointNoise)
			lenNoise := 0
			if respNoise != nil {
				b, _ := io.ReadAll(respNoise.Body)
				lenNoise = len(b)
				respNoise.Body.Close()
			}

			isDifferentFromNoise := math.Abs(float64(lenTarget-lenNoise)) > float64(lenNoise)*0.1

			if respTarget.StatusCode == 200 && isDifferentFromNoise {
				return &models.Vulnerability{
					Target:      target,
					Name:        "Potential IDOR Found",
					Severity:    "HIGH",
					CVSS:        7.5,
					Description: fmt.Sprintf("Access to different user objects detected without auth error.\nEndpoint: %s\nID=1 Size: %d\nID=2 Size: %d\nID=999999 (Error) Size: %d", pattern, lenBase, lenTarget, lenNoise),
					Solution:    "Implement strict access controls checks for object IDs.",
					Reference:   "OWASP Broken Access Control",
				}
			}
		}
	}
	return nil
}
