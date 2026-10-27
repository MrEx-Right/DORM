package analyzer

// Fuzz target for the passive analyzer: every proxied response body goes
// through it, so a hostile page must not panic it (the Plesk key check
// slices the body around each match), and it must stay silent on bodies
// that hold no key material. Nightly CI runs it for a short budget.

import (
	"DORM/models"
	"net/http"
	"strings"
	"testing"
)

func FuzzAnalyzeResponse(f *testing.F) {
	f.Add("<html>nothing here</html>")
	f.Add("key=AKIAABCDEFGHIJKLMNOP")
	f.Add(`Jsw.UAT.init({"versionInfo":"18.0.72","firehose":{"accessKeyId":"AKIAABCDEFGHIJKLMNOP"}});`)
	f.Add(`"accessKeyId":"AKIAABCDEFGHIJKLMNOP" Jsw.UAT.init({"firehose"});`)
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nMIIB...")

	req, _ := http.NewRequest("GET", "http://target.test:8080/x", nil)
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	f.Fuzz(func(t *testing.T, body string) {
		var found []*models.Vulnerability
		old := OnVulnFound
		OnVulnFound = func(v *models.Vulnerability) { found = append(found, v) }
		defer func() { OnVulnFound = old }()

		AnalyzeResponse(req, resp, []byte(body))

		if len(found) > 0 && !strings.Contains(body, "AKIA") && !strings.Contains(body, "PRIVATE KEY-----") {
			t.Errorf("finding %q on a body with no key material", found[0].Name)
		}
		for _, v := range found {
			if v.Target.IP != "target.test" || v.Target.Port != 8080 {
				t.Errorf("finding attributed to %+v, want target.test:8080", v.Target)
			}
		}
	})
}
