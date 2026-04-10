package plugins

import (
	"DORM/models"
	"net/http"
)

// 81. WEBSOCKET HIJACKING (CSWSH)
type WebSocketPlugin struct{}

func (p *WebSocketPlugin) Name() string { return "WebSocket Hijacking" }

func (p *WebSocketPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	req, _ := http.NewRequest("GET", getURL(target, "/chat"), nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Origin", "http://evil.com")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	resp, err := models.GetClient().Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 101 {
			return &models.Vulnerability{
				Target: target, Name: "Cross-Site WebSocket Hijacking", Severity: "HIGH", CVSS: 8.1,
				Description: "WebSocket allows connections from arbitrary origins.",
				Solution:    "Validate the 'Origin' header during handshake.", Reference: "CSWSH",
			}
		}
	}
	return nil
}
