package analyzer

import (
	"DORM/models"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OnVulnFound is a callback to report vulnerabilities to the main engine
var OnVulnFound func(*models.Vulnerability)

// ProxyHandler is the core of the native analyzer
type ProxyHandler struct {
	transport *http.Transport
}

func NewProxyHandler() *ProxyHandler {
	return &ProxyHandler{
		transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// For HTTPS tunneling via CONNECT, a different handler is needed.
	// Since DORM uses `http.ProxyURL` in its `Transport`, standard forward proxy requests are sent.
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT method not supported by basic analyzer proxy", http.StatusMethodNotAllowed)
		return
	}

	// Direct request to proxy server (e.g. visiting 127.0.0.1:8081 in browser)
	if r.URL.Host == "" && r.URL.Scheme == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>DORM Dynamic Analyzer Proxy</title>
	<style>
		body {
			font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
			background: radial-gradient(circle at top, #1E2640 0%, #0B0F19 100%);
			color: #F8FAFC;
			margin: 0;
			height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			overflow: hidden;
		}
		.glass-card {
			background: rgba(30, 41, 59, 0.45);
			backdrop-filter: blur(16px);
			-webkit-backdrop-filter: blur(16px);
			border: 1px solid rgba(255, 255, 255, 0.08);
			border-radius: 24px;
			padding: 48px;
			max-width: 600px;
			width: 90%;
			box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
			text-align: center;
			transform: translateY(0);
			transition: all 0.3s ease;
		}
		.glass-card:hover {
			border-color: rgba(99, 102, 241, 0.4);
			box-shadow: 0 20px 50px rgba(99, 102, 241, 0.15);
		}
		.logo-container {
			font-size: 3.5rem;
			font-weight: 800;
			letter-spacing: 2px;
			background: linear-gradient(135deg, #6366F1 0%, #38BDF8 100%);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
			margin-bottom: 24px;
		}
		h2 {
			font-size: 1.5rem;
			margin-bottom: 16px;
			color: #E2E8F0;
		}
		p {
			color: #94A3B8;
			line-height: 1.6;
			font-size: 1.05rem;
			margin-bottom: 32px;
		}
		.code-block {
			background: rgba(15, 23, 42, 0.6);
			border: 1px solid rgba(255, 255, 255, 0.05);
			border-radius: 12px;
			padding: 16px;
			font-family: 'Consolas', 'Courier New', Courier, monospace;
			font-size: 1.1rem;
			color: #38BDF8;
			display: flex;
			align-items: center;
			justify-content: center;
			gap: 12px;
			margin-bottom: 24px;
		}
		.pulse-dot {
			width: 10px;
			height: 10px;
			background-color: #10B981;
			border-radius: 50%;
			display: inline-block;
			box-shadow: 0 0 10px #10B981;
			animation: pulse 1.8s infinite;
		}
		@keyframes pulse {
			0% { transform: scale(0.9); opacity: 0.6; }
			50% { transform: scale(1.1); opacity: 1; box-shadow: 0 0 16px #10B981; }
			100% { transform: scale(0.9); opacity: 0.6; }
		}
		.footer {
			margin-top: 32px;
			font-size: 0.85rem;
			color: #64748B;
		}
	</style>
</head>
<body>
	<div class="glass-card">
		<div class="logo-container">DORM</div>
		<h2>Dynamic Analyzer Proxy</h2>
		<p>This is DORM's integrated DAST (Dynamic Application Security Testing) proxy layer. Instead of accessing it directly via a web browser, configure your browser or scanner tool proxy settings to capture and analyze your HTTP traffic.</p>
		
		<div class="code-block">
			<span class="pulse-dot"></span>
			HTTP Proxy: 127.0.0.1:8081
		</div>
		
		<div class="footer">
			Native Analyzer Active
		</div>
	</div>
</body>
</html>`))
		return
	}

	// 1. Analyze the Request
	AnalyzeRequest(r)

	// Clone the request for forwarding
	outReq := r.Clone(r.Context())
	outReq.RequestURI = "" // RequestURI must be empty for client requests

	// Forward the request to the actual destination
	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Proxy Error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 2. Intercept Response Body (Max 5MB to avoid memory exhaustion)
	var bodyBytes []byte
	const maxBodySize = 5 * 1024 * 1024
	bodyBytes, _ = io.ReadAll(io.LimitReader(resp.Body, maxBodySize))

	// Restore the body so it can be copied to the client
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 3. Analyze the Response (Passive Vulnerability Detection)
	AnalyzeResponse(r, resp, bodyBytes)

	// Copy original headers back to the client
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Write the intercepted body, then stream any remaining parts
	w.Write(bodyBytes)
	if resp.Body != nil {
		io.Copy(w, resp.Body)
	}
}

// StartAnalyzer starts the proxy server on the given port
func StartAnalyzer(port string) error {
	handler := NewProxyHandler()
	server := &http.Server{
		Addr:    ":" + port,
		Handler: handler,
	}
	fmt.Println("[+] Native Analyzer Proxy started on port", port)
	return server.ListenAndServe()
}
