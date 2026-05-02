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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
