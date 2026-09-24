package plugins

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"DORM/models"
)

// ==================================================
// MCP SERVER EXPOSURE SCANNER
// Detects unauthenticated Model Context Protocol (MCP) servers. MCP exposes
// JSON-RPC "tools" that an LLM agent can invoke; an unauthenticated MCP
// server lets any network-adjacent actor enumerate (and potentially call)
// those tools directly — an "excessive agency" risk (OWASP LLM06).
// ==================================================

type MCPExposurePlugin struct{}

func (p *MCPExposurePlugin) Name() string { return "MCP Server Exposure Scanner" }

func (p *MCPExposurePlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()

	if v := checkMCPStreamableHTTP(client, target); v != nil {
		return v
	}
	return checkMCPSSETransport(target)
}

// mcpStreamableEndpoints are conventional locations for MCP's "Streamable
// HTTP" transport (a single endpoint accepting POSTed JSON-RPC).
var mcpStreamableEndpoints = []string{"/mcp", "/api/mcp", "/mcp/v1"}

const (
	mcpInitializeRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dorm-scanner","version":"1.0"}}}`
	mcpToolsListRequest  = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
)

// mcpDangerousToolKeywords escalate severity when a discovered tool's name
// or description suggests a highly sensitive capability.
var mcpDangerousToolKeywords = []string{"exec", "shell", "file", "write", "delete", "sql", "admin", "command", "eval"}

type mcpJSONRPCResponse struct {
	Result map[string]interface{} `json:"result"`
	Error  map[string]interface{} `json:"error"`
}

// postMCPJSONRPC POSTs a JSON-RPC payload and parses the result object,
// tolerating both a plain JSON response and an SSE-framed single "data: "
// line (the streamable-HTTP transport may reply either way).
func postMCPJSONRPC(client *http.Client, targetURL, payload, sessionID string) (result map[string]interface{}, sessionHeader string, err error) {
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(payload))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 262144))
	text := strings.TrimSpace(string(body))

	// SSE-framed single response: strip a leading "data: " line.
	if strings.HasPrefix(text, "event:") || strings.HasPrefix(text, "data:") {
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "data:") {
				text = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				break
			}
		}
	}

	var rpc mcpJSONRPCResponse
	if jsonErr := json.Unmarshal([]byte(text), &rpc); jsonErr != nil {
		return nil, "", jsonErr
	}

	return rpc.Result, resp.Header.Get("Mcp-Session-Id"), nil
}

// isValidMCPInitializeResult requires BOTH protocolVersion and
// (serverInfo OR capabilities) to be present, so an unrelated JSON-RPC-
// shaped API doesn't false-positive as an MCP server.
func isValidMCPInitializeResult(result map[string]interface{}) bool {
	if result == nil {
		return false
	}
	_, hasProtocolVersion := result["protocolVersion"]
	_, hasServerInfo := result["serverInfo"]
	_, hasCapabilities := result["capabilities"]
	return hasProtocolVersion && (hasServerInfo || hasCapabilities)
}

// extractMCPTools reads a tools/list result into a slice of tool objects.
func extractMCPTools(result map[string]interface{}) []map[string]interface{} {
	if result == nil {
		return nil
	}
	raw, ok := result["tools"].([]interface{})
	if !ok {
		return nil
	}
	var tools []map[string]interface{}
	for _, t := range raw {
		if m, ok := t.(map[string]interface{}); ok {
			tools = append(tools, m)
		}
	}
	return tools
}

// buildMCPFinding scores severity from the enumerated tools (enumeration
// only — no tool is ever actually invoked) and produces the finding.
func buildMCPFinding(target models.ScanTarget, endpoint string, tools []map[string]interface{}) *models.Vulnerability {
	if len(tools) == 0 {
		return &models.Vulnerability{
			Target:      target,
			Name:        "Unauthenticated MCP Server Discovered",
			Severity:    "INFO",
			CVSS:        0.0,
			Description: fmt.Sprintf("An unauthenticated Model Context Protocol (MCP) server responded to a JSON-RPC 'initialize' handshake at '%s'. Tool enumeration ('tools/list') did not return any callable tools, or the request failed.", endpoint),
			Solution:    "Require authentication (e.g. a bearer token or mTLS) in front of the MCP endpoint, and bind it to a private network if it is not meant to be publicly reachable.",
			Reference:   "MCP Specification 2024-11-05 | OWASP Top 10 for LLM Applications 2025 - LLM06: Excessive Agency",
		}
	}

	var names []string
	dangerous := false
	for i, t := range tools {
		if i >= 10 {
			break
		}
		name, _ := t["name"].(string)
		desc, _ := t["description"].(string)
		names = append(names, name)
		combined := strings.ToLower(name + " " + desc)
		for _, kw := range mcpDangerousToolKeywords {
			if strings.Contains(combined, kw) {
				dangerous = true
				break
			}
		}
	}

	severity, cvss := "HIGH", 7.5
	if dangerous {
		severity, cvss = "CRITICAL", 9.1
	}

	return &models.Vulnerability{
		Target:   target,
		Name:     "Unauthenticated MCP Server Exposes Tools",
		Severity: severity,
		CVSS:     cvss,
		Description: fmt.Sprintf(
			"An unauthenticated Model Context Protocol (MCP) server at '%s' returned %d callable tool(s) via "+
				"'tools/list' with no authentication required.\n\nTools: %s\n\n"+
				"This allows any network-adjacent actor to enumerate (and, separately, invoke) arbitrary tool "+
				"functions exposed to the LLM agent — an excessive agency risk that can lead to data exfiltration, "+
				"SSRF, or remote code execution depending on what the tools do. DORM only enumerated the tools; "+
				"it did not invoke any of them.",
			endpoint, len(tools), strings.Join(names, ", "),
		),
		Solution:  "Require authentication (bearer token, mTLS, or an API gateway) in front of the MCP endpoint before any tool is reachable. Apply least-privilege scoping to each tool and never expose destructive/administrative tools without strict access control.",
		Reference: "OWASP Top 10 for LLM Applications 2025 - LLM06: Excessive Agency | MCP Specification 2024-11-05",
	}
}

// checkMCPStreamableHTTP probes the modern single-endpoint "Streamable
// HTTP" MCP transport.
func checkMCPStreamableHTTP(client *http.Client, target models.ScanTarget) *models.Vulnerability {
	for _, endpoint := range mcpStreamableEndpoints {
		fullURL := getURL(target, endpoint)

		result, sessionID, err := postMCPJSONRPC(client, fullURL, mcpInitializeRequest, "")
		if err != nil || !isValidMCPInitializeResult(result) {
			continue
		}

		toolsResult, _, err := postMCPJSONRPC(client, fullURL, mcpToolsListRequest, sessionID)
		var tools []map[string]interface{}
		if err == nil {
			tools = extractMCPTools(toolsResult)
		}

		return buildMCPFinding(target, endpoint, tools)
	}
	return nil
}

// mcpSSEClient is a short, local timeout client — separate from the shared
// target client — because an SSE stream can stay open indefinitely and must
// never block the overall scan.
var mcpSSEClient = &http.Client{Timeout: 3 * time.Second}

// checkMCPSSETransport probes the legacy HTTP+SSE MCP transport: a GET to
// /sse should emit an "event: endpoint" / "data: <url>" handshake pointing
// at a session-scoped POST endpoint.
func checkMCPSSETransport(target models.ScanTarget) *models.Vulnerability {
	sseURL := getURL(target, "/sse")
	req, err := http.NewRequest("GET", sseURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := mcpSSEClient.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 8192))
	var eventEndpoint string
	sawEndpointEvent := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "event: endpoint" {
			sawEndpointEvent = true
			continue
		}
		if sawEndpointEvent && strings.HasPrefix(line, "data:") {
			eventEndpoint = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			break
		}
	}

	if !sawEndpointEvent {
		return nil
	}

	if eventEndpoint == "" {
		return &models.Vulnerability{
			Target:      target,
			Name:        "Unauthenticated MCP Server Discovered",
			Severity:    "INFO",
			CVSS:        0.0,
			Description: "An unauthenticated Model Context Protocol (MCP) SSE transport handshake ('event: endpoint') was observed at '/sse', but no session endpoint could be parsed to confirm further.",
			Solution:    "Require authentication in front of the MCP endpoint and bind it to a private network if it is not meant to be publicly reachable.",
			Reference:   "MCP Specification 2024-11-05 | OWASP Top 10 for LLM Applications 2025 - LLM06: Excessive Agency",
		}
	}

	postURL := eventEndpoint
	if strings.HasPrefix(postURL, "/") {
		postURL = getURL(target, postURL)
	}

	result, sessionID, err := postMCPJSONRPC(mcpSSEClient, postURL, mcpInitializeRequest, "")
	if err != nil || !isValidMCPInitializeResult(result) {
		return &models.Vulnerability{
			Target:      target,
			Name:        "Unauthenticated MCP Server Discovered",
			Severity:    "INFO",
			CVSS:        0.0,
			Description: fmt.Sprintf("An unauthenticated Model Context Protocol (MCP) SSE transport was discovered at '/sse' (session endpoint '%s'), but a JSON-RPC 'initialize' handshake against it did not complete.", eventEndpoint),
			Solution:    "Require authentication in front of the MCP endpoint and bind it to a private network if it is not meant to be publicly reachable.",
			Reference:   "MCP Specification 2024-11-05 | OWASP Top 10 for LLM Applications 2025 - LLM06: Excessive Agency",
		}
	}

	toolsResult, _, err := postMCPJSONRPC(mcpSSEClient, postURL, mcpToolsListRequest, sessionID)
	var tools []map[string]interface{}
	if err == nil {
		tools = extractMCPTools(toolsResult)
	}

	return buildMCPFinding(target, "/sse -> "+eventEndpoint, tools)
}
