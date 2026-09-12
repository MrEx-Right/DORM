package plugins

import (
	"DORM/models"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// ==================================================
// AI & VECTOR DATABASE UNAUTHORIZED ACCESS
// ChromaDB / Qdrant / Milvus / Ollama expose management APIs over plain
// HTTP with no authentication by default — these ports are NOT part of
// models.IsWebPort's whitelist, so this plugin gates on exact target.Port
// values instead (mirrors the multi-port pattern in mongo.go).
// ==================================================
type AIVectorDBPlugin struct{}

func (p *AIVectorDBPlugin) Name() string { return "AI/Vector Database Unauthorized Access" }

func (p *AIVectorDBPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	switch target.Port {
	case 8000:
		return checkChromaDB(target)
	case 6333:
		return checkQdrant(target)
	case 19530, 9091:
		return checkMilvus(target)
	case 11434:
		return checkOllama(target)
	default:
		return nil
	}
}

func checkChromaDB(target models.ScanTarget) *models.Vulnerability {
	client := models.GetClient()
	resp, err := client.Get(getURL(target, "/api/v1/heartbeat"))
	if err != nil {
		return nil
	}
	body := readBody(resp, 8192)
	if !strings.Contains(body, "heartbeat") {
		return nil
	}

	collResp, err := client.Get(getURL(target, "/api/v1/collections"))
	if err != nil {
		return nil
	}
	collBody := readBody(collResp, 65536)

	var collections []map[string]interface{}
	names := []string{}
	if err := json.Unmarshal([]byte(collBody), &collections); err == nil {
		for i, c := range collections {
			if i >= 5 {
				break
			}
			if n, ok := c["name"].(string); ok {
				names = append(names, n)
			}
		}
	}

	desc := fmt.Sprintf(
		"ChromaDB instance responded to an unauthenticated heartbeat check and returned its collection list without any authentication.\nCollections found: %d\n",
		len(collections),
	)
	if len(names) > 0 {
		desc += "Sample collection names: " + strings.Join(names, ", ") + "\n"
	}
	desc += "This exposes raw vector/RAG data (embeddings, and potentially source documents) to anyone who can reach this port."

	return &models.Vulnerability{
		Target: target, Name: "ChromaDB Unauthenticated Access", Severity: "CRITICAL", CVSS: 9.4,
		Description: desc,
		Solution:    "Enable ChromaDB authentication (a server-side auth provider) and bind the service to a private network / firewall it off from public access.",
		Reference:   "CWE-306: Missing Authentication for Critical Function",
	}
}

func checkQdrant(target models.ScanTarget) *models.Vulnerability {
	client := models.GetClient()
	resp, err := client.Get(getURL(target, "/collections"))
	if err != nil {
		return nil
	}
	body := readBody(resp, 65536)
	if !strings.Contains(body, `"collections"`) {
		return nil
	}

	extra := ""
	if clusterResp, err := client.Get(getURL(target, "/cluster")); err == nil {
		clusterBody := readBody(clusterResp, 8192)
		if strings.Contains(clusterBody, "peer_id") || strings.Contains(clusterBody, "raft_info") {
			extra = "\nCluster topology (/cluster) is also disclosed without authentication."
		}
	}

	return &models.Vulnerability{
		Target: target, Name: "Qdrant Unauthenticated Access", Severity: "CRITICAL", CVSS: 9.4,
		Description: "Qdrant vector database returned its full collection list via /collections without any API key or authentication." + extra,
		Solution:    "Set the `api_key` configuration option (or front Qdrant with an authenticating reverse proxy) and remove public network access to this port.",
		Reference:   "CWE-306: Missing Authentication for Critical Function",
	}
}

func checkMilvus(target models.ScanTarget) *models.Vulnerability {
	if target.Port == 9091 {
		resp, err := models.GetClient().Get(getURL(target, "/metrics"))
		if err != nil {
			return nil
		}
		body := readBody(resp, 131072)
		if !strings.Contains(body, "milvus_") {
			return nil
		}
		return &models.Vulnerability{
			Target: target, Name: "Milvus Metrics Endpoint Exposed", Severity: "HIGH", CVSS: 8.0,
			Description: "Milvus's Prometheus metrics endpoint (/metrics on port 9091) is exposed without authentication, disclosing internal operational data (query load, collection activity, resource usage).",
			Solution:    "Restrict access to the metrics port to a private monitoring network; do not expose it publicly.",
			Reference:   "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
		}
	}

	// Port 19530 is Milvus's gRPC endpoint — a plain HTTP client can't speak
	// gRPC, so we only confirm the port is genuinely open and note that deep
	// protocol verification needs a real Milvus/gRPC client. Deliberately
	// not claiming a CRITICAL finding without real protocol confirmation.
	addr := net.JoinHostPort(target.IP, fmt.Sprintf("%d", target.Port))
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil
	}
	_ = conn.Close()

	return &models.Vulnerability{
		Target: target, Name: "Milvus gRPC Endpoint Open", Severity: "INFO", CVSS: 0.0,
		Description: "A TCP connection to Milvus's default gRPC port (19530) succeeded, indicating the service is reachable. DORM did not perform deep gRPC protocol verification here — manually confirm with a Milvus client (e.g. pymilvus) whether authentication is enforced.",
		Solution:    "Restrict network access to the Milvus gRPC port and enable Milvus's authentication feature if not already configured.",
		Reference:   "CWE-306: Missing Authentication for Critical Function",
	}
}

func checkOllama(target models.ScanTarget) *models.Vulnerability {
	client := models.GetClient()
	resp, err := client.Get(getURL(target, "/api/tags"))
	if err != nil {
		return nil
	}
	body := readBody(resp, 65536)
	if !strings.Contains(body, `"models"`) {
		return nil
	}

	var tagsResp struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	modelNames := []string{}
	if err := json.Unmarshal([]byte(body), &tagsResp); err == nil {
		for i, m := range tagsResp.Models {
			if i >= 5 {
				break
			}
			modelNames = append(modelNames, m.Name)
		}
	}

	desc := fmt.Sprintf(
		"Ollama's model management API (/api/tags) responded without any authentication, disclosing the full installed model inventory.\nModels found: %d",
		len(tagsResp.Models),
	)
	if len(modelNames) > 0 {
		desc += "\nSample models: " + strings.Join(modelNames, ", ")
	}

	// Minimal, capped confirmation that /api/generate is also unauthenticated:
	// tiny fixed prompt, non-streaming, hard token cap, short timeout. This
	// is supplementary evidence appended to the same finding, never a
	// separate/replacement result.
	model := "llama3"
	if len(modelNames) > 0 {
		model = modelNames[0]
	}
	genPayload := strings.NewReader(fmt.Sprintf(
		`{"model":%q,"prompt":"Reply with exactly the word: test","stream":false,"options":{"num_predict":5}}`, model,
	))
	genReq, _ := http.NewRequest("POST", getURL(target, "/api/generate"), genPayload)
	if genReq != nil {
		genReq.Header.Set("Content-Type", "application/json")
		genClient := &http.Client{Timeout: 5 * time.Second}
		if genResp, genErr := genClient.Do(genReq); genErr == nil {
			genBody := readBody(genResp, 4096)
			if strings.Contains(genBody, `"response"`) {
				desc += "\n\nAdditionally confirmed: /api/generate executed a minimal (5-token, non-streaming) completion without authentication — the target's compute resources can be consumed by anyone who can reach this port."
			}
		}
	}

	return &models.Vulnerability{
		Target: target, Name: "Ollama Unauthenticated Access", Severity: "CRITICAL", CVSS: 9.1,
		Description: desc,
		Solution:    "Bind Ollama to localhost only, or place it behind an authenticating reverse proxy. Do not expose port 11434 to untrusted networks.",
		Reference:   "CWE-306: Missing Authentication for Critical Function",
	}
}
