package nosqliengine

import (
	"DORM/models"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ============================================================
//  COUCHDB PROBE — Unauthorized Access Detection
// ============================================================

// RunCouchProbe tests CouchDB for unauthenticated administrative access or open instances.
func RunCouchProbe(client *http.Client, baseURL string, target models.ScanTarget) *models.Vulnerability {
	endpoints := []string{
		"/_all_dbs",
		"/_utils/",
		"/_membership",
		"/_replicate",
		"/_config",
		"/_active_tasks",
	}

	for _, ep := range endpoints {
		resp, err := client.Get(baseURL + ep)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		_ = resp.Body.Close()
		bodyStr := string(body)

		if resp.StatusCode == 200 {
			if ep == "/_all_dbs" && strings.HasPrefix(bodyStr, "[") && strings.Contains(bodyStr, "_replicator") {
				return buildCouchVuln(target, baseURL+ep, "Open CouchDB Instance (/_all_dbs accessible)", bodyStr)
			}
			if ep == "/_utils/" && strings.Contains(bodyStr, "Fauxton") {
				return buildCouchVuln(target, baseURL+ep, "Open CouchDB Fauxton Admin UI", "Fauxton interface exposed")
			}
			if ep == "/_membership" && strings.Contains(bodyStr, "all_nodes") {
				return buildCouchVuln(target, baseURL+ep, "CouchDB Membership Info Leak", bodyStr)
			}
		}
	}
	return nil
}

func buildCouchVuln(target models.ScanTarget, url, name, sample string) *models.Vulnerability {
	if len(sample) > 200 {
		sample = sample[:200] + "..."
	}
	return &models.Vulnerability{
		Target:   target,
		Name:     name,
		Severity: "CRITICAL",
		CVSS:     9.8,
		Description: fmt.Sprintf(
			"Unauthorized access to CouchDB API endpoint.\nURL: %s\nResponse Sample:\n%s",
			url, sample,
		),
		Solution:  "Require authentication for all CouchDB endpoints. Bind CouchDB to localhost if not used externally.",
		Reference: "CWE-284: Improper Access Control",
	}
}
