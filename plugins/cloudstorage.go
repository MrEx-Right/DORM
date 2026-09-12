package plugins

import (
	"DORM/models"
	"DORM/sitemapper"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// AggressiveCloudWrite gates the anonymous PUT/write test in
// CloudStoragePlugin. Off by default — only set true when a scan
// explicitly opts in via the `aggressiveCloudWrite=true` query param
// (read and wired in handlers.go, mirroring bypassers.GlobalDelayConfig).
var AggressiveCloudWrite = false

// ==================================================
// MULTI-CLOUD STORAGE DEEP PROBE
// Extends the trivial S3-only substring check (s3bucket.go) to GCS, Azure
// Blob, DigitalOcean Spaces, and Cloudflare R2 — with ACTIVE anonymous
// LIST verification (always on) and an opt-in anonymous WRITE/cleanup test.
// ==================================================
type CloudStoragePlugin struct{}

func (p *CloudStoragePlugin) Name() string {
	return "Multi-Cloud Storage Exposure (Bucket/Blob Takeover)"
}

type bucketCandidate struct {
	Provider string
	Bucket   string
	Endpoint string // base URL to probe, no trailing slash
}

var (
	gcsHostRe  = regexp.MustCompile(`([a-z0-9][a-z0-9._-]{1,61})\.storage\.googleapis\.com`)
	gcsPathRe  = regexp.MustCompile(`storage\.googleapis\.com/([a-z0-9][a-z0-9._-]{1,61})`)
	azureRe    = regexp.MustCompile(`([a-z0-9]{3,24})\.blob\.core\.windows\.net/([a-zA-Z0-9$._-]{3,63})`)
	doSpacesRe = regexp.MustCompile(`[a-z0-9-]{3,63}\.[a-z0-9-]+\.digitaloceanspaces\.com`)
	r2Re       = regexp.MustCompile(`[a-z0-9-]{3,63}\.r2\.cloudflarestorage\.com`)
	r2DevRe    = regexp.MustCompile(`pub-[a-z0-9]+\.r2\.dev`)
)

func discoverCloudCandidates(body string) []bucketCandidate {
	var out []bucketCandidate
	seen := map[string]bool{}
	add := func(c bucketCandidate) {
		key := c.Provider + ":" + c.Endpoint
		if !seen[key] {
			seen[key] = true
			out = append(out, c)
		}
	}
	for _, m := range gcsHostRe.FindAllStringSubmatch(body, -1) {
		add(bucketCandidate{Provider: "gcs", Bucket: m[1], Endpoint: "https://" + m[1] + ".storage.googleapis.com"})
	}
	for _, m := range gcsPathRe.FindAllStringSubmatch(body, -1) {
		add(bucketCandidate{Provider: "gcs", Bucket: m[1], Endpoint: "https://storage.googleapis.com/" + m[1]})
	}
	for _, m := range azureRe.FindAllStringSubmatch(body, -1) {
		add(bucketCandidate{Provider: "azure", Bucket: m[2], Endpoint: fmt.Sprintf("https://%s.blob.core.windows.net/%s", m[1], m[2])})
	}
	for _, m := range doSpacesRe.FindAllString(body, -1) {
		add(bucketCandidate{Provider: "dospaces", Endpoint: "https://" + m})
	}
	for _, m := range r2Re.FindAllString(body, -1) {
		add(bucketCandidate{Provider: "r2", Endpoint: "https://" + m})
	}
	for _, m := range r2DevRe.FindAllString(body, -1) {
		add(bucketCandidate{Provider: "r2dev", Endpoint: "https://" + m})
	}
	return out
}

func anonHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

// probeCloudList attempts an anonymous LIST/listing request against the
// candidate's endpoint. Returns (confirmed, evidence snippet).
func probeCloudList(c bucketCandidate) (bool, string) {
	client := anonHTTPClient()
	var listURL string
	switch c.Provider {
	case "gcs":
		listURL = c.Endpoint // public GCS buckets return an XML listing at the bare endpoint
	case "azure":
		listURL = c.Endpoint + "?restype=container&comp=list"
	case "dospaces", "r2", "r2dev":
		listURL = c.Endpoint + "/?list-type=2"
	default:
		return false, ""
	}

	resp, err := client.Get(listURL)
	if err != nil {
		return false, ""
	}
	body := readBody(resp, 65536)
	if resp.StatusCode != 200 {
		return false, ""
	}

	switch c.Provider {
	case "gcs":
		if strings.Contains(body, "<ListBucketResult") || strings.Contains(body, `"items"`) {
			return true, "anonymous request returned bucket contents (ListBucketResult/items)"
		}
	case "azure":
		if strings.Contains(body, "<EnumerationResults") {
			return true, "anonymous container listing returned <EnumerationResults>"
		}
	case "dospaces", "r2", "r2dev":
		if strings.Contains(body, "<ListBucketResult") {
			return true, "anonymous LIST (list-type=2) returned <ListBucketResult>"
		}
	}
	return false, ""
}

// probeCloudWrite attempts an anonymous PUT of a uniquely-named, clearly
// labeled test object, then a best-effort DELETE cleanup. Only ever called
// when AggressiveCloudWrite is explicitly enabled for the scan.
func probeCloudWrite(c bucketCandidate) (writeConfirmed bool, cleanedUp bool, evidence string) {
	client := anonHTTPClient()

	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	objectName := "dorm-security-test-" + hex.EncodeToString(randBytes) + ".txt"
	body := "This file was created by DORM (a security scanner) as part of an authorized security assessment " +
		"to test anonymous write permissions on this storage bucket/container. It is safe to delete."

	objURL := c.Endpoint + "/" + objectName

	putReq, _ := http.NewRequest("PUT", objURL, strings.NewReader(body))
	putReq.Header.Set("Content-Type", "text/plain")
	if c.Provider == "azure" {
		putReq.Header.Set("x-ms-blob-type", "BlockBlob")
	}
	putResp, err := client.Do(putReq)
	if err != nil {
		return false, false, ""
	}
	_ = readBody(putResp, 4096)
	if putResp.StatusCode != 200 && putResp.StatusCode != 201 && putResp.StatusCode != 204 {
		return false, false, ""
	}

	evidence = fmt.Sprintf("anonymous PUT of %s succeeded (HTTP %d)", objectName, putResp.StatusCode)

	delReq, _ := http.NewRequest("DELETE", objURL, nil)
	if c.Provider == "azure" {
		delReq.Header.Set("x-ms-delete-snapshots", "include")
	}
	delResp, delErr := client.Do(delReq)
	cleanedUp = delErr == nil && delResp != nil && (delResp.StatusCode == 200 || delResp.StatusCode == 202 || delResp.StatusCode == 204)
	if delResp != nil {
		_ = readBody(delResp, 1024)
	}

	return true, cleanedUp, evidence
}

func (p *CloudStoragePlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	resp, err := client.Get(getURL(target, "/"))
	if err != nil {
		return nil
	}
	body := readBody(resp, 65536)

	candidates := discoverCloudCandidates(body)

	// Also scan JS file URLs the sitemapper already discovered — some
	// bucket references only ever appear in bundled JS, not raw HTML.
	if sm := sitemapper.GetSiteMap(target.IP); sm != nil {
		for _, jf := range sm.JSFiles {
			candidates = append(candidates, discoverCloudCandidates(jf.URL)...)
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	for _, c := range candidates {
		listOK, listEvidence := probeCloudList(c)

		var writeOK, cleaned bool
		var writeEvidence string
		if AggressiveCloudWrite {
			writeOK, cleaned, writeEvidence = probeCloudWrite(c)
		}

		if !listOK && !writeOK {
			continue
		}

		desc := fmt.Sprintf("Provider: %s\nEndpoint: %s\n", strings.ToUpper(c.Provider), c.Endpoint)
		severity := "HIGH"
		cvss := 8.6
		if listOK {
			desc += "Anonymous LIST: CONFIRMED — " + listEvidence + "\n"
		} else {
			desc += "Anonymous LIST: not confirmed.\n"
		}
		if AggressiveCloudWrite {
			if writeOK {
				desc += "Anonymous WRITE: CONFIRMED — " + writeEvidence + "\n"
				if cleaned {
					desc += "Cleanup: test object deleted successfully.\n"
				} else {
					desc += "Cleanup: WARNING — could not confirm deletion of the test object; verify/remove it manually.\n"
				}
				severity = "CRITICAL"
				cvss = 9.8
			} else {
				desc += "Anonymous WRITE: not confirmed (tested, since aggressive mode was enabled for this scan).\n"
			}
		}

		return &models.Vulnerability{
			Target: target, Name: "Multi-Cloud Storage Exposure (Bucket/Blob Takeover)", Severity: severity, CVSS: cvss,
			Description: desc,
			Solution:    "Remove public/anonymous read (and write, if confirmed) access from this bucket/container. Apply provider-specific private-by-default ACLs (S3/R2 bucket policy, GCS uniform bucket-level access, Azure private container access level).",
			Reference:   "CWE-284: Improper Access Control",
		}
	}

	return nil
}
