package promptinjectionengine

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Independent payload-corpus sync. This is DELIBERATELY separate from
// cve/sync.go and cve/kev.go — no shared code, no shared data files — only
// stylistically informed by their conventions (disk-backed cache, graceful
// degradation on failure, never blocking a scan on network I/O).
//
// Source: swisskyrepo/PayloadsAllTheThings "Prompt Injection" page (MIT
// licensed). It's a single flat markdown file with no releases/API
// mechanism, so freshness is judged by local file age, not a version compare.
// ─────────────────────────────────────────────────────────────────────────────

const (
	syncSourceURL = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Prompt%20Injection/README.md"

	// syncedPayloadsFile is relative to the process's working directory,
	// mirroring wordlists/ and cve/cve_full.json's relative-path convention.
	// Git-ignored — a runtime-refreshable cache, not a source file.
	syncedPayloadsFile = "plugins/promptinjectionengine/synced_payloads.json"

	syncMaxAge       = 24 * time.Hour // re-fetch at most once/day
	syncFetchTimeout = 10 * time.Second
	syncMaxBodyBytes = 2 << 20 // 2MB hard cap on the fetched markdown
	syncMaxPayloads  = 150     // cap on extracted+cached synced payloads
)

type syncedPayloadStore struct {
	FetchedAt time.Time `json:"fetchedAt"`
	SourceURL string    `json:"sourceUrl"`
	Payloads  []string  `json:"payloads"` // raw extracted text, canary NOT applied on disk
}

var (
	syncedMu    sync.RWMutex
	syncedCache []string // canary-trailer-applied, ready for direct use by LoadPayloads()
)

// StartBackgroundSync is the sole exported entry point main.go calls, as a
// fire-and-forget goroutine. It never blocks the caller on network I/O
// beyond its own goroutine, never panics out, and always leaves the package
// in a working state — BundledPayloads alone is already a complete corpus.
func StartBackgroundSync() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[-] PromptInjection Sync: recovered from panic: %v\n", r)
		}
	}()

	// 1. Always load whatever is on disk first (even if stale), so the
	//    process has synced data available immediately without waiting on
	//    the network — first-run/offline must still work via BundledPayloads.
	loadLocalIntoCache()

	// 2. Only hit the network if the local cache is missing or stale.
	if !isFresh(syncedPayloadsFile, syncMaxAge) {
		fetchAndPersist()
	}
}

func isFresh(path string, maxAge time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false // missing -> not fresh -> triggers a fetch
	}
	return time.Since(info.ModTime()) < maxAge
}

func loadLocalIntoCache() {
	data, err := os.ReadFile(syncedPayloadsFile)
	if err != nil {
		return // no local cache yet; syncedCache stays nil, LoadPayloads() falls back to bundled-only
	}
	var store syncedPayloadStore
	if err := json.Unmarshal(data, &store); err != nil {
		fmt.Printf("[-] PromptInjection Sync: local cache parse error: %v\n", err)
		return
	}
	applyCanaryAndCache(store.Payloads)
}

func fetchAndPersist() {
	body, err := fetchMarkdown()
	if err != nil {
		fmt.Printf("[-] PromptInjection Sync: fetch failed: %v (keeping bundled/cached payloads)\n", err)
		return
	}

	extracted := ExtractPayloads(body)
	if len(extracted) == 0 {
		// Source structure changed / doc empty / parsing regressed — refuse
		// to overwrite a possibly-good existing cache with nothing.
		fmt.Println("[-] PromptInjection Sync: 0 payloads extracted, keeping existing cache")
		return
	}

	store := syncedPayloadStore{
		FetchedAt: time.Now(),
		SourceURL: syncSourceURL,
		Payloads:  extracted,
	}
	if err := persist(store); err != nil {
		fmt.Printf("[-] PromptInjection Sync: failed to persist: %v\n", err)
		// Still usable in-memory for this run even if the disk write failed.
	}
	applyCanaryAndCache(extracted)
	fmt.Printf("[+] PromptInjection Sync: %d payloads synced from PayloadsAllTheThings\n", len(extracted))
}

func fetchMarkdown() (string, error) {
	// Deliberately NOT models.GetClient() — that client is tuned for
	// scan-target traffic (UA rotation/jitter/proxy). This is a one-off
	// infra fetch against GitHub, so it gets its own plain client.
	client := &http.Client{Timeout: syncFetchTimeout}

	req, err := http.NewRequest("GET", syncSourceURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "DORM-Security-Scanner (prompt-injection payload sync)")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, syncSourceURL)
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, syncMaxBodyBytes))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func persist(store syncedPayloadStore) error {
	if err := os.MkdirAll(filepath.Dir(syncedPayloadsFile), os.ModePerm); err != nil {
		return err
	}
	out, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(syncedPayloadsFile, out, 0644)
}

func applyCanaryAndCache(raw []string) {
	trailered := make([]string, 0, len(raw))
	for _, p := range raw {
		if wc := WithCanaryTrailer(p); wc != "" {
			trailered = append(trailered, wc)
		}
	}
	syncedMu.Lock()
	syncedCache = trailered
	syncedMu.Unlock()
}

// GetSyncedPayloads returns a defensive copy of the current in-memory
// synced-payload cache (already canary-trailered). Pure read, no I/O.
func GetSyncedPayloads() []string {
	syncedMu.RLock()
	defer syncedMu.RUnlock()
	out := make([]string, len(syncedCache))
	copy(out, syncedCache)
	return out
}

// LoadPayloads merges BundledPayloads (always first, always present) with
// the currently-cached synced payloads, deduped and capped — mirrors
// dirbuster.go's "curated list always included first" cap-then-union pattern.
func LoadPayloads() []string {
	maxTotal := len(BundledPayloads) + syncMaxPayloads
	seen := make(map[string]bool, maxTotal)
	out := make([]string, 0, maxTotal)

	add := func(p string) {
		if p == "" || seen[p] || len(out) >= maxTotal {
			return
		}
		seen[p] = true
		out = append(out, p)
	}

	for _, p := range BundledPayloads {
		add(p)
	}
	for _, p := range GetSyncedPayloads() {
		add(p)
	}
	return out
}

// ── Markdown extraction ──────────────────────────────────────────────────

var (
	fencedBlockRe = regexp.MustCompile("(?s)```[a-zA-Z0-9_-]*\\n(.*?)```")
	inlineCodeRe  = regexp.MustCompile("`([^`\\n]{15,300})`")
	tableRowRe    = regexp.MustCompile(`^\|(.+)\|$`)

	// codeNoiseRe matches structural/code syntax markers that indicate a
	// candidate is JSON/config/shell/source, not a natural-language prompt.
	codeNoiseRe = regexp.MustCompile(`[{}]|#!/|\bfunc \b|\bdef \b|\bclass \b|\bimport \b|\bSELECT \b|<\?php|==|->|;\s*$`)

	wordRe = regexp.MustCompile(`[A-Za-z']+`)
)

// ExtractPayloads pulls plausible natural-language prompt-injection payload
// strings out of a markdown document: fenced code blocks, inline code
// spans, and markdown table cells. Filters out JSON/code/schema noise.
func ExtractPayloads(md string) []string {
	var candidates []string

	for _, m := range fencedBlockRe.FindAllStringSubmatch(md, -1) {
		candidates = append(candidates, strings.Split(m[1], "\n")...)
	}
	for _, m := range inlineCodeRe.FindAllStringSubmatch(md, -1) {
		candidates = append(candidates, m[1])
	}
	for _, line := range strings.Split(md, "\n") {
		if m := tableRowRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			candidates = append(candidates, strings.Split(m[1], "|")...)
		}
	}

	seen := make(map[string]bool)
	var out []string
	for _, c := range candidates {
		p := strings.TrimSpace(c)
		if !isPlausiblePayload(p) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) >= syncMaxPayloads {
			break
		}
	}
	return out
}

// isPlausiblePayload applies concrete length/structure/word-ratio heuristics
// to reject JSON/code/schema noise while keeping natural-language prompts.
func isPlausiblePayload(s string) bool {
	if len(s) < 15 || len(s) > 400 {
		return false
	}
	if strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "---") {
		return false
	}
	if codeNoiseRe.MatchString(s) {
		return false
	}
	words := wordRe.FindAllString(s, -1)
	if len(words) < 3 {
		return false
	}
	alphaChars, totalChars := 0, 0
	for _, r := range s {
		if r == ' ' {
			continue
		}
		totalChars++
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '\'' || r == ',' || r == '.' {
			alphaChars++
		}
	}
	if totalChars == 0 || float64(alphaChars)/float64(totalChars) < 0.75 {
		return false // too much punctuation/symbol noise relative to prose
	}
	return true
}
