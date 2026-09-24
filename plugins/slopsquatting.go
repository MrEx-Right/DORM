package plugins

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"DORM/models"
)

// ==================================================
// AI DEPENDENCY HALLUCINATION (SLOPSQUATTING) SCANNER
// Fetches exposed dependency manifests from the target and checks each
// referenced package name against its public registry. A name that does not
// resolve is a supply-chain risk: "slopsquatting" is an attack where an AI
// coding assistant hallucinates a plausible-looking but non-existent package
// name, which an attacker can then register and poison ahead of anyone who
// trusts the AI-generated dependency list.
// ==================================================

type SlopsquattingPlugin struct{}

func (p *SlopsquattingPlugin) Name() string {
	return "AI Dependency Hallucination (Slopsquatting) Scanner"
}

func (p *SlopsquattingPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()

	manifests := fetchDependencyManifests(client, target)
	if len(manifests) == 0 {
		return nil
	}

	deps := extractDependencies(manifests)
	if len(deps) == 0 {
		return nil
	}

	return checkPackageRegistries(target, deps)
}

// ── Manifest discovery ──────────────────────────────────────────────────

type slopManifestFile struct {
	Path      string
	Ecosystem string
	Body      string
}

// slopCandidateManifestPaths is a deliberately short, high-signal list
// rather than a broad wordlist, to bound the number of requests per scan.
var slopCandidateManifestPaths = map[string]string{
	"/package.json":     "npm",
	"/requirements.txt": "pypi",
	"/go.mod":           "go",
	"/composer.json":    "packagist",
}

const maxManifestBytes = 512 * 1024

// fetchDependencyManifests probes the target for exposed dependency
// manifests and returns the ones actually found (skipping 404s, empty
// bodies, and responses that look like an HTML error/catch-all page rather
// than a real manifest file).
func fetchDependencyManifests(client *http.Client, target models.ScanTarget) []slopManifestFile {
	var found []slopManifestFile

	for path, ecosystem := range slopCandidateManifestPaths {
		resp, err := client.Get(getURL(target, path))
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes))
		_ = resp.Body.Close()

		text := strings.TrimSpace(string(body))
		if text == "" {
			continue
		}
		// A real manifest never starts with an HTML tag — most catch-all/SPA
		// routes return an HTML page (often status 200) for any unknown path.
		if strings.HasPrefix(text, "<") {
			continue
		}

		found = append(found, slopManifestFile{Path: path, Ecosystem: ecosystem, Body: text})
	}

	return found
}

// ── Dependency extraction ───────────────────────────────────────────────

type slopDependency struct {
	Name      string
	Ecosystem string
}

// maxDependencies caps the total number of unique dependencies checked
// against public registries per scan, bounding worst-case outbound requests.
const maxDependencies = 25

// extractDependencies parses each manifest per its ecosystem's format,
// filters out entries that are obviously private/local (and therefore not
// registry-resolvable, which would be a false positive), dedupes by
// (ecosystem, name) across all manifests found, and caps the result.
func extractDependencies(manifests []slopManifestFile) []slopDependency {
	seen := map[string]bool{}
	var deps []slopDependency

	add := func(name, ecosystem string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		key := ecosystem + ":" + name
		if seen[key] {
			return
		}
		seen[key] = true
		deps = append(deps, slopDependency{Name: name, Ecosystem: ecosystem})
	}

	for _, m := range manifests {
		switch m.Ecosystem {
		case "npm":
			extractNPMDeps(m.Body, add)
		case "pypi":
			extractPyPIDeps(m.Body, add)
		case "go":
			extractGoDeps(m.Body, add)
		case "packagist":
			extractPackagistDeps(m.Body, add)
		}
		if len(deps) >= maxDependencies {
			break
		}
	}

	if len(deps) > maxDependencies {
		deps = deps[:maxDependencies]
	}
	return deps
}

func isLocalVersionSpec(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "workspace:") ||
		strings.HasPrefix(v, "file:") ||
		strings.HasPrefix(v, "link:") ||
		strings.HasPrefix(v, "portal:") ||
		strings.HasPrefix(v, "git+") ||
		strings.HasPrefix(v, "git://") ||
		strings.HasPrefix(v, "http://") ||
		strings.HasPrefix(v, "https://")
}

func extractNPMDeps(body string, add func(name, ecosystem string)) {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(body), &pkg); err != nil {
		return
	}
	for name, version := range pkg.Dependencies {
		if !isLocalVersionSpec(version) {
			add(name, "npm")
		}
	}
	for name, version := range pkg.DevDependencies {
		if !isLocalVersionSpec(version) {
			add(name, "npm")
		}
	}
}

var slopPyPILineRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)`)

func extractPyPIDeps(body string, add func(name, ecosystem string)) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-r") ||
			strings.HasPrefix(line, "-e") || strings.HasPrefix(line, "--") {
			continue
		}
		// Skip lines that are actually direct URLs/VCS refs, not a plain
		// registry package name.
		if strings.Contains(line, "://") {
			continue
		}
		if m := slopPyPILineRe.FindStringSubmatch(line); m != nil {
			add(m[1], "pypi")
		}
	}
}

var slopGoRequireLineRe = regexp.MustCompile(`^\s*([a-zA-Z0-9.\-_]+(?:/[a-zA-Z0-9.\-_~]+)+)\s+v[0-9]`)

func extractGoDeps(body string, add func(name, ecosystem string)) {
	inBlock := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "require (") {
			inBlock = true
			continue
		}
		if inBlock && trimmed == ")" {
			inBlock = false
			continue
		}
		if strings.HasPrefix(trimmed, "replace ") {
			continue
		}

		var candidate string
		if inBlock {
			candidate = trimmed
		} else if strings.HasPrefix(trimmed, "require ") {
			candidate = strings.TrimPrefix(trimmed, "require ")
		} else {
			continue
		}

		if m := slopGoRequireLineRe.FindStringSubmatch(candidate); m != nil {
			modulePath := m[1]
			// A module path's first segment normally contains a dot (a real
			// host like github.com); skip anything that doesn't, to avoid
			// treating local/relative-looking paths as registry modules.
			firstSeg := strings.SplitN(modulePath, "/", 2)[0]
			if strings.Contains(firstSeg, ".") {
				add(modulePath, "go")
			}
		}
	}
}

func extractPackagistDeps(body string, add func(name, ecosystem string)) {
	var pkg struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal([]byte(body), &pkg); err != nil {
		return
	}
	handle := func(m map[string]string) {
		for name, version := range m {
			// Platform pseudo-packages (php, ext-json, lib-*) have no '/' and
			// are not real Packagist packages.
			if !strings.Contains(name, "/") {
				continue
			}
			if strings.TrimSpace(version) == "*" {
				continue
			}
			add(name, "packagist")
		}
	}
	handle(pkg.Require)
	handle(pkg.RequireDev)
}

// ── Public registry verification ────────────────────────────────────────

// slopRegistryClient is a plain client deliberately separate from the
// target's models.GetClient() — the WAF-bypass UA rotation/jitter on that
// client exists to evade the SCAN TARGET's defenses and is pointless (and
// slower) against public package registries.
var slopRegistryClient = &http.Client{Timeout: 4 * time.Second}

// packageExistsInRegistry checks whether a dependency name resolves in its
// public registry. checkErr is set (and found ignored) on any
// network/unexpected-status failure, so registry flakiness/rate-limiting
// never gets reported as a hallucinated package.
func packageExistsInRegistry(dep slopDependency) (found bool, checkErr error) {
	var checkURL string
	switch dep.Ecosystem {
	case "npm":
		checkURL = npmRegistryLookupURL(dep.Name)
	case "pypi":
		checkURL = "https://pypi.org/pypi/" + url.PathEscape(dep.Name) + "/json"
	case "go":
		checkURL = "https://proxy.golang.org/" + escapeGoModulePath(dep.Name) + "/@v/list"
	case "packagist":
		parts := strings.SplitN(dep.Name, "/", 2)
		if len(parts) != 2 {
			return false, fmt.Errorf("malformed packagist name: %s", dep.Name)
		}
		checkURL = "https://repo.packagist.org/p2/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + ".json"
	default:
		return false, fmt.Errorf("unknown ecosystem: %s", dep.Ecosystem)
	}

	resp, err := slopRegistryClient.Get(checkURL)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case 200:
		return true, nil
	case 404, 410:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, checkURL)
	}
}

func npmRegistryLookupURL(name string) string {
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			return "https://registry.npmjs.org/" + url.PathEscape(parts[0]) + "%2f" + url.PathEscape(parts[1])
		}
	}
	return "https://registry.npmjs.org/" + url.PathEscape(name)
}

// escapeGoModulePath applies the Go module proxy's case-encoding rule
// (each uppercase letter becomes '!' + its lowercase form) so mixed-case
// module paths resolve correctly against proxy.golang.org.
func escapeGoModulePath(path string) string {
	var b strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// checkPackageRegistries verifies every dependency against its registry
// and, if any could not be resolved, returns a single finding listing all
// of them.
func checkPackageRegistries(target models.ScanTarget, deps []slopDependency) *models.Vulnerability {
	var missing []slopDependency
	for _, dep := range deps {
		found, err := packageExistsInRegistry(dep)
		if err != nil {
			continue // network failure ≠ hallucination — don't flag
		}
		if !found {
			missing = append(missing, dep)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	severity, cvss := "MEDIUM", 5.3
	if len(missing) >= 2 {
		severity, cvss = "HIGH", 7.2
	}

	var lines []string
	for _, dep := range missing {
		lines = append(lines, fmt.Sprintf("  - [%s] %s", dep.Ecosystem, dep.Name))
	}

	description := fmt.Sprintf(
		"The following %d dependency name(s) were found in the target's exposed manifest(s) but do not "+
			"resolve in their public registry:\n\n%s\n\n"+
			"\"Slopsquatting\" is a supply-chain attack where an AI coding assistant hallucinates a "+
			"plausible-looking but non-existent package name; an attacker who notices the hallucinated "+
			"name can register it and publish malicious code, which then gets pulled in by anyone (or any "+
			"CI pipeline) that trusts the AI-generated dependency list.\n\n"+
			"This finding does NOT by itself confirm the name was AI-hallucinated — verify manually, "+
			"especially for private/internal packages that are not meant to be publicly resolvable "+
			"(private registries, monorepo-local packages, or recently unpublished packages can also "+
			"produce this result).",
		len(missing), strings.Join(lines, "\n"),
	)

	return &models.Vulnerability{
		Target:      target,
		Name:        "AI Dependency Hallucination (Slopsquatting) Risk",
		Severity:    severity,
		CVSS:        cvss,
		Description: description,
		Solution:    "Verify each listed dependency is intentional and resolves in your build. If any name was AI-generated (e.g. by a coding assistant) and does not exist upstream, remove it immediately and consider registering the exact string under your own namespace to preempt registration by an attacker.",
		Reference:   "OWASP LLM Top 10 2025 - LLM03: Supply Chain Vulnerabilities",
	}
}
