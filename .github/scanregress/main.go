// scanregress runs one full DORM scan (plugins=ALL) against the nightly lab
// targets and compares the findings with baseline.json:
//
//   - expected:            must be found; a missing one is a lost detection
//   - knownFalsePositives: tolerated while unfixed (warning); once one stops
//     firing it is reported so it can move out of the list
//   - flaky:               may or may not fire (timing-dependent variants)
//   - anything else fails: a new false positive, or a new detection that has
//     to be reviewed and added to the baseline
//
// A finding is keyed "<label>:<port> | <Name> | <Severity>"; baseline
// patterns use * as a wildcard. Run with -record to write every finding of
// this run as a candidate baseline instead of comparing.
//
// It lives under .github so `go build ./...` and the linters skip it; run it
// in file mode: go run .github/scanregress/main.go -targets ...
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

type baseline struct {
	Expected            []string     `json:"expected"`
	KnownFalsePositives []knownFP    `json:"knownFalsePositives"`
	Flaky               []string     `json:"flaky"`
	Notes               []string     `json:"notes,omitempty"`
	compiled            *compiledSet `json:"-"`
}

type knownFP struct {
	Match string `json:"match"`
	Note  string `json:"note"`
}

type compiledSet struct {
	expected, known, flaky []*regexp.Regexp
}

type finding struct {
	Status string
	Name   string
	Target struct {
		IP   string
		Port int
	}
	Severity    string
	Description string
}

func main() {
	dorm := flag.String("dorm", "http://127.0.0.1:8080", "DORM base URL")
	targetsFlag := flag.String("targets", "", "comma-separated label=host[:port] list, e.g. juiceshop=172.17.0.2:3000")
	baselinePath := flag.String("baseline", ".github/scanregress/baseline.json", "baseline file")
	outPath := flag.String("out", "findings.json", "where to write this run's findings")
	record := flag.Bool("record", false, "write the findings as a candidate baseline instead of comparing")
	timeout := flag.Duration("timeout", 50*time.Minute, "overall scan timeout")
	flag.Parse()

	labels, hosts, err := parseTargets(*targetsFlag)
	if err != nil {
		fatal(err)
	}

	if err := waitReady(*dorm, 15*time.Minute); err != nil {
		fatal(err)
	}

	findings, err := scan(*dorm, hosts, *timeout)
	if err != nil {
		fatal(err)
	}

	keys := map[string]finding{}
	for _, f := range findings {
		label, ok := labels[f.Target.IP]
		if !ok {
			label = f.Target.IP
		}
		keys[fmt.Sprintf("%s:%d | %s | %s", label, f.Target.Port, f.Name, f.Severity)] = f
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	// The key list is what gets compared; the descriptions next to it are
	// what a human needs to tell a true positive from a false one.
	type detail struct {
		Key         string
		Description string
	}
	details := make([]detail, 0, len(sorted))
	for _, k := range sorted {
		details = append(details, detail{k, keys[k].Description})
	}
	if err := writeJSON(*outPath, details); err != nil {
		fatal(err)
	}
	fmt.Printf("%d findings (%d unique) written to %s\n", len(findings), len(sorted), *outPath)

	// A finding about a URL on another host means DORM attacked a site
	// that is not a lab target. The lab has no internet, so the request
	// itself failed there, but the scope leak is a bug in every mode.
	violations := scopeViolations(findings, labels)
	for _, v := range violations {
		fmt.Printf("::error title=Scope violation::%s\n", v)
	}
	if len(violations) > 0 {
		summary("### Scope violations (%d)\n\nDORM reported findings on hosts outside the scan targets:\n\n- `%s`\n\n", len(violations), strings.Join(violations, "`\n- `"))
	}

	if *record {
		cand := baseline{Expected: sorted, KnownFalsePositives: []knownFP{}, Flaky: []string{}}
		path := strings.TrimSuffix(*outPath, ".json") + ".baseline-candidate.json"
		if err := writeJSON(path, cand); err != nil {
			fatal(err)
		}
		fmt.Printf("record mode: candidate baseline written to %s; classify it before committing\n", path)
		summary("### Scan regression (record mode)\n\n%d unique findings recorded. Review the candidate baseline artifact, move false positives to `knownFalsePositives`, then commit it.\n", len(sorted))
		if len(violations) > 0 {
			os.Exit(1)
		}
		return
	}

	b, err := loadBaseline(*baselinePath)
	if err != nil {
		fatal(err)
	}
	if len(b.Expected) == 0 {
		fatal(errors.New("baseline has no expected findings; run once with -record and commit the reviewed result"))
	}
	if !compare(b, sorted) || len(violations) > 0 {
		os.Exit(1)
	}
}

// urlFieldRe matches the "URL: ..." / "Endpoint: ..." fields plugins put in
// a finding's description; payload strings elsewhere in it may name other
// hosts on purpose (SSRF probes), so only these fields are checked.
var urlFieldRe = regexp.MustCompile(`(?:^|\s)(?:URL|Endpoint):\s*(\S+)`)

func scopeViolations(fs []finding, labels map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range fs {
		for _, m := range urlFieldRe.FindAllStringSubmatch(f.Description, -1) {
			u, err := url.Parse(m[1])
			if err != nil || u.Hostname() == "" {
				continue
			}
			if _, ok := labels[u.Hostname()]; ok {
				continue
			}
			v := fmt.Sprintf("%s (%s:%d) -> %s", f.Name, f.Target.IP, f.Target.Port, m[1])
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

func parseTargets(s string) (labels map[string]string, hosts []string, err error) {
	labels = map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		label, host, ok := strings.Cut(part, "=")
		if !ok || label == "" || host == "" {
			return nil, nil, fmt.Errorf("bad target %q, want label=host[:port]", part)
		}
		// DORM reports findings by bare host; a port given here only tells
		// the pre-scan which port to crawl (a bare host crawls port 80).
		ip := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			ip = h
		}
		labels[ip] = label
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 {
		return nil, nil, errors.New("no -targets given")
	}
	return labels, hosts, nil
}

// waitReady polls DORM until its HTTP server answers. Startup blocks on the
// CVE database sync, which can take minutes on a cold cache.
func waitReady(base string, max time.Duration) error {
	deadline := time.Now().Add(max)
	c := &http.Client{Timeout: 5 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := c.Get(base + "/plugins")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("DORM at %s not ready after %s", base, max)
}

// scan opens the /scan SSE stream and collects every finding until DONE.
// Findings sent after DONE are dropped by DORM itself, so DONE is final.
func scan(base string, hosts []string, timeout time.Duration) ([]finding, error) {
	q := url.Values{}
	q.Set("targets", strings.Join(hosts, ","))
	q.Set("plugins", "ALL")
	c := &http.Client{Timeout: timeout}
	resp, err := c.Get(base + "/scan?" + q.Encode())
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/scan returned %s", resp.Status)
	}

	var out []finding
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	start := time.Now()
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		var f finding
		if err := json.Unmarshal([]byte(data), &f); err != nil {
			return nil, fmt.Errorf("bad SSE frame %q: %w", data, err)
		}
		if f.Name != "" {
			out = append(out, f)
			continue
		}
		switch f.Status {
		case "DONE":
			fmt.Printf("scan DONE after %s\n", time.Since(start).Round(time.Second))
			return out, nil
		case "ERROR":
			return nil, fmt.Errorf("scan error: %s", data)
		case "STARTED":
			fmt.Printf("scan started: %s\n", data)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("SSE stream ended without DONE")
}

func compare(b *baseline, keys []string) bool {
	var unexpected, knownHit []string
	expHit := make([]bool, len(b.Expected))
	knownSeen := make([]bool, len(b.KnownFalsePositives))

	for _, k := range keys {
		matched := false
		for i, re := range b.compiled.expected {
			if re.MatchString(k) {
				expHit[i], matched = true, true
			}
		}
		for i, re := range b.compiled.known {
			if re.MatchString(k) {
				knownSeen[i], matched = true, true
				knownHit = append(knownHit, k)
			}
		}
		for _, re := range b.compiled.flaky {
			if re.MatchString(k) {
				matched = true
			}
		}
		if !matched {
			unexpected = append(unexpected, k)
		}
	}

	var missing, fixed []string
	for i, hit := range expHit {
		if !hit {
			missing = append(missing, b.Expected[i])
		}
	}
	for i, seen := range knownSeen {
		if !seen {
			fixed = append(fixed, b.KnownFalsePositives[i].Match)
		}
	}

	var md strings.Builder
	md.WriteString("### Scan regression\n\n")
	section := func(title, level string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&md, "**%s (%d)**\n\n", title, len(items))
		for _, it := range items {
			fmt.Fprintf(&md, "- `%s`\n", it)
			fmt.Printf("::%s title=%s::%s\n", level, title, it)
		}
		md.WriteString("\n")
	}
	section("Lost detections", "error", missing)
	section("Unexpected findings (new FP or unreviewed detection)", "error", unexpected)
	section("Known false positives still firing", "warning", knownHit)
	section("Known false positives no longer firing (fixed? remove from baseline)", "notice", fixed)
	fmt.Fprintf(&md, "%d findings, %d expected patterns.\n", len(keys), len(b.Expected))
	summary("%s", md.String())

	return len(missing) == 0 && len(unexpected) == 0
}

func loadBaseline(path string) (*baseline, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b baseline
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	b.compiled = &compiledSet{}
	for _, p := range b.Expected {
		b.compiled.expected = append(b.compiled.expected, pattern(p))
	}
	for _, k := range b.KnownFalsePositives {
		b.compiled.known = append(b.compiled.known, pattern(k.Match))
	}
	for _, p := range b.Flaky {
		b.compiled.flaky = append(b.compiled.flaky, pattern(p))
	}
	return &b, nil
}

// pattern turns a baseline entry into an anchored regexp where * matches
// any run of characters and everything else is literal.
func pattern(p string) *regexp.Regexp {
	parts := strings.Split(p, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$")
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// summary appends to the GitHub job summary when running in Actions.
func summary(format string, a ...any) {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, format, a...)
}

func fatal(err error) {
	fmt.Println("::error::" + err.Error())
	os.Exit(1)
}
