package templates

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"DORM/models"
)

// DynamicPlugin adapts a user-saved ScanTemplate into a models.ScannerPlugin
// so the existing Engine can run it exactly like any built-in plugin — same
// worker pool, timeout, panic recovery and AllowedPlugins gating. It also
// inherits the active scan's auth header, proxy and jitter settings for
// free, since those live in the shared client returned by models.GetClient().
type DynamicPlugin struct {
	Template ScanTemplate
}

func (d *DynamicPlugin) Name() string { return d.Template.Name }

func (d *DynamicPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !models.IsWebPort(target.Port) {
		return nil
	}

	// A template needs to see the literal 3xx response (status + Location
	// header) to test for things like open redirects — the shared client's
	// default behavior of auto-following redirects means that response is
	// never observed, and if the redirect target doesn't resolve (a common
	// PoC pattern — pointing at a throwaway/attacker-controlled domain), the
	// whole request errors out and the template silently never matches.
	// Reuses the shared client's Transport (so proxy/auth/UA rotation still
	// apply) but stops at the first response instead of chasing Location.
	sharedClient := models.GetClient()
	client := &http.Client{
		Transport: sharedClient.Transport,
		Timeout:   sharedClient.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req := d.Template.Request

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	payloads := req.Payloads
	if len(payloads) == 0 {
		payloads = []string{""}
	}

	for _, payload := range payloads {
		path := strings.ReplaceAll(req.Path, "{{payload}}", payload)
		body := strings.ReplaceAll(req.Body, "{{payload}}", payload)

		httpReq, err := http.NewRequest(method, models.GetURL(target, path), strings.NewReader(body))
		if err != nil {
			continue
		}

		// A body on POST/PUT/PATCH is almost always meant as HTML-form data
		// (the overwhelmingly common case: testing a login/search form's own
		// POST body). Without this, PHP's $_POST — and most other backends'
		// equivalent — never populates, so a payload placed in the body is
		// silently ignored by the server even though the request "succeeds".
		// Set as a default, not forced, so an explicit header below (e.g. for
		// a JSON API template) still wins.
		if body != "" && (method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch) {
			httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for k, v := range req.Headers {
			httpReq.Header.Set(k, strings.ReplaceAll(v, "{{payload}}", payload))
		}

		resp, err := client.Do(httpReq)
		if err != nil {
			continue
		}
		status := resp.StatusCode
		headers := resp.Header
		bodyStr := models.ReadBody(resp, 65536)

		if evaluateMatcher(d.Template.Matcher, status, bodyStr, headers) {
			return &models.Vulnerability{
				Target:      target,
				Name:        d.Template.Name,
				Severity:    d.Template.Severity,
				CVSS:        d.Template.CVSS,
				Description: d.Template.Description,
				Solution:    d.Template.Solution,
				Reference:   d.Template.Reference,
			}
		}
	}

	return nil
}

// evaluateMatcher checks a single matcher group against one response.
func evaluateMatcher(m MatcherSpec, status int, body string, headers http.Header) bool {
	var result bool

	switch m.Type {
	case "status_code":
		result = matchAny(m, func(v string) bool {
			code, err := strconv.Atoi(strings.TrimSpace(v))
			return err == nil && code == status
		})
	case "regex":
		haystack := selectPart(m.Part, status, body, headers)
		result = matchAny(m, func(v string) bool {
			re, err := regexp.Compile(v)
			return err == nil && re.MatchString(haystack)
		})
	default: // "word"
		haystack := selectPart(m.Part, status, body, headers)
		result = matchAny(m, func(v string) bool {
			return strings.Contains(haystack, v)
		})
	}

	if m.Negate {
		result = !result
	}
	return result
}

// selectPart returns the response slice a word/regex matcher searches.
// "header" flattens every response header into "Key: value" lines so a
// single matcher can check any header without the builder having to name
// which one in advance.
func selectPart(part string, status int, body string, headers http.Header) string {
	switch part {
	case "header":
		var sb strings.Builder
		for k, vals := range headers {
			for _, v := range vals {
				sb.WriteString(k)
				sb.WriteString(": ")
				sb.WriteString(v)
				sb.WriteString("\n")
			}
		}
		return sb.String()
	case "status":
		return strconv.Itoa(status)
	default:
		return body
	}
}

// matchAny applies test to every matcher value, combined with the matcher's
// Condition. Condition defaults to OR when unset or not "AND".
func matchAny(m MatcherSpec, test func(string) bool) bool {
	if len(m.Values) == 0 {
		return false
	}
	if strings.EqualFold(m.Condition, "AND") {
		for _, v := range m.Values {
			if !test(v) {
				return false
			}
		}
		return true
	}
	for _, v := range m.Values {
		if test(v) {
			return true
		}
	}
	return false
}
