package sitemapper

import (
	"net/http"
	"strings"
)

// techSignature maps a detection key to a human-readable technology name.
type techSignature struct {
	key  string
	tech string
}

// headerSignatures checks HTTP response headers for technology hints.
var headerSignatures = []struct {
	header string
	value  string
	tech   string
}{
	{"Server", "nginx", "Nginx"},
	{"Server", "apache", "Apache"},
	{"Server", "iis", "IIS"},
	{"Server", "cloudflare", "Cloudflare"},
	{"Server", "lighttpd", "Lighttpd"},
	{"Server", "gunicorn", "Gunicorn"},
	{"Server", "caddy", "Caddy"},
	{"X-Powered-By", "php", "PHP"},
	{"X-Powered-By", "asp.net", "ASP.NET"},
	{"X-Powered-By", "express", "Express.js"},
	{"X-Powered-By", "next.js", "Next.js"},
	{"X-Generator", "wordpress", "WordPress"},
	{"X-Generator", "drupal", "Drupal"},
	{"X-Generator", "joomla", "Joomla"},
}

// cookieSignatures maps cookie name substrings to detected technologies.
var cookieSignatures = []techSignature{
	{"PHPSESSID", "PHP"},
	{"JSESSIONID", "Java (Servlet)"},
	{"ASP.NET_SessionId", "ASP.NET"},
	{"ASPSESSIONID", "ASP.NET"},
	{"laravel_session", "Laravel"},
	{"XSRF-TOKEN", "Laravel/Angular"},
	{"django", "Django"},
	{"wordpress_logged_in", "WordPress"},
	{"joomla_user_state", "Joomla"},
}

// bodySignatures maps HTML/body substrings to technologies.
var bodySignatures = []techSignature{
	{"wp-content", "WordPress"},
	{"wp-includes", "WordPress"},
	{"wp-json", "WordPress"},
	{"/themes/joomla", "Joomla"},
	{"Joomla!", "Joomla"},
	{"__VIEWSTATE", "ASP.NET WebForms"},
	{"__EVENTVALIDATION", "ASP.NET WebForms"},
	{"ng-version=", "Angular"},
	{"data-reactroot", "React"},
	{"__nuxt", "Nuxt.js"},
	{"__NEXT_DATA__", "Next.js"},
	{"django-csrf", "Django"},
	{"/static/admin/", "Django"},
	{"laravel", "Laravel"},
	{"symfony", "Symfony"},
	{"codeigniter", "CodeIgniter"},
	{"rails-ujs", "Ruby on Rails"},
	{`<meta name="generator" content="Gatsby`, "Gatsby"},
	{"x-vue-", "Vue.js"},
	{"svelte", "Svelte"},
}

// FingerprintPage detects technologies used by a page based on its response.
// It returns a deduplicated list of technology names.
func FingerprintPage(resp *http.Response, body string) []string {
	seen := make(map[string]bool)
	var techs []string

	add := func(t string) {
		if !seen[t] {
			seen[t] = true
			techs = append(techs, t)
		}
	}

	// 1. Check HTTP response headers
	for _, sig := range headerSignatures {
		val := strings.ToLower(resp.Header.Get(sig.header))
		if val != "" && strings.Contains(val, strings.ToLower(sig.value)) {
			add(sig.tech)
		}
	}

	// 2. Check cookies
	for _, cookie := range resp.Cookies() {
		cookieUpper := strings.ToUpper(cookie.Name)
		cookieLower := strings.ToLower(cookie.Name)
		for _, sig := range cookieSignatures {
			if strings.Contains(cookieUpper, strings.ToUpper(sig.key)) ||
				strings.Contains(cookieLower, strings.ToLower(sig.key)) {
				add(sig.tech)
			}
		}
	}

	// 3. Check body content
	bodyLower := strings.ToLower(body)
	for _, sig := range bodySignatures {
		if strings.Contains(bodyLower, strings.ToLower(sig.key)) {
			add(sig.tech)
		}
	}

	return techs
}
