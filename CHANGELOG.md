# Changelog

All notable changes to this project will be documented in this file.

## [v1.20.0] - 2026-07-23
### 🕷️ DOM Crawler Integration & Concurrency Refactor

This major release introduces a headless browser engine capable of crawling JavaScript-heavy Single Page Applications (SPAs). It also features a complete overhaul of the pre-scan concurrency model to eliminate bottlenecks and prevent connection timeouts.

---

#### 🕸️ DOM Crawler Engine (`dom/` & `sitemapper/`)
- **SPA-Aware Browser Crawler:** Integrated `chromedp` to launch a headless browser that executes JavaScript, navigates SPAs (React, Vue, Angular), and clicks interactive elements to uncover hidden attack surfaces.
- **Network Interception:** Added a network listener to capture XHR/Fetch API calls initiated by the page. Dynamically discovered endpoints are correctly parsed with their HTTP methods (POST, PUT, etc.) and payloads, ensuring DORM plugins can attack them accurately.
- **Client-Side Route Discovery:** Injects scripts to capture `history.pushState` and `window.__dormRoutes` to map hidden client-side routing logic.
- **Form Extraction:** Extracts HTML forms rendered dynamically via JS and automatically feeds them into the main vulnerability Engine.

#### 🖥️ UI & Control Panel (`web/`)
- **Live Activity Feed:** Added a new "DOM Crawler" panel that streams real-time browser activity (Navigations, Clicks, Forms, XHRs, and Errors) with micro-animations.
- **New Icons:** Updated the "New Scan" icon to `fa-satellite-dish` for better thematic alignment.

#### 🔒 TLS Scanner False Positive Mitigation (`plugins/tlscipher.go` & `plugins/tlscheck.go`)
- **Strict Application Data Verification:** Completely removed fallback logic that treated read timeouts (`timeout`) or connection drops (`eof`) as valid indicators of weak cipher support. WAFs/CDNs often complete TLS handshakes for traffic inspection but drop or ignore connections afterwards.
- **HTTP/1.1 Probe Request:** Probes now transmit a complete, compliant `HTTP/1.1` request with a `Host` header (`GET / HTTP/1.1\r\nHost: <IP>\r\nConnection: close\r\nUser-Agent: DORM-Scanner\r\n\r\n`).
- **Empirical Read Confirmation:** A weak cipher suite or legacy protocol is now flagged **only** if the target web server explicitly returns encrypted application-layer data over the negotiated TLS connection (`readErr == nil && n > 0`).

---

## [v1.19.1] - 2026-07-16
### 🔧 Bug Fixes & Severity Calibration

This patch corrects inflated severity ratings in the port scanner, fixes a broken CVE database rendering bug in the frontend, and hardens the CVE sync engine to reliably fetch the latest daily snapshots from CVEProject.

---

#### ⚖️ Port Scanner Severity Calibration (`plugins/unnecessaryports.go`)
- **FTP (21) & Database Ports downgraded to INFO:** The mere presence of an open port is informational, not a confirmed vulnerability. Dedicated plugins (`ftpanon.go`, `mongo.go`, `redis.go`, etc.) already perform active exploit checks and issue HIGH/CRITICAL findings when warranted. Reporting FTP as CVSS 7.5 solely because port 21 is open was a false positive.
- **Telnet (23) & SMB (445) downgraded to MEDIUM / CVSS 5.3:** Both protocols carry inherent risk, but port visibility alone does not confirm exploitability. Severity reduced from HIGH / 7.5–8.5 to MEDIUM / 5.3.
- **RDP (3389) & VNC (5900/5901) downgraded to LOW / CVSS 3.5:** Reduced from MEDIUM / 6.0. Port exposure is worth noting but does not constitute a confirmed attack surface without further testing.
- **DevOps API ports (Docker, Kubernetes, RabbitMQ, Consul) downgraded to LOW / CVSS 3.1:** Reduced from MEDIUM / 6.5. Exposure is notable but unconfirmed without authentication testing.
- **Alternative HTTP ports (non-dev) downgraded to INFO / CVSS 0.0:** Generic web services on non-standard ports are purely informational unless a dev/debug signature is detected via active probe.
- **Dev/Debug services (webpack, werkzeug, Flask debug, etc.) remain MEDIUM / CVSS 6.0:** This finding is backed by active HTTP probing and confirmed body/header signal matching — severity is justified.

#### 🐛 CVE Database Frontend Fix (`web/app.js`)
- **Broken render fixed:** `/api/cvedb` returns `{ "stats": {...}, "cves": [...] }` but the frontend was treating the entire object as an array. `cves.length` evaluated to `undefined`, causing `renderCVELines()` to crash silently — the CVE tab displayed nothing. Fixed by correctly destructuring `data.cves` from the response.
- **Stats counter fixed:** Total record count now reads from `data.stats.total_cves` (the actual in-memory count of ~280K) instead of the truncated display slice length.
- **Severity badge fix in `renderCVELines()`:** Badge logic previously collapsed LOW and INFO into MEDIUM. Corrected to CRITICAL (≥9.0) / HIGH (≥7.0) / MEDIUM (≥4.0) / LOW (>0) / INFO (=0). CVSS 0 entries now display `N/A` instead of crashing on `.toFixed()`.

#### 🔄 CVE Sync Engine Hardening (`cve/sync.go`)
- **Missing timestamp in probe list:** CVEProject publishes snapshots at various hours throughout the day. The fallback `probeSnapshotURL()` function only checked `1900Z–2300Z`. The `1100Z` release (confirmed live on 2026-07-16) was never discovered, causing the engine to fall back to yesterday's database when the GitHub API was unavailable. Expanded `knownTimestamps` to cover all 24 hours (`0000Z`–`2300Z`).
- **UpdateInterval reduced from 24h to 6h:** A 24-hour window meant that restarting DORM later in the same day always loaded the stale morning snapshot. 6 hours allows up to 4 refreshes per day, matching CVEProject's publish cadence without hammering GitHub.
- **Delta URL false match fixed:** `strings.HasSuffix(name, ".zip")` also matches `.zip.zip` filenames. The full snapshot (`all_CVEs_at_midnight.zip.zip`) could have been incorrectly selected as the delta. Added an explicit `!strings.HasSuffix(name, ".zip.zip")` guard.
- **End-of-day delta support added:** CVEProject publishes a `_delta_CVEs_at_end_of_day.zip` asset that contains all CVE changes for the entire day — more comprehensive than the intraday `_at_midnight` delta. The asset selector now uses a two-pass approach to explicitly prefer the end-of-day delta, falling back to any other delta variant if it is not yet available.

---

## [v1.19.0] - 2026-07-14
### 🛡️ WAF Bypass Engine & UI Enhancements

This update introduces a dedicated WAF bypass architecture to help DORM evade enterprise rate-limiting and signature-based WAFs. It also fixes critical real-time state synchronization issues with the Sitemapper module.

---

#### 🥷 WAF Bypass Framework (`bypassers/`)
- **Rate Limiting / Jitter (`delay.go`):** Added a global sleep mechanism with configurable base delay and random jitter (ms) to throttle outgoing requests and bypass rate-limiting WAF rules.
- **User-Agent Rotation (`rotateagent.go`):** Extracted UA rotation logic into a dedicated module and hardcoded it to be permanently active for all outgoing plugin and spider requests.
- **Null-Byte Injection (`nullbyte.go`):** Implemented safe `%00` injection logic for future payloads to exploit path truncation flaws in backend parsing.
- **Double URL Encoding (`uep.go`):** Added a payload transformer that double URL encodes malicious payloads (`<script>` -> `%253Cscript%253E`) to bypass WAFs that only decode inputs once.

#### 🖥️ UI & Control Panel
- **WAF Bypass Menu:** Added a dedicated "WAF Bypass" tab to the left navigation menu, allowing users to configure Base Delay, Jitter, Null-Byte, and UEP settings dynamically before starting a scan.
- **Proxy Icon Update:** Changed the Proxy Settings icon to `fa-server` to distinguish it visually from the Sitemap icon.
- **Rotate User-Agent Removed:** Removed the "Rotate User-Agent" toggle from the UI, as this feature is now a permanently enabled stealth mechanism in the core HTTP client.

#### 🗄️ Core Engine & Sitemapper Fixes
- **Sitemap Sync & Polling:** Fixed a synchronization bug where Sitemapper results were not streaming to the frontend during scans. The backend now immediately fires a `STARTED` SSE payload containing the `ScanID`, allowing the frontend to begin polling `db_site_maps` instantly.


## [v1.18.0] - 2026-07-10
### 🕷️ Spider & CVE Database Improvements

This update significantly improves the Web Spider and the CVE Database Sync mechanisms, making DORM more resilient, accurate, and memory efficient.

---

#### 🕸️ Web Spider (v3) Engine Rewrite
- **Timeout Protection:** Added context deadlines to `fetchBody` (`context.WithTimeout`). The spider now aborts requests safely if a target server hangs indefinitely, preventing runaway processes.
- **Dynamic Config Limits:** Removed the hard-coded 150 URL limit. Added a new `SpiderConfig` struct that supports dynamic `MaxURLs` (default 500) and `MaxDepth` constraints to better handle large corporate sites.
- **Robust HTML Parsing:** Removed fragile Regex-based HTML parsing for forms and links. Switched to `golang.org/x/net/html` for robust traversal. Regex is now only utilized as a fallback for extracting JavaScript paths.

#### 🗄️ CVE Database Engine Enhancements
- **Multi-Level Product Resolution:** Fixed a major issue where over 150K CVEs were being skipped due to missing product identifiers. The engine now uses a 3-tier fallback logic:
  1. Primary: Reads the structured Product tag.
  2. Fallback: Uses the Vendor Project tag if Product is missing or "n/a".
  3. NLP Fallback: Extracts the product name directly from the description text via grammatical patterns (e.g., "flaw in the X module").
- **Universal Language Fallback:** Descriptions are no longer restricted strictly to "en" or "en-US". The engine will accept any available language description if English is missing.
- **Skip Diagnostics Logging:** Added explicit skip counters (`state`, `no_desc`, `no_product`) during database compilation to provide better visibility into why certain CVEs are rejected (e.g., REJECTED/RESERVED states).
- **Format & Path Changes:** Converted `cve_full.json` serialization from minified strings to indented JSON (`json.MarshalIndent`) for manual inspection. Moved the database location from `wordlists/` to a dedicated `cve/` directory.

#### 🎯 Passive CVE Plugin Enhancements
- **Composite Key Search:** Enhanced the index search capability (`Search()`) to query both simple product names and `vendor:product` composite keys, and increased the result limits from 25 to 50 deduplicated hits.
- **Unrestricted Reporting:** Removed the CVSS thresholds that previously dropped MEDIUM and LOW vulnerabilities. The engine now reports every matched CVE regardless of its score.
- **Versionless Reporting:** If a technology version cannot be fingerprinted, DORM will now report all discovered CVEs (up to the limit) for the matching product as potential risks instead of silently skipping them.

#### 🖥️ UI & Scan Stability
- **Unreachable Target Validation:** If a user enters a dead IP or domain, the UI no longer silently resets to the "START SCAN" state. The backend immediately fires an explicit `"ERROR"` SSE payload, and the frontend intercepts this to display a browser alert. Scan history now correctly reflects a "Failed" status for unreachable targets.
- **Localization:** Translated all Turkish comments and strings across the Spider component into professional English.


## [v1.17.0] - 2026-07-05
### 🧩 Framework Security Suite & Detection Engine Hardening

This update delivers three major improvements: a full framework-specific vulnerability suite (9 new plugins), a hardened Prompt Injection engine, and a false-positive fix for the TLS Cipher scanner — bringing the total active plugin count to **99**.

---

#### 🆕 Framework-Specific Security Misconfiguration Suite (9 New Plugins)

A new category of plugins has been introduced targeting framework-level operational security misconfigurations. Each plugin first fingerprints the target framework via HTTP response signals (headers, cookies, body patterns), then fires a chain of active probes against framework-specific endpoints. Findings are returned only on confirmed body/header signal matches — no passive-only checks, no CVE exploitation. All 9 plugins follow the same `fingerprint → probe → signal → Vulnerability{}` architecture used by every other DORM module.

- **Django Scanner (`django.go`):** Fingerprints via `/admin/` + `csrfmiddlewaretoken`. Detects: Debug mode active (`DisallowedHost`, `ImproperlyConfigured`, stack trace in 404), insecure `django-insecure-` secret key visible in error pages, admin panel exposed at `/admin/`, Django Debug Toolbar accessible at `/__debug__/`, DRF Browsable API renderer enabled (`/api/?format=api`), API schema publicly accessible (`/api/schema/`, `/api/docs/`), and static file directory listing (`/static/`). Aggregates all hits into a single finding with severity escalation up to `CRITICAL (CVSS 9.1)`.

- **Ruby on Rails Scanner (`rails.go`):** Fingerprints via `X-Runtime: 0.` float header + `_session_id` cookie. Detects: `/rails/info/properties` exposing Ruby/Rails version and middleware stack, `/rails/info/routes` leaking the full route table, development exception pages rendering `ActionController::RoutingError` + `Rails.root`, mailer preview endpoint accessible at `/rails/mailers/`, asset source maps (`.js.map`, `.css.map`) downloadable, and Devise/auth sign-in endpoints enumerable.

- **ASP.NET Core Scanner (`aspnetcore.go`):** Fingerprints via `X-Powered-By: ASP.NET`, `X-AspNet-Version` header, `Server: Microsoft-IIS/Kestrel`, or `__RequestVerificationToken` in body. Detects: Developer Exception Page revealing .NET stack traces and assembly paths, `Trace.axd` HTTP request history log, ELMAH error log (`/elmah.axd`), `web.config` backup files (`.bak`, `.old`, `.orig`) containing connection strings, Blazor WASM boot manifest (`/_framework/blazor.boot.json`) exposing assembly list, Swagger/OpenAPI UI accessible in production, health check endpoints leaking internal service topology (DB/Redis names), and SignalR hub negotiation endpoints returning `connectionToken` unauthenticated.

- **Express/Node.js Scanner (`expressjs.go`):** Fingerprints via `X-Powered-By: Express` header + `connect.sid` cookie. Detects: `X-Powered-By` version disclosure, `package.json` publicly accessible (full dependency list), `package-lock.json`/`yarn.lock` lock file exposure, `node_modules/` directory listing enabled, `.env` file exposure containing `NODE_ENV`/`DB_PASSWORD`/`SECRET`/`API_KEY`, JavaScript source maps (`.js.map`) downloadable from web root, and application log endpoints (`/logs`, `/debug`, `/_logs`) returning plaintext log data.

- **Next.js Scanner (`nextjs.go`):** Fingerprints via `__NEXT_DATA__` script tag in HTML + `/_next/static/` path or `x-nextjs-page` header. Detects: `__NEXT_DATA__` JSON blob containing `env`, `serverRuntimeConfig`, or `runtimeConfig` keys with non-empty values leaked to the client, build ID exposure at `/_next/BUILD_ID`, `next.config.js` publicly accessible, JavaScript source maps in `/_next/static/chunks/`, unprotected API routes returning secret/password/token/key/database fields, server-side env vars leaked into `pageProps`, and middleware authorization bypass via the `x-middleware-subrequest` header (status code differential detection).

- **NestJS Scanner (`nestjs.go`):** Fingerprints via `X-Powered-By: Express` + `/api-json` OpenAPI response. Detects: Swagger/OpenAPI documentation publicly accessible (`/api`, `/api-docs`, `/swagger`, `/api-json`), internal module names leaked in malformed JSON POST error responses (`@nestjs/`, `TypeOrmModule`), health endpoint revealing DB/Redis/ORM dependency names, debug/log endpoints returning `[LOG]`/`[DEBUG]`/`[ERROR]` output, and unsecured API operations detected by parsing OpenAPI spec for missing `security` fields (threshold: >3 unguarded operations).

- **FastAPI Scanner (`fastapi.go`):** Fingerprints via `Server: uvicorn`/`gunicorn` header or `/openapi.json` returning `"openapi"`. Detects: Swagger UI (`/docs`) and ReDoc (`/redoc`) publicly accessible, raw OpenAPI JSON schema exposed (`/openapi.json`), Pydantic v2 validation error objects leaking field schema (`"loc"` + `"msg"` + `"type"` triple), Python tracebacks (`Traceback (most recent call last)`) in 500 responses, Prometheus metrics endpoint (`/metrics`) returning `# HELP`/`# TYPE` lines, and CORS wildcard + credentials misconfiguration (`Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` simultaneously).

- **Symfony Scanner (`symfony.go`):** Fingerprints via `X-Debug-Token` response header, `sf-dump` CSS class in body, or `Symfony\Component` in exception pages. Detects: Web Debug Toolbar accessible at `/_wdt/`, full Symfony Profiler request/response dump at `/_profiler/`, development front controllers (`app_dev.php`, `index_dev.php`) reachable in production, exception pages exposing `Symfony\Component` class names and Twig template paths, `.env` variant files (`/.env.local`, `/.env.dev`, `/.env.test`, `/.env.prod`) containing `APP_SECRET`/`DATABASE_URL`, and API Platform documentation accessible without authentication.

- **CodeIgniter Scanner (`codeigniter.go`):** Fingerprints via `ci_session` cookie + `CodeIgniter` keyword in body or `/index.php/` URL pattern. Detects: PHP error display enabled (`A PHP Error was encountered`, `Severity: Notice`), `database.php` config file publicly accessible containing DB credentials, `config.php` exposed with encryption key and base URL, application/system directory listing (`/application/`, `/system/`), `phpinfo()` pages accessible, `ci_session` cookie missing `HttpOnly`/`Secure`/`SameSite` flags, and Spark CLI endpoint accessible via HTTP.

---

#### 🔁 Prompt Injection Engine — v2.0 (`prompt_injection.go`)

Complete rewrite of the AI/LLM Prompt Injection scanner with significantly expanded coverage and a smarter detection mechanism.

- **30 Payload Configurations:** Expanded from 3 to 30 unique injection configurations, each targeting a distinct bypass vector: classic direct override, DAN role-play persona swap, nested continuation injection, Markdown code-block smuggling, Base64 decode trick, JSON role injection, XML/CDATA smuggling, prompt-continuation override, Unicode homoglyph bypass, `[INST]` bracket override (Llama/Mistral format), token-stuffing via repetition, false-authority admin override, developer mode jailbreak, translation obfuscation, hypothetical framing, story/fiction framing, Socratic system prompt leak, reverse psychology, invisible zero-width Unicode injection, fake system message header spoofing, leetspeak encoded override, false memory injection, instruction chaining, escaped newline smuggling, fabricated chat-log injection, OpenAI function-call JSON injection, negative constraint bypass, emotional manipulation, URL parameter comment injection, and multi-language confusion (French).

- **50-Word Feedback Signal Engine:** Detection logic entirely rewritten. Instead of checking for a single hardcoded canary string, the engine now maintains a dictionary of 50 feedback words — direct canary markers (`DORM_PWNED`, `DORM_INJECTED`, `DORM_CONFIRMED`, `DORM_CANARY`, `DORM_LEAKED`), obedience phrases (`sure, i can help with that`, `as instructed`, `following your instructions`, `previous instructions ignored`), system prompt leakage signals (`system prompt:`, `my instructions are`, `confidential instructions`), jailbreak confirmation phrases (`dan mode`, `developer mode enabled`, `do anything now`, `unrestricted mode`), and generic compliance outputs (`acknowledged`, `your wish is my command`, `consider it done`).

- **HTML Body Grep Mechanism:** The detection pipeline strips all HTML markup from the response body using a compiled `regexp` before scanning — `stripHTML()` removes all `<tag>` elements and normalises whitespace, ensuring signals embedded in HTML-formatted responses (chat interfaces, rendered markdown) are not missed. `containsFeedbackSignal()` then applies case-insensitive `strings.Contains` against all 50 words on the cleaned plaintext.

- **Status Code Independence:** The engine no longer requires HTTP 200 to process a response. Every response body — regardless of status code — is read and analysed. This captures AI APIs that return injection compliance in 400/500 error envelopes.

- **Improved `urlParamEncode()`:** Expanded the minimal URL encoder to handle 10 special characters (`"`, `'`, `\n`, `\r`, `{`, `}`, `[`, `]`, `<`, `>`) in addition to spaces, enabling proper encoding of complex payloads in GET query parameters.

- **Severity Upgrade:** Confirmed prompt injection findings are now rated `HIGH (CVSS 8.1)` (previously `MEDIUM 6.5`) reflecting the confirmed model compliance signal.

- **Extended API Endpoint Coverage:** Added `/query`, `/api/query`, `/llm`, `/gpt`, `/assistant`, `/api/assistant` to the probe endpoint list (15 total, previously 9).

---

#### 🐛 TLS Cipher Scanner — False Positive Fix (`tlscipher.go`)

Fixed a class of false positives caused by WAFs, CDNs, and load balancers that accept TLS handshakes for all cipher suites (for interception/inspection purposes) but immediately reset the connection with a TCP RST when the backend does not support the negotiated cipher.

- **Root Cause:** The previous implementation flagged a cipher as "supported" immediately after a successful TLS handshake, before verifying that the server would actually transmit application data. WAFs completing handshakes for traffic analysis triggered false positives.

- **Fix — Application Data Verification:** After the handshake + `ConnectionState` cipher check, the scanner now sends a minimal HTTP request (`GET / HTTP/1.0\r\n\r\n`) and attempts to read at least 1 byte of the response with a 2-second deadline. The cipher is only added to the confirmed weak list if: the server returns data (`readErr == nil`), the read times out (`timeout` in error string — server is holding the connection), or the connection is cleanly closed by the server (`eof` in error string). A hard TCP RST or TLS alert (connection reset by peer) is treated as a delayed WAF rejection and the cipher is discarded from results.

---

## [v1.16.0] - 2026-06-26
### 🌐 NIST CVE Database (cvelistV5) & UX Update

- **Full CVE Database Engine:** Removed the legacy CISA KEV implementation and fully integrated the comprehensive CVEProject/cvelistV5 nightly snapshot system. The database now tracks over 280,000+ vulnerability records with intelligent delta updates (fetching only changes) and high-speed in-memory indexing via the new `cve/sync.go` engine.
- **UX & Interface Refinements:** Streamlined the web interface by removing the local CVE database views for a cleaner experience. Replaced the basic terminal startup banner with a highly stylized, ANSI Shadow ASCII art banner that visually emphasizes the core "DORM" brand.
- **Resilience:** Implemented a robust `probeSnapshotURL()` mechanism that uses HTTP HEAD requests to intelligently discover the latest CVE release snapshots even when GitHub's standard API endpoints are rate-limited or unavailable.

## [v1.15.1] - 2026-06-23
### 🐛 False Positive Eradication Update

- **Open Redirect Scanner:** Fixed a major false positive where innocuous redirects (e.g., HTTP to HTTPS) were flagged as vulnerabilities simply because the `Location` header contained the payload as a parameter. The engine now strictly parses the `Location` header and verifies that the `Host` exactly matches the payload domain (`example.com`), guaranteeing absolute precision.
- **Weak TLS Cipher Suites:** Eliminated false positives related to legacy ciphers (e.g., CVE-2016-2183 SWEET32, RC4). Previously, a successful TLS connection triggered an alert even if the server ignored the requested weak cipher and negotiated a secure fallback. The scanner now strictly inspects the `ConnectionState` to verify that the server explicitly negotiated and accepted the weak `CipherSuite` requested.

## [v1.15.0] - 2026-06-19
### ⚡ The Auth-Breaker & IP-Ghost Update

Two new next-generation security modules have been added to the active scanning engine, bringing the total plugin count to **90**. Both modules target attack surfaces not previously covered by any existing plugin.

- **BFLA/BOLA Scanner — v1.0 `bfla_bola.go` (New Plugin):** Introduced a dedicated **Broken Function Level Authorization (BFLA)** and **Broken Object Level Authorization via HTTP Method Tampering (BOLA)** detection engine, targeting OWASP API Security Top-10 2023 A1 and A5. This module is architecturally distinct from the existing IDOR plugin — where IDOR focuses on sequential object ID enumeration, this engine attacks **authorization matrix gaps exposed through HTTP verb switching and role boundary crossing**. The detection pipeline runs four independent phases: **(1) Admin Endpoint Discovery** — combines Spider-harvested endpoints with a 28-path admin pattern matrix (`/api/admin`, `/api/management`, `/internal/admin`, `/api/users/all`, `/api/billing/override`, and more) to identify function-level targets; **(2) Unauthorized Role Escalation (BFLA)** — replays discovered admin endpoints using a low-privilege Token B, raising a **CRITICAL (CVSS 9.8)** finding if the server returns a non-empty 200 response free of soft-error signals; also tests unauthenticated access with admin data keyword scoring (minimum 2-keyword match to suppress false positives); **(3) HTTP Method Tampering (BOLA)** — for every object endpoint returning HTTP 200 via GET, the engine replays the request using PUT, DELETE, and PATCH verbs under a lower-privilege identity, raising **CRITICAL (CVSS 9.6)** on success; success is determined by status code (200/201/204) combined with soft-error absence detection (9 denial keyword patterns); **(4) Cross-Tenant Method-Based Object Access** — confirms object ownership via Token A (GET), then attempts DELETE and PUT on the same resource using Token B, raising **CRITICAL (CVSS 9.7)** if the mutation succeeds. Soft-error detection prevents false positives from servers that return 200 with embedded denial messages. Token configuration reuses the existing `idor_token_a` / `idor_token_b` shared state keys; the engine degrades gracefully to anonymous-only testing when tokens are absent.

- **IP Spoof Scanner — v1.0 `ip_spoof.go` (New Plugin):** Introduced a **Rate-Limit & WAF Bypass via IP Header Spoofing** detection engine targeting OWASP API Security Top-10 2023 A4 (Unrestricted Resource Consumption). Engineered with a **passive-first, ban-safe architecture** to prevent IP bans from disrupting concurrently running plugins. Five safety rules are baked into the design: *(1)* passive header inspection before any active probing; *(2)* a hard cap of 3 active probe requests per run; *(3)* an 8-second startup delay to yield priority to critical plugins (SQLi, XSS, Spider); *(4)* a ban sentinel that aborts the entire plugin on any connection error; *(5)* one request per spoof header with no retry loops. The detection pipeline operates in four phases: **(Phase 1 — Passive Header Scan)** issues a single request to a lightweight probe endpoint and inspects all response headers against 10 rate-limit signature patterns (`X-RateLimit-Limit`, `RateLimit-Remaining`, `Retry-After`, `X-Rate-Limit-*`, etc.) — zero active flooding required; **(Phase 2 — Minimal Active Probe)** sends at most 3 sequential requests to confirm a 429 or 403+WAF-body signal when no passive header evidence is found; **(Phase 3 — Header Spoof Bypass)** iterates a 12-header spoof matrix — Standard Proxy (`X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`), CDN/Cloud (`True-Client-IP` for Akamai/Cloudflare Enterprise, `CF-Connecting-IP`, `Fastly-Client-IP`, `X-Azure-ClientIP`, `X-Cluster-Client-IP`), and RFC 7239 (`Forwarded: for=127.0.0.1`) — sending one request per header and stopping immediately on the first bypass; **(Phase 4 — Compound Multi-Header Attack)** injects all 12 spoof headers simultaneously in a single request, targeting parsers that resolve ambiguity by acting on the first match. Findings are rated **HIGH (CVSS 7.5)** for confirmed bypass, **MEDIUM (CVSS 5.8)** for compound-header bypass, and **MEDIUM (CVSS 4.3)** for detected-but-unbypassable rate-limiting. Discovered rate-limit and WAF state is written to `SharedData` for consumption by other plugins. IP pool covers localhost, all RFC-1918 ranges, and IPv6 loopback — no real external IPs are used.

## [v1.14.0] - 2026-06-03
### ⚡ Plugin Enhancement Pack 1.2

Four core security modules have been completely rewritten with next-generation attack and detection architectures.

- **License Migration — AGPL-3.0:** Project relicensed under the GNU Affero General Public License v3.0. Any derivative work or network-accessible deployment of DORM must be distributed under the same license with full source code made available. See `LICENSE` for full terms.

- **Blind RCE Engine — v3.0 "Phantom Strike" (Complete Rewrite):** Introduced a **dynamic WAF-bypass obfuscation engine** that never sends raw `sleep N` commands — payloads are algorithmically transformed per-request into 10+ variants for Linux (``$IFS`` substitution, ``${IFS}`` spacing, hex-encoded binary names via ``$'\xNN'``, inline variable split ``s=sl;e=eep;$s$e N``, brace expansion ``{sleep,N}``, ``printf+sh`` pipe) and Windows (cmd caret bypass ``p^i^n^g``, empty-string bypass ``pi''ng``, PowerShell string concat ``&('sl'+'eep') N``, ``Start-Sleep``, ``[Threading.Thread]::Sleep``). Introduced an **adaptive statistical delta analysis** engine to eliminate false positives on slow networks: Phase 1 measures the server's baseline RTT via 3 clean GET samples; Phase 2 fires a ``sleep 2`` probe and rejects if latency delta is within noise margin; Phase 3 fires a ``sleep 7`` probe and mathematically verifies the ``t2/t1 ≈ 3.5 ± 20%`` proportionality ratio before confirming the vulnerability. Added full **POST parameter fuzzing** for Spider-discovered POST endpoints. Probe endpoint list expanded from 6 to 13 paths; parameter list expanded from 8 to 14.

- **JWT Security Scanner — v3.0 "Key Breaker" (Complete Rewrite):** Brute-force dictionary expanded from 20 to **50+ common weak secrets** covering Flask, Django, Rails, and generic JWT defaults. Added **automated Algorithm Confusion attack** (RS256/ES256 → HS256): the engine auto-discovers the server's JWKS endpoint (8 common paths scanned), extracts the RSA public key, marshals it to PEM format, and uses it as the HMAC-SHA256 secret to forge valid tokens — fully automated, zero external dependencies (``crypto/rsa``, ``crypto/x509``, ``math/big``). Added **`none` algorithm bypass** extended to 5 casing variants (``none``, ``None``, ``NONE``, ``nOnE``, ``NoNe``). Added **KID header injection** with path traversal (``../../../../dev/null``, ``../../etc/passwd``) and SQL injection payloads (UNION SELECT). Added **JWK self-embed** (embedded attacker-controlled symmetric key in JWT header). Added **JKU URL injection** probing SSRF via ``jku`` header parameter. Spider integration now tests JWT weaknesses on all discovered endpoints containing Authorization headers.

- **Tomcat Manager — v3.0 "Catalina Exploiter" (Complete Rewrite):** Default credential matrix expanded from 3 to **19 credential pairs** covering all known Tomcat, JBoss, and generic Java container defaults. Added **8 URL bypass variants** probing all manager endpoints: standard ``/manager/html``, ``/manager/status``, ``/manager/text/list`` (text API for automation), ``/host-manager/html``, double-slash WAF bypass ``//manager/html``, partial URL-encode ``/manager/%68tml``, Tomcat path traversal CVE bypass ``/.;/manager/html``, and full URL-encode bypass. Upon successful credential validation, the engine performs **in-memory WAR deployment**: a minimal ``.war`` archive (``WEB-INF/web.xml`` + ``shell.jsp``) is constructed entirely in RAM using Go's ``archive/zip``, uploaded via ``PUT /manager/text/deploy`` (with multipart form fallback), and verified by executing ``id`` against the deployed JSP shell. If ``uid=`` is found in the response, the finding is escalated to **CRITICAL (CVSS 10.0)** as "RCE Confirmed via WAR Deployment". Shell is **automatically undeployed** via ``/manager/text/undeploy`` after verification regardless of outcome. Three-tier severity model: CRITICAL (unauthenticated access) → CRITICAL (creds + WAR deploy → RCE confirmed) → CRITICAL (creds + WAR deployed but RCE unconfirmed) → HIGH (panel exposed, creds failed).

## [v1.13.1] - 2026-05-30
### 🧹 CVE Plugin Cleanup & Proxy Optimization

- **Vulnerability Scanning Streamlining:** Decoupled and completely removed 8 signature-based CVE exploit plugins from the active scanning pool. This streamlines the scanner engine to focus primarily on high-fidelity, input-driven generic vulnerabilities.
  - **Removed Modules:** Log4Shell (CVE-2021-44228), Spring Cloud Gateway RCE (CVE-2022-22947), F5 BIG-IP TMUI RCE (CVE-2020-5902), Shellshock (CVE-2014-6271), Drupalgeddon2 RCE (CVE-2018-7600), Citrix ADC Traversal (CVE-2019-19781), Atlassian Confluence RCE (CVE-2022-26134), and TeamCity Auth Bypass (CVE-2023-42793).
  - **Retained General Modules:** Retained generic product scanners and detection modules, including WordPress Enumeration & CVE Radar, Apache Struts RCE, and the Offline CVE Radar database parsing engine.
- **Native Analyzer Proxy Landing Page:** Resolved a protocol scheme resolution error when accessing the local DAST proxy (port `8081`) directly via a web browser. Implemented a beautiful, glassmorphic dark-themed English instructions landing page for direct browser access, preventing raw `unsupported protocol scheme` failures while keeping forward proxy operations fully functional.

## [v1.13.0] - 2026-05-28
### 🚀 Plugin Enhancement Pack 1 · Update PEP 1.1

Eight core injection and attack modules have been completely rewritten with next-generation detection architectures.

- **Brute Force Engine — v2.0 "Hydra Elite" (Complete Rewrite):** Expanded the credential arsenal from 10 to **100+ default credentials** covering Generic, Router/IoT, Linux/Unix, Cloud/DevOps, Database, VPN/Network, and Application Panel categories. Added **HTTP Basic Auth brute force** targeting ports 80/443/8080 across 18 common panel endpoints (`/admin`, `/wp-admin`, `/manager`, `/phpmyadmin`, `/panel`, `/cpanel`, and more) — only activates after a 401 pre-flight check. Added **Telnet service detection** with banner fingerprinting (IAC byte + keyword matching) on port 23. SSH and FTP engines now run via **concurrent goroutines** with a 5-worker semaphore, delivering a significant speed improvement over the previous sequential loop. All findings now include full metadata: service type, port, credentials, and timestamp.

- **SQL Injection Engine — v5.0 "Omni-SQLi" (Complete Rewrite):** Completely overhauled into a six-phase attack pipeline: **(1) Error-Based** with 10 WAF-bypass payload variants (`/*!50000*/`, comment obfuscation, null byte, double-encoding, case variation); **(2) UNION-Based** using `ORDER BY` column-count discovery followed by a `UNION SELECT` canary string injection to confirm data extraction; **(3) Spider Endpoint Integration** replaying GET parameters discovered by the Spider; **(4) Header Injection** fuzzing `User-Agent`, `X-Forwarded-For`, `X-Real-IP`, and `Referer` headers with injection payloads; **(5) Time-Based Blind** for MySQL/PostgreSQL/MSSQL; **(6) POST Auth Bypass** differential analysis. All findings now include a **database fingerprint** (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) extracted from the response body. Body reads are capped at 64KB via `io.LimitReader`.

- **XXE Injection Engine — v2.0 "XML Devil" (Complete Rewrite):** Expanded from a single-endpoint, single-payload check to a **multi-phase XML attack engine**. The module now probes 13 endpoints (`/xml`, `/upload`, `/api`, `/soap`, `/xmlrpc.php`, `/sitemap.xml`, `/parse`, `/feed`, `/rss`, and more) across 3 Content-Type variants (`application/xml`, `text/xml`, `application/soap+xml`). Payload arsenal expanded to 5 types: **(1)** Classic entity reflection; **(2)** Linux LFI via `file:///etc/passwd`; **(3)** Windows LFI via `file:///C:/Windows/win.ini`; **(4)** SSRF via XXE targeting AWS metadata (`169.254.169.254`); **(5)** PHP source code disclosure via `php://filter/convert.base64-encode`. Spider-discovered POST endpoints are also tested. Body reads capped at 128KB.

- **CRLF Injection Engine — v2.0 "Header Hijack" (Complete Rewrite):** Expanded from a single-encoding check to a **tri-phase injection engine**. Encoding arsenal upgraded to 6 variants: standard `%0d%0a`, uppercase `%0D%0A`, Unicode multi-byte `%E5%98%8D%E5%98%8A`, IIS Unicode `%u000d%u000a`, hash-prefix `%23%0d%0a`, and double-percent `%%0d%%0a`. Phase 1 tests URL path injection for `Set-Cookie` header pollution and custom header injection (`X-DORM-Injected`). Phase 2 fuzzes 8 redirect/open-redirect parameters (`redirect`, `url`, `next`, `return`, `dest`, `target`, `redir`, `goto`). Phase 3 adds **XSS-via-CRLF escalation** by injecting `Content-Type: text/html` followed by a `<script>` payload. Spider-discovered endpoints with redirect-like parameters are also tested.

- **NoSQL Injection Engine — v2.0 "Mongo Mayhem" (Complete Rewrite):** Upgraded to an **eight-phase detection pipeline**: **(1)** GET-based `$ne` operator injection (existing, hardened with baseline latency check); **(2)** **JSON Body Injection** sending `application/json` POST payloads (`$gt`, `$ne`, `$exists`, `$regex` operators) to login/auth endpoints; **(3)** **POST Form Injection** using `user[$ne]=x` form-encoded body; **(4)** **`$where` JavaScript Time-Based** — sends `{"$where": "sleep(5000)"}` and confirms execution if attack latency exceeds baseline by 4+ seconds; **(5)** **`$regex` Data Leak Detection** — wildcard regex triggers a measurable response size increase; **(6)** **CouchDB Unauthorized Probe** against `/_users`, `/_all_docs`, `/_config`, `/_utils`; **(7)** Time-Based Boolean (improved); **(8)** Spider POST endpoint integration.

- **SSRF Engine — v2.0 "Cloud Phantom" (Complete Rewrite):** Massively expanded payload surface across five attack groups: **(1)** Cloud metadata for 8 providers (AWS, GCP, Azure, Alibaba, DigitalOcean, Oracle Cloud, AWS ECS); **(2)** **127.0.0.1 WAF Bypass formats** — Hex (`0x7f000001`), Octal (`0177.0.0.0.1`), Decimal (`2130706433`), IPv6 localhost (`[::1]`), IPv4-mapped IPv6, IPv6 zero (`[::]`), Zero IP (`0`), double URL-encoded dot; **(3)** **DNS Rebinding** via wildcard DNS services — `nip.io`, `xip.io`, `sslip.io` for both localhost and AWS metadata; **(4)** **AWS Metadata WAF Bypass** — Hex, Decimal, Octal, and IPv6-mapped representations of `169.254.169.254`; **(5)** **Internal Service Probe** against 8 common ports (Redis/6379, Elasticsearch/9200, PostgreSQL/5432, MySQL/3306, Consul/8500, Docker API/2375, etcd/2379, HTTP/8080); **(6)** **Gopher Protocol Pivot** (`gopher://127.0.0.1:6379/`) and Dict Protocol (`dict://127.0.0.1:6379/info`); **(7)** **OOB Collaborator** integration reading `collab_url` from `models.SharedData` — skips gracefully if not set; **(8)** Spider endpoint integration for redirect/fetch-like parameters. Parameter list expanded from 16 to 30.

- **SSTI Engine — v3.0 "Template Terminator" (Complete Rewrite):** Expanded to **17 engine-specific probes** covering Jinja2 (math canary + string-repeat fingerprint `7*'7'=7777777`), Twig, Freemarker (string method + assign directive), Velocity (`#set`), Smarty (version disclosure + math function), Mako, Ruby ERB, Nunjucks, and a universal polyglot probe. Added **framework fingerprinting** — the detected engine name is embedded in every finding. Added **RCE escalation payloads** for Jinja2 (`os.popen('id')` via Python object chain) and Freemarker (`Execute` class instantiation). Added **error-based detection** capturing template parse exceptions (`TemplateSyntaxError`, `ParseError`, `SmartTemplateException`, etc.). **POST parameter fuzzing** now covers Spider-discovered POST endpoints. Body reads capped at 64KB.

- **MongoDB No Auth — v2.0 "Mongo Wire Inspector" (Complete Rewrite):** Replaced the simple TCP connect check with a **full MongoDB Wire Protocol implementation** (OP_QUERY, opcode 2004) using only the Go standard library — zero new `go.mod` dependencies. Hardcoded BSON payloads are sent for three commands: **(1)** `isMaster` — confirms the service is MongoDB before proceeding; **(2)** `listDatabases` — if the server returns a database list without authentication, a **CRITICAL (CVSS 9.8)** finding is raised with the actual database names extracted from the raw BSON response; **(3)** `buildInfo` — the MongoDB version string is parsed and embedded in all findings. Now also covers **port 27018** (replica set secondary). Three-tier severity model: CRITICAL (unauth DB access) → HIGH (auth required but wire exposed) → HIGH (isMaster-only exposure).

## [v1.12.0] - 2026-05-24

### 🔬 Next-Gen Vulnerability Intelligence & Port Risk Analysis

- **Unnecessary Port Warning (New Plugin):** Introduced a dedicated multi-tier port risk intelligence module that performs deep service classification on every discovered open port. The engine categorizes findings across three severity bands: **HIGH** (legacy cleartext protocols: Telnet/21, FTP/23, SMB/445, RDP/3389, VNC/5900), **MEDIUM** (exposed database engines: MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Memcached, MSSQL, Oracle; DevOps control planes: Docker API, Kubernetes API, RabbitMQ, Consul), and **LOW/MEDIUM** (alternative HTTP ports: 3000, 5000, 8000, 8001, 8888, 9000). For alternative web ports, the plugin actively probes the HTTP response body and `Server`/`X-Powered-By` headers to fingerprint live development server signatures — detecting Webpack Dev Server, Vite, Python Werkzeug, Flask Debug, Django Debug Toolbar, Browsersync, FastAPI Docs, Vue/React DevTools, and hot-module replacement (HMR) indicators before raising an alert.

- **XSS Engine — Next-Gen V4.0 (Complete Rewrite):** Completely overhauled the XSS detection pipeline with a tri-phase architecture:
  - **Phase 1 — Smart Character Reflection Probe:** Before executing full payloads, the engine first probes each parameter by injecting a special canary string containing all dangerous characters (`"`, `'`, `<`, `>`, `/`, `&`). If any of these characters are reflected unencoded in the response body, the module immediately raises a **HIGH** finding with CVSS 8.0, confirming missing output encoding at the framework level.
  - **Phase 1 — Advanced WAF-Bypassing Payload Arsenal (18 payloads):** Expanded the payload set far beyond classic `<script>` tags. The new arsenal includes HTML5 event handler injections (`<details ontoggle>`, `<body onpageshow>`), SVG-based vectors, iframe `javascript:` URI abuse, attribute context breakouts (`onfocus`, `onmouseover`), JavaScript URI WAF-bypass polyglots with CRLF encoding (`%%0D%%0A`), template literal injections, **path traversal–based XSS** (`../../canary"><img>`), null byte injections (`%%00`), Unicode escape bypasses (`\u003c`), CSS context injections, and AngularJS sandbox escapes (`{{constructor.constructor(...)()}}`).
  - **Phase 2 — POST Parameter Fuzzing:** Spider-discovered endpoints are now tested across both GET and POST HTTP methods by injecting XSS payloads directly into form body parameters via `PostForm`, not only URL query strings.
  - **Phase 3 — DOM XSS Static Analysis Engine:** The engine fetches the target's root HTML, extracts all same-origin JavaScript bundle URLs, and performs line-by-line static taint analysis on each file (up to 512KB/file, max 10 files). It maps attacker-controlled **sources** (`location.hash`, `location.search`, `location.pathname`, `document.URL`, `document.referrer`, `window.name`, `localStorage`, `sessionStorage`) flowing into dangerous **sinks** (`document.write`, `innerHTML`, `outerHTML`, `eval`, `setTimeout`, `setInterval`, `new Function`, `.src=`, `.href=`, `import()`, `insertAdjacentHTML`, `setAttribute("on…")`, jQuery/`$` location calls). Proximity analysis extends the detection window to ±5 surrounding lines to catch multi-line patterns.

- **IDOR Engine — Next-Gen V4.0 (Complete Rewrite):** Completely re-engineered the IDOR detection pipeline with a four-phase architecture:
  - **Phase 1 — Dual-Profile Authorization Matrix (Critical New Mechanism):** The engine reads two distinct session tokens from the global state pool (`idor_token_a`, `idor_token_b`). It first performs full resource discovery as **User A** across 18 IDOR-prone endpoint patterns, recording all accessible object IDs and UUIDs. It then replays every request as **User B**, substituting User A's object IDs into the URL or body. If the server returns `200 OK` and the response contains PII keywords, DORM raises a **CRITICAL IDOR (CVSS 9.8)** finding, confirming a broken object-level authorization (BOLA) flaw. UUID-based resources discovered during User A's session are also re-requested under User B's identity, flagging any unauthorized access as **CRITICAL** with CVSS 9.5.
  - **Phase 2 — UUID Harvest & Targeted Fuzzing Engine:** The engine actively harvests UUID values from 13 public-facing pages, error responses, and all HTTP response headers (e.g., `X-Request-ID`, `X-Trace-ID`). Up to 20 unique UUIDs are then systematically tested against 8 privileged API endpoint templates (`/api/v1/delete-profile/[UUID]`, `/api/v1/admin/user/[UUID]`, etc.) with optional User B token injection, confirming whether the application incorrectly treats UUIDs as a security boundary.
  - **Phase 3 — Spider-Driven PII Differential Analysis:** Spider-discovered endpoints are analyzed for ID-like parameters (`id`, `uid`, `user_id`, `account_id`, `doc_id`, `order_id`, `invoice_id`, and 15 other variants). The engine performs a three-way response comparison: a baseline request (ID=1), a target request (ID=2), and a noise baseline (ID=99999999). A finding is raised only when the target response is semantically different from the noise floor (>15% size deviation, minimum 100-byte threshold) **and** the response body contains PII keywords (`email`, `phone`, `username`, `address`, `role`, `password`, `ssn`, `credit_card`, `api_key`, and 15 others), eliminating false positives from generic 200 OK responses.
  - **Phase 4 — GraphQL Introspection & Sub-Field IDOR:** When a `/graphql` endpoint is detected, the engine fires a full schema introspection query and parses the returned AST to map all type definitions. It specifically extracts fields accepting **integer (`Int`) arguments** in nested sub-objects — the exact attack surface where UUID-enforced parent queries expose sequential integer sub-fields. IDOR probes (IDs 1–999) are then injected into these sub-fields (e.g., `query { getUser(id: "uuid") { invoice(id: 1) } }`) under User B's session, flagging any `200 OK` response without an `"errors"` key as a **HIGH** GraphQL sub-field authorization bypass.

## [v1.11.0] - 2026-05-21
### 🛡️ Local CVE Database Segregation & UI Refinement

- **Dedicated CVE Database View (Sidebar Integration):** Completely decoupled the "Offline CVE Radar" from the general plugin pool. Removed it from the `/plugins` dynamic inventory and introduced a premium, high-fidelity **"CVE Veritabanı"** (CVE Database) section directly in the persistent sidebar.
- **Optimized Local DB Search & API Integration:** Created new `/api/cvedb` and `/api/cvedb/search` endpoints on the Go backend to stream memory-cached CISA KEV entries. Built a zero-latency, client-side search engine with dynamic CVSS-based color-coded badges (Critical/High/Medium/Low) and search metrics.
- **Engine Query Routing (`cveRadar`):** Updated the active scan orchestration engine to read the `cveRadar` parameter state on target initialization, dynamically mounting or bypassing the passive CVE signature parser.

## [v1.10.1] - 2026-05-10
### 🪟 Windows Build Tooling & Installation Overhaul

- **Windows Build Script (`build_windows.bat`):** Introduced a dedicated Windows build pipeline. The script validates the Go toolchain (enforcing a minimum of v1.21), fetches all module dependencies via `go mod download`, and compiles a native `DORM.exe` binary in a single execution. Eliminates the need for manual `go get` invocations or `go mod init` on fresh clones.
- **Smart Rebuild Logic:** The build script performs a binary existence check before initiating compilation. If `DORM.exe` is already present, the build phase is skipped entirely, reducing subsequent launch overhead to zero.
- **Process Lifecycle Management:** Prior to each launch, the script issues a `taskkill` against any lingering `DORM.exe` instance, guaranteeing port `8080` is free and preventing socket bind conflicts on repeated invocations.
- **Installation Documentation (README):** Restructured the Installation section into separate Linux/macOS and Windows tracks. The Linux path is reduced to three commands (`git clone` → `go mod download` → `go run .`); the Windows path documents the `build_windows.bat` → `.\DORM.exe` workflow without redundant dependency management steps.
- **`.gitignore` Correction:** Replaced the stale `dorm_engine.exe` entry with the canonical `DORM.exe` artifact name to prevent accidental binary commits.


## [v1.10.0] - 2026-05-08
### 📂 History Archival & Global Management

- **History Archival & Detail Viewer (v2.0):** Completely decoupled scan history from the active dashboard. Past scan records are now loaded into a dedicated, high-end "Detail View" section, preserving the integrity and state of the main scanner while allowing for deep retrospective analysis.
- **Enhanced History Arsenal:** Overhauled the history management table with an elegant, side-by-side action button layout. Introduced a "Global Purge" (Delete All) functionality with a critical confirmation modal for secure bulk data management.
- **Archived Report Generation:** Extended the report engine to support full HTML and PDF export functionality directly from archived history records. Users can now generate professional security reports for any past scan without re-executing the engine.

## [v1.9.0] - 2026-05-02
### 🕷️ Native Analyzer & Smart Spider (Active Fuzzer)

- **Native Proxy Analyzer (New Architecture):** DORM has evolved from a traditional scanner into a full-fledged Dynamic Application Security Testing (DAST) proxy. An internal HTTP Proxy Server (`analyzer` package) now spins up on port `8081` alongside the main engine, intercepting all internal HTTP traffic to perform passive vulnerability analysis without the need for external tools like Burp Suite.
- **Passive Vulnerability Sensors:** The newly integrated `responser.go` module performs real-time, memory-safe (5MB limit) inspection of all proxy traffic. It automatically detects critical Information Leakage (AWS API Keys, Private Keys) and broadcasts findings directly to the DORM dashboard via SSE.
- **Smart Spider (Active Fuzzing Engine):** The Spider module has been completely re-engineered from a simple link crawler into an intelligent endpoint discovery tool. It now performs "Deep Parsing" on HTML `<form>` inputs, POST actions, and dynamically extracts API endpoints hidden within `.js` files using advanced Regex.
- **Shared Endpoint Intelligence:** Spider no longer attacks blindly. It extracts specific URL parameters (e.g., `?id=1`) and stores them in a shared state pool (`models.SharedData`). This prevents rate-limit bans and allows the Spider to act as a recon agent for the rest of the DORM ecosystem.
- **Surgical Exploitation (Plugin Integration):** Four critical, input-dependent plugins—**SQLi, XSS, LFI, and SSTI**—along with **Open Redirect** and **Blind RCE**, have been structurally updated to consume the Spider's intelligence pool. Instead of attacking base URLs, these plugins now execute precision, surgical payload injections directly into the exact endpoints and parameters discovered by the Spider.

## [v1.8.0] - 2026-04-21
### 🧠 Advanced Evasion & AI Scanner Integrations

- **Spider & 403 Coordination (New Feature):** Upgraded the Spider crawler to capture and export `401 Unauthorized` and `403 Forbidden` response paths into a newly localized state cache (`SharedData`). This creates an asynchronous, dynamic target feed for downstream evasion plugins.
- **403/401 Authorization Bypass (New Plugin):** Engineered a high-impact evasion scanner that consumes forbidden endpoints from the Spider. Evaluates access control logic flaws using header manipulation (`X-Forwarded-For`, `X-Rewrite-URL`, etc.) and path normalization exploits (`/%2e/`, `//`).
- **AI/LLM Prompt Injection Scanner (New Plugin):** Introduced a dedicated vulnerability checker targeting modern AI Chat application interfaces (`/chat`, `/api/completions`). It systematically deploys system override and guardrail subversion payloads (e.g. `Ignore all previous instructions...`) to confirm autonomous behavior hijacking.
- **XSS Engine (Critical Bug Fix):** Fixed a severe structural bug in the `XSS (Reflected - Smart)` engine where the HTTP response body was mistakenly closed prior to being read, rendering the canary checks blind. The module now successfully processes response reflections.

## [v1.7.0] - 2026-04-13
### 🎨 Dashboard Overhaul & Fuzzer Engine Removal

- **Luxury Dark UI Redesign:** Completely rebuilt the web dashboard from the ground up with a premium glassmorphism aesthetic. The new interface features a deep cool-dark base (`#0B0F19`), radial ambient gradients, a persistent sidebar layout with animated navigation items, and smooth `fadeUp` transitions on all view switches — replacing the previous minimal layout entirely.
- **Category-Based Plugin Grid (UX):** Overhauled the plugin selection panel into a dynamic, categorized grid populated via the `/plugins` API. Each category renders a group header with a "Select/Deselect All" toggle, and every plugin entry features a custom-styled checkbox that toggles an `active-plugin` highlight state — eliminating the previously broken toggle logic.
- **Fuzzer Engine Removal:** Completely excised the Fuzzer from the active scanning pipeline. The fuzzer plugin registration in `handlers.go` and the "Fuzzer Control Panel" sidebar block have been removed. The `fuzzing.txt` payload file has also been permanently removed. This reduces the attack surface, eliminates a dead code path, and tightens the overall engine surface area.

## [v1.6.0] - 2026-04-10
### 🏗️ Architectural Refactoring & Modular Engine Overhaul

- **Monolithic Decoupling:** Extracted core engine logic, `Start()`, and structural types into `engine.go`, leaving `main.go` strictly for application bootstrapping.
- **API Handler Segregation:** Moved all HTTP endpoint operations (`handleScan`, `handleStop`, `handleHistory`) into a dedicated `handlers.go` file for cleaner API management.
- **Frontend Isolation:** Cleaned up the root directory by migrating all UI assets (`dashboard.html`, `app.js`) into a new structured `/web/` directory.
- **Wordlist Consolidation:** Centralized all heavy reconnaissance dictionaries into a dedicated `/wordlists/` folder to streamline payload execution for the Fuzzer and Spider modules.

## [v1.5.1] - 2026-04-3
### CVE Pattern List Update
- The CVE pattern list has been updated, and critical CVEs have been added.

## [v1.5.0] - 2026-03-26
### 🎯 Precision Intelligence & Deep Fingerprinting Update

- **Semantic Versioning (SemVer) AI Engine:** Completely re-engineered the CVE correlation logic. The new AI-driven engine mathematically parses complex boundary conditions (e.g., "through", "up to", "<=") from the CISA KEV catalog. This guarantees absolute precision and eliminates false negatives when evaluating exact boundary matches against outdated infrastructure.
- **Zero-Latency Tech Stack Profiling:** Deprecated redundant network requests across multiple plugins. Introduced the `DeepScanTarget` engine powered by a concurrent RAM caching architecture (`sync.Map`). It utilizes advanced NLP regex and cookie-based extraction to parse headers and frameworks, serving sanitized `TechNode` intelligence to all plugins in $O(1)$ time complexity.
- **Arbitrary File Upload (Active RCE Validation):** Introduced a highly sophisticated multipart/form-data payload delivery system. The module performs active behavioral analysis to differentiate between safely stored arbitrary files and highly critical Remote Code Execution (RCE) vectors by verifying custom PHP execution signatures.
- **WordPress Infrastructure Enumeration:** Deployed a targeted reconnaissance module designed to extract Core and High-Value Plugin versions (e.g., WooCommerce, Elementor) directly from static assets and `readme` files. Findings are seamlessly piped into the local CVE AI for instant threat correlation.
- **Weak TLS Cipher Suite Probing:** Upgraded the cryptographic analysis engine to perform active TLS handshake manipulation. DORM now forces connections using targeted legacy algorithms to expose servers vulnerable to devastating cryptographic attacks, including SWEET32 (3DES) and RC4 biases.

## [v1.4.3] - 2026-03-21
### CVE Pattern List Update
- The CVE pattern list has been updated, and critical CVEs have been added.


## [v1.4.2] - 2026-03-18
### CVE Pattern List Update
- The CVE pattern list has been completely updated and now uses the official CISA patterns.

## [v1.4.1] - 2026-03-14
### Additional Pattern Update
- 2.000 new CVE patterns have been added.

## [v1.4.0] - 2026-03-12
### ⚡ Intelligence Core & High-Velocity Arsenal Update

- **SQLite Intelligence Engine (Migration):** Deprecated the legacy JSON-based storage for the core vulnerability database. Migrated to a high-performance **SQLite3** backend, implementing SQL Indexing on product/version vectors to achieve $O(1)$ search complexity and zero-RAM overhead for massive datasets.
- **Enterprise CVE Arsenal (1,462+ Signatures):** Integrated a localized threat intelligence repository featuring **1,462+ high-impact CVE patterns**. The engine now performs deep-packet inspection of HTTP headers to identify unpatched technologies (Apache, Nginx, PHP, Redis, etc.) with near-zero false positives.
- **Multi-IP Target Orchestrator:** Expanded the scanner's reach with native support for bulk target processing. The engine can now orchestrate concurrent, non-blocking scans across multiple IP ranges and CIDR blocks, significantly increasing infrastructure coverage.
- **Web Cache Poisoning (New Vector):** Introduced a tactical plugin to identify unkeyed header vulnerabilities. It performs active verification of cache manipulation risks, targeting missing `Vary` headers and identifying potential session compromise via edge-server poisoning.
- **Advanced WAF Fingerprinting (v2.0):** Overhauled the WAF detection module to recognize **10+ industry-standard protection layers** (Cloudflare, Akamai, AWS WAF, Imperva, F5 BIG-IP). The logic now utilizes a hybrid approach, analyzing both response headers and unique HTML error body signatures for 99% accuracy.

## [v1.3.5] - 2026-02-01
### ☁️ Cloud Intelligence & Modern Protocol Update

- **SSRF Omni-Hunter (Multi-Cloud):** Expanded detection capabilities to cover GCP, Azure, DigitalOcean, and Oracle Cloud metadata leaks. Implemented advanced WAF evasion via IP Obfuscation (Decimal/Hex) and Protocol Smuggling (`file://`, `gopher://`).
- **NoSQL Hunter (Polyglot):** Replaced static analysis with **Time-Based** (JavaScript `sleep()`) and **Boolean-Based** blind injection techniques, enabling precise RCE verification on MongoDB and CouchDB.
- **JWT Security Scanner (Pro):** Completely overhauled the engine to perform structural JSON analysis. Features now include **Weak Secret Brute-Force** (HMAC-SHA256) and active "None" algorithm bypass verification.
- **CORS Misconfiguration (Enhanced):** Upgraded logic to detect **Cache Poisoning** risks via missing `Vary: Origin` headers and implemented browser-aware checks for "Wildcard + Credentials" combinations.
- **ColdFusion Exposure (Content-Aware):** Integrated **Signature Verification** to eliminate false positives. The scanner now strictly validates response bodies for specific ColdFusion fingerprints before flagging Debug or Admin panels.

## [v1.3.4] - 2026-01-30
### 🛑 Emergency Stop & Advanced Logic Attack Vectors

- **Emergency Scan Abort (Context-Aware):** Implemented a global cancellation system allowing operators to instantly halt running scans. The engine now gracefully terminates all active goroutines and closes network connections upon receiving the "STOP" signal.
- **HTTP Request Smuggling (The Ghost):** Added a high-criticality plugin to detect CL.TE and TE.CL desynchronization attacks. The module uses raw socket manipulation and interference techniques to identify "poisoned" backend sockets.
- **Race Condition (Limit Breaker):** Introduced a state-mutation concurrency tester. Utilizing a "Gate" synchronization pattern, it fires simultaneous POST requests to critical endpoints and analyzes response anomalies for logical race conditions.
- **Dangerous Methods (Smart Verify):** Upgraded the HTTP Method scanner to perform active verification. It now attempts a full lifecycle check (Upload -> Verify Content -> Delete) to confirm `PUT` method exposure, strictly eliminating false positives.

## [v1.3.3] - 2026-01-25
### 🧠 Intelligent Engine & Core Refinements

- **Online Plugin Suite (Updated):** Major updates to web-based attack vectors including SQLi, XSS, and IDOR. Detection algorithms have been strengthened against modern WAFs.
- **Spider Engine (Optimized):** Crawler regex structure has been optimized. Enhanced capability to detect unquoted attributes and complex link structures.
- **Smart EDB Search:** Exploit-DB module now uses "Smart Keyword Matching" logic for higher accuracy and fewer missed exploits.
- **Shellshock (Advanced Detection):** Switched from static string reflection to mathematical execution verification ($((A+B))) to eliminate False Positives.
- **General Improvements:** Various workflow optimizations and stability fixes were applied to the core engine.

## [v1.3.2] - 2026-01-22
### 🌪️ Advanced Fuzzer & Deep Anomaly Detection

- **Dynamic Fuzzing Engine (Enhanced):** Completely overhauled the fuzzing architecture to support external payload loading via `payloads/fuzzing.txt`, allowing for extensive and customizable attack simulations.
- **Deep Anomaly Detection:** Implemented a multi-vector analysis system that identifies vulnerabilities through Status Code crashes (500), Response Size deviations (>40%), Time Latency (Blind SQLi/DoS), and Input Reflection.
- **Smart Jitter (WAF Evasion):** Integrated a randomized delay mechanism (300ms-1500ms) to mimic organic traffic behavior, significantly improving evasion capabilities against WAFs and Rate Limiters.
- **Dashboard Integration (UX):** Integrated a dedicated "Fuzzer Control Panel" into the sidebar, providing seamless control over active fuzzing operations without disrupting the main scanning workflow.

## [v1.3.1] - 2026-01-20
### 🏗️ Architecture Refactor & Detection Engine Upgrade

- **Frontend Architecture (Refactored):** Decoupled the presentation layer from logic by migrating all JavaScript to a standalone `app.js`. Updated `main.go` to serve static assets, significantly improving maintainability.
- **Node.js Prototype Pollution (v2.0):** Upgraded detection logic to use recursive JSON injection targeting `__proto__` and `constructor` properties, featuring a new canary check mechanism for accurate verification.
- **SSRF Cloud Metadata (v2.0):** Expanded the attack vector list to cover 9 common parameter names (e.g., `dest`, `u`, `uri`) and implemented signature-based detection for critical AWS Metadata (IMDSv1) leakage.

## [v1.3.0] - 2026-01-16
### 🔐 Authentication & Deep Logic Update
- **Authenticated Scanning (New):** Implemented a session-aware scanning engine, enabling the scanner to perform deep vulnerability assessments on endpoints behind login pages.
- **XSS Engine (Refactored):** Upgraded to "Context-Aware" detection logic (v3). Implemented Polyglot payloads and "Canary Token" verification to eliminate false positives caused by sanitization.
- **IDOR / BOLA Logic (Advanced):** Introduced "Differential Analysis" for Broken Access Control. The engine now compares baseline, target, and "Soft-404" responses to validate unauthorized access with high precision.
- **JWT Attack Module (New):** Integrated an automated JWT vulnerability scanner. Features "None" algorithm bypass testing (`alg: none`), token discovery, and signature validation checks.
- **NoSQL Injection (Pro):** Enhanced MongoDB detection using differential response size analysis (`$ne` operator injection) to identify database leakage.
- **SQL Injection (Hardened):** Optimized payload injection patterns to support more complex detection scenarios and reduce noise.

## [v1.2.0] - 2026-01-14
### 🦎 Chameleon, Stealth & Evasion Update
- **Chameleon Mode (Evasion):** Implemented a dynamic User-Agent rotation engine (`UARoundTripper`). The scanner now mimics legitimate browsers (Chrome, Firefox, Safari on Windows/Mac/Linux) to bypass WAF signatures.
- **Smart Rate Limiting (Stability):** Integrated a backend throttling mechanism (default 300ms delay) and optimized worker concurrency (reduced to 10 threads). Prevents unintentional DoS behavior and ensures server stability during scans.
- **Dashboard Controls (UI):** Added a "Chameleon Mode" toggle switch to the sidebar interface, allowing operators to enable/disable evasion tactics in real-time.
- **Engine Optimization (Core):** Refactored the `getClient` logic to support middleware injection, creating a modular base for future proxy integrations.

## [v1.1.0] - 2026-01-13
### 🧠 Persistence, Reporting & Enterprise Logic Update
- **Scan Persistence Engine (New):** Implemented a local JSON-based storage system (`storage.go`). The scanner now automatically saves scan history, enabling retrospective analysis and data persistence across sessions.
- **Enterprise PDF Reporting (Client-Side):** Integrated `jspdf` and `autotable` for generating executive summaries. Reports now feature severity-based color coding (Critical/Red, High/Orange) and auto-formatted tables.
- **Dashboard Logic (Refactored):** Introduced a Sidebar layout with "New Scan" and "History" views. Added real-time status tracking (Running/Completed) to the interface.
- **10x Enterprise Plugins (Logic Expansion):** Added high-impact modules targeting cloud and CI/CD stacks: `SSRF Cloud Metadata` (AWS/GCP), `Terraform State Exposure`, `TeamCity Auth Bypass`, `Citrix ADC Traversal`, and `WebSocket Hijacking`.
- **Core Stability (Fix):** Resolved `strings.Header` type mismatch in Citrix module and cleaned up unused payload variables in SSRF module. Added missing `google/uuid` dependency.

## [v1.0.3] - 2026-01-11
### 🎯 Enterprise Verification & Proof-of-Concept Update
- **F5 BIG-IP RCE (Hardened):** Switched detection strategy from `fileSave.jsp` to `directoryList.jsp`. Vulnerability is now verified by listing internal config files (`web.xml`), eliminating WAF false positives.
- **Spring Boot Actuator (Hardened):** Implemented strict JSON fingerprinting. The scanner now validates `propertySources` and `systemProperties` keys instead of relying on HTTP 200 OK status.
- **Spring Cloud Gateway (Hardened):** Enhanced CVE-2022-22947 detection. Verifies the presence of `predicate` and `route_id` in JSON responses. Severity bumped to CVSS 10.0.
- **Backup File Discovery (Smart):** Added **"Magic Bytes"** verification. The engine now checks file headers (e.g., `PK` for Zip, `1F 8B` for Gzip) to prevent "Soft 404" HTML pages from being flagged as backups.
- **Tomcat Manager (Aggressive):** Added Realm fingerprinting (`WWW-Authenticate`) and automatic default credential testing (`tomcat:s3cret`). Now distinguishes between "Exposed Panel" (High) and "Pwned Panel" (Critical).

## [v1.0.2] - 2026-01-10
### 🛡️ Security & Accuracy Update
- **Security Fix:** Patched a stored Cross-Site Scripting (XSS) vulnerability in the Web Dashboard. All scan results are now properly sanitized before rendering.
- **Logic Hardening (Blind RCE):** Implemented "Baseline Latency Check". The scanner now measures server response time before attacking to prevent false positives on slow networks.
- **Logic Hardening (SSTI):** Updated detection logic to use high-entropy mathematical operations (`1337*1337`) and polyglot payloads, replacing simple `7*7` checks.
- **Logic Hardening (Laravel):** Switched to fingerprinting specific JSON keys (`can_execute_commands`) and JS objects instead of generic text matching.
- **Logic Hardening (Admin Bypass):** Added pre-flight status verification (403/401 checks) before attempting IP spoofing.

## [v1.0.2] - 2026-01-09
### 🧠 Logic Hardening & Accuracy Update
- **Blind RCE Plugin (Updated):** Implemented "Baseline Latency Check". The engine now measures the server's normal response time before attacking. Vulnerability is confirmed only if `Attack Time > (Baseline + Sleep Payload)`. Zero false positives on slow networks.
- **Admin Bypass Plugin (Updated):** Added "Pre-flight Status Verification". The scanner now validates if the target endpoint is actually restricted (403/401) before attempting IP spoofing. Vulnerability is triggered only on a specific status code flip (e.g., 403 -> 200).

## [v1.0.0] - 2026-01-07
### 🚀 Initial Release
- Core Engine launched with concurrent scanning.
- Added 70+ vulnerability plugins.
- Web Dashboard (SSE) implemented.
- Headless Chrome (DOM XSS) module added.
- Exploit-DB integration active.
