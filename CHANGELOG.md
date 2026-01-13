# Changelog

All notable changes to this project will be documented in this file.

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
