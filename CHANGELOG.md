# Changelog

All notable changes to this project will be documented in this file.

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
