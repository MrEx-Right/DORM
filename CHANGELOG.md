# Changelog

All notable changes to this project will be documented in this file.

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
