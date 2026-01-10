# Changelog

All notable changes to this project will be documented in this file.

## 🛡️ v1.0.2 - Accuracy & Self-Defense Update

This release focuses on **eliminating false positives** in critical plugins and **hardening the scanner's own dashboard** against client-side attacks. DORM is now smarter in detection and safer to use.

### 🧠 Logic & Core Improvements (Zero False Positives)
* **SSTI Plugin (Professionalized):** * Replaced simple math checks (`7*7`) with unique high-entropy calculations (`1337*1337=1787569`) to prevent accidental matches on product IDs or prices.
    * Added Polyglot support for Jinja2, Smarty, FreeMarker, and ERB engines.
* **Laravel Debug Plugin (Fingerprinting):** * Moved away from simple text matching ("Whoops"). Now validates vulnerabilities by parsing specific JSON keys (`can_execute_commands`) and JavaScript objects (`window.ignition`).
* **Blind RCE / SSRF Logic:** * Implemented **"Baseline Latency Check"**. The engine now measures the server's natural response time before attacking. Vulnerability is only reported if `Attack Time > (Baseline + Sleep Payload)`.

### 🔒 Security Fixes (Self-Protection)
* **Dashboard XSS Patch:** * Fixed a **Self-XSS** vulnerability in the Web Dashboard.
    * All incoming scan data (`Name`, `Description`, `Target`) is now strictly sanitized using an `escapeHtml()` wrapper before rendering. Malicious server responses can no longer execute JavaScript in the operator's browser.

---

**Full Changelog**: https://github.com/yourusername/dorm/compare/v1.0.1...v1.0.2
