# Changelog

All notable changes to this project will be documented in this file.

## [v1.0.1] - 2026-01-09
### 🧠 Logic Hardening & Accuracy Update
- **Blind RCE Plugin (Updated):** Implemented "Baseline Latency Check". The engine now measures the server's normal response time before attacking. Vulnerability is confirmed only if `Attack Time > (Baseline + Sleep Payload)`. Zero false positives on slow networks.
- **Admin Bypass Plugin (Updated):** Added "Pre-flight Status Verification". The scanner now validates if the target endpoint is actually restricted (403/401) before attempting IP spoofing. Vulnerability is triggered only on a specific status code flip (e.g., 403 -> 200).
