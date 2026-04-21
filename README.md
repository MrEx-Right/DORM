# 👁️ DORM - Next-Gen Vulnerability Scanner

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-GPLv3-blue)
![Type](https://img.shields.io/badge/Type-Offensive%20Security-red)

**DORM** is a high-performance, concurrent, and modular vulnerability scanner written in **Go**. Designed for Red Teams and Bug Bounty hunters, it combines passive reconnaissance with active, aggressive exploitation techniques.

Unlike traditional scanners, DORM features a hybrid engine that utilizes **Headless Chrome (DOM XSS)**, **Smart Fuzzing**, and **In-Memory Exploit-DB** integration.

---

## ✨ Dashboard Preview

### 🖥️ Scanner Interface
<p align="center">
  <img src="docs/images/dashboard1.png" alt="Main Interface" width="100%">
</p>

### 📊 Live Results
<p align="center">
  <img src="docs/images/dashboard2.png" alt="Results Interface" width="100%">
</p>

<p align="center">
  <i>Real-time monitoring and advanced vulnerability detection capabilities.</i>
</p>

---

## 🚀 Key Features

### 🔥 Core Engine
- **High Concurrency:** Scans multiple targets and ports simultaneously using Go routines.
- **Smart Port Discovery:** Automatically detects web, database, and cloud services.
- **Real-Time Dashboard:** Web-based UI (SSE) to monitor scan progress live.

### 🧠 Advanced Capabilities
- **🕷️ Web Spider:** Recursively crawls the target to map the attack surface.
- **🕸️ DOM XSS Scanner:** Uses **Headless Chrome** to detect JavaScript-based vulnerabilities in SPA (React/Vue).
- **📚 Exploit-DB Integration:** Loads the entire Exploit Database into RAM for instant service version matching.
- **🔓 Brute Force (Mini-Hydra):** Supports dictionary attacks on SSH and FTP.

### 🛡️ 80+ Attack Modules
DORM comes with over 80 specialized plugins including:
- **Injection:** SQLi (Blind/Time), XSS (Reflected/DOM), SSTI, CRLF, Host Header.
- **Cloud & DevOps:** Docker API, Kubernetes Kubelet, AWS/Google Key Leaks, S3 Buckets.
- **Critical CVEs:** Log4Shell, Spring4Shell, Drupalgeddon2, F5 BIG-IP TMUI.
- **Misconfig:** CORS, Git/Env Exposure, Open Redirects, Subdomain Takeover.

---

## 📦 Installation

DORM requires **Go 1.21+** and **Google Chrome** (for DOM Scanner).

```bash
# 1. Clone the repository
git clone https://github.com/MrEx-Right/DORM.git
cd DORM

# 2. Initialize the module
go mod init DORM

# 3. Install dependencies
go get [github.com/chromedp/chromedp](https://github.com/chromedp/chromedp)
go get [github.com/jlaffaye/ftp](https://github.com/jlaffaye/ftp)
go get golang.org/x/crypto/ssh
go get github.com/google/uuid

# 4. Run DORM
go run .
