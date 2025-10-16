# 🧠 CognitiveTrust Security Scanner for VS Code

The **CognitiveTrust Security Scanner** is a Visual Studio Code extension that helps developers write more secure Python code by detecting and fixing common security anti-patterns in real time.  
It leverages **Semgrep** for static code analysis and integrates with **Google’s Gemini API** for intelligent, AI-powered code refactoring.

---

## 🚀 Features

### ✅ Required Features

#### 🔍 Real-Time Security Scanning
Automatically scans **Python (`.py`)** and **`requirements.txt`** files on open and save.

#### 🧩 Vulnerability Detection
- **Hardcoded Secrets:** Detects exposed API keys, tokens, and credentials in the source code.  
- **Missing Authorization:** Identifies Python Flask routes that may lack proper authorization checks.  
- **Outdated Libraries:** Flags vulnerable dependencies listed in `requirements.txt`.

#### ⚡ One-Click Fixes
Provides a **Quick Fix** to automatically replace hardcoded secrets with secure `os.getenv()` lookups.

#### 🔄 Rescan After Fix
Automatically rescans the file on save to confirm that vulnerabilities have been resolved.

---

### 💎 Optional (Bonus) Features

#### 🤖 AI-Powered Refactoring (Gemini Integration)
Offers a **“Refactor with Gemini ✨”** Quick Fix option that uses Google’s Gemini API to intelligently rewrite insecure code, suggesting context-aware security improvements.

#### 📊 Scan History & Metrics
Maintains a log of every scan, tracking the number of findings and fixes applied.  
Use the “Show Scan History” command to review past metrics.

#### 🌐 Full Workspace Scanning
Provides a **“Scan Entire Workspace”** command to analyze all supported files across your project and display consolidated results in the **Problems panel**.

---

## ⚙️ Setup & Installation

### 🧾 Prerequisites

- **VS Code:** version `1.85` or newer  
- **Node.js:** version `18.x` or newer  
- **Python:** version `3.8` or newer  
- **Semgrep:** install via pip  
  ```bash
  pip install semgrep
