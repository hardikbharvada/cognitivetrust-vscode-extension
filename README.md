CognitiveTrust Security Scanner for VS Code

This VS Code extension helps developers write more secure code by identifying and fixing common security anti-patterns in real-time. It uses Semgrep for powerful static analysis and integrates with Google's Gemini API for intelligent, AI-powered refactoring.

Features

Required Features

Real-time Security Scanning: Automatically scans Python and requirements.txt files on open and on save.

Vulnerability Detection:

Hardcoded Secrets: Finds API keys, tokens, and other credentials exposed in the source code.

Missing Authorization: Detects Python Flask routes that may be missing authorization checks.

Outdated Libraries: Scans requirements.txt for packages with known vulnerabilities.

One-Click Fixes: Provides a standard, one-click Quick Fix to replace hardcoded secrets with secure environment variable lookups.

Rescan After Fix: Automatically rescans a file upon saving to confirm that a vulnerability has been successfully resolved.

Optional (Bonus) Features

AI-Powered Refactoring: Offers a "Refactor with Gemini ✨" Quick Fix for all detected issues, providing context-aware solutions for secrets, missing authorization, and outdated dependencies.

Scan History & Metrics: Logs every scan and tracks the total number of fixes applied. This data can be viewed at any time.

Full Workspace Scanning: Includes a command to scan every supported file in the entire workspace at once, populating the "Problems" panel with a complete security overview.

Setup & Installation

Prerequisites

VS Code: Version 1.85 or newer.

Node.js: Version 18.x or newer.

Python: Version 3.8 or newer.

Semgrep: The core scanning engine. Install it via pip:

pip install semgrep


Installation

Clone the Repository:

git clone <your-repository-url>
cd <your-repository-directory>


Install Dependencies:

npm install


How to Use

Running the Extension

Open the project folder in VS Code.

Press F5 to open a new Extension Development Host window with the extension running.

Using the Features

Automatic Scanning: Simply open a .py file or a requirements.txt file. Any vulnerabilities will be highlighted with a squiggly line. Hover over the line to see the issue description.

Applying a Quick Fix:

Click on a line with a warning.

Click the lightbulb icon that appears, or press Ctrl + . (period).

Choose either the standard fix (if available) or "Refactor with Gemini ✨".

Using the Gemini AI Fix (First Time):

The first time you select the Gemini fix, an input box will appear at the top of the screen.

Paste your Google AI Gemini API Key and press Enter. The key will be stored securely for future use.

Available Commands

Open the Command Palette (Ctrl+Shift+P or Cmd+Shift+P) and type "CognitiveTrust" to access these commands:

CognitiveTrust: Scan Entire Workspace: Scans all .py and requirements.txt files in your project.

CognitiveTrust: Show Scan History: Opens an output panel with a log of recent scans and the total number of fixes applied.

CognitiveTrust: Clear API Key: Removes your stored Gemini API key, allowing you to enter a new one.