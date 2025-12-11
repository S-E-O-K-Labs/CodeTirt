# CodeTirt

CodeTirt is a lightweight Static Application Security Testing (SAST) tool designed to quickly scan **Python, Node.js, and PHP** projects for common security vulnerabilities directly from your Linux terminal.

## Features

CodeTirt detects the following security issues:

* **SQL Injection:** Insecure database queries.
* **XSS (Cross-Site Scripting):** Dangerous HTML/JS outputs.
* **Command Injection:** Risky system commands (e.g., `os.system`).
* **Code Injection:** Dynamic code execution functions (e.g., `eval()`, `exec()`).
* **Hardcoded Secrets:** Forgotten passwords, tokens, and API keys in source code.
* **Path Traversal:** Insecure file path handling.
* **Debug Mode:** Active debug configurations in production code.

## Requirements

* **Operating System:** Linux (Terminal/Bash)
* **Runtime:** Python 3.x
* **Dependencies:** None (No `pip install` required). Uses standard libraries only.

## Installation

1.  Clone the repository or download the `codetirt.py` file.
2.  Make sure the script is in your working directory or added to your path.
3.  Grant execution permissions (optional but recommended):
    ```bash
    chmod +x codetirt.py
    ```

## Usage

Open your Linux terminal and run the tool using Python 3.

**Scan a specific file:**
```bash

python3 codetirt.py filename.py

