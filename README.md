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

<img width="838" height="864" alt="1" src="https://github.com/user-attachments/assets/4c64c5a2-3f5a-4531-b209-cd6154443695" />
**Scan a specific file:**
```bash

python3 codetirt.py filename.py

## Creating Report
<img width="790" height="542" alt="2" src="https://github.com/user-attachments/assets/9ea9d439-4b2e-4213-9991-b5737af8b707" />

After the scan is complete, the tool will prompt you to save the results:

Generate report? (y/n)

y (Yes): Saves the full scan summary and findings to a text file (e.g., scan_report.txt) in the current directory.

n (No): Displays the results in the terminal only and exits.
<img width="720" height="519" alt="3" src="https://github.com/user-attachments/assets/de09180d-e9a5-41c8-8bce-deace6a93994" />
