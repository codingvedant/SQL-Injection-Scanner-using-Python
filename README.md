# SQL Injection Scanner

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight Python security tool that detects SQL injection vulnerabilities in web applications by analyzing HTML forms and testing common injection payloads. Built for **ethical hacking**, **penetration testing**, and **security research**.

> ⚠️ **Legal Notice**: Only use this tool on systems you own or have explicit authorization to test. Unauthorized access to computer systems is illegal.

## Features

- **Form detection** — Automatically discovers and analyzes all forms on a target URL
- **Multiple payloads** — Tests various SQL injection patterns (quotes, OR-based, etc.)
- **Error-based detection** — Identifies vulnerabilities through database error signatures (MySQL, PostgreSQL, SQL Server, Oracle, SQLite)
- **CLI interface** — Simple command-line usage with configurable options
- **Verbose mode** — Detailed output for debugging and learning
- **Zero config** — Works out of the box with minimal dependencies

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/SQL-Injection-Scanner-using-Python.git
cd SQL-Injection-Scanner-using-Python

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python scan.py https://example.com

# Verbose output (shows each payload tested)
python scan.py https://example.com -v

# Custom timeout (seconds)
python scan.py https://example.com --timeout 15

# URL without protocol (https:// will be prepended)
python scan.py example.com
```

### Options

| Option | Short | Description |
|--------|-------|-------------|
| `--verbose` | `-v` | Enable verbose output |
| `--timeout` | `-t` | Request timeout in seconds (default: 10) |

## How It Works

1. **Fetch & Parse** — Retrieves the target page and parses all `<form>` elements
2. **Extract Details** — Collects action URL, HTTP method (GET/POST), and input fields
3. **Inject Payloads** — Submits each form with SQL injection test strings
4. **Analyze Response** — Looks for database error signatures in the response
5. **Report** — Summarizes findings with vulnerable forms and triggering payloads

### Error Signatures Detected

The scanner checks for common SQL error patterns from:

- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite
- Generic ODBC/JDBC drivers

## Example Output

```
[*] Starting SQL injection scan on https://testphp.vulnweb.com
[*] Found 2 form(s) on https://testphp.vulnweb.com
[*] Scanning form 1/2...
[*] Scanning form 2/2...

============================================================
SQL INJECTION SCAN REPORT
============================================================
Target URL: https://testphp.vulnweb.com
Forms analyzed: 2
------------------------------------------------------------
[!] VULNERABLE: 1 form(s) may be susceptible
    Form 1: Payload: "'"
============================================================
```

## Testing

For educational testing, consider using intentionally vulnerable applications:

- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web Application)
- [bWAPP](http://www.itsecgames.com/)

## Project Structure

```
SQL-Injection-Scanner-using-Python/
├── scan.py           # Main scanner script
├── requirements.txt  # Python dependencies
├── README.md         # This file
└── LICENSE           # MIT License
```

## Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. The authors are not responsible for misuse or damage caused by this software. Always obtain proper authorization before testing any system.
