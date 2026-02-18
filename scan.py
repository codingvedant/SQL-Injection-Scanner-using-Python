#!/usr/bin/env python3
"""
SQL Injection Scanner - A security tool to detect SQL injection vulnerabilities
in web applications by analyzing forms and testing injection payloads.
"""

import argparse
import sys
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# SQL error signatures that indicate potential injection
SQL_ERROR_SIGNATURES = {
    "quoted string not properly terminated",
    "unclosed quotation mark after the character string",
    "you have an error in your sql syntax",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "pg_query()",
    "pg_exec()",
    "ora_",
    "oracle error",
    "sqlite_",
    "syntax error",
    "warning: pg_",
    "warning: mysql_",
    "valid mysql result",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "sqlserver jdbc driver",
    "postgresql.*driver",
    "drivers.*jdbc",
    "odbc.*driver",
    "sql syntax.*mysql",
    "syntax error.*postgresql",
    "warning:.*\\\\.*syntax",
    "unexpected end of sql command",
    "sql command not properly ended",
    "ora-01",
    "ora-01756",
    "syntax error or access violation",
}

# Common SQL injection payloads for testing
SQL_PAYLOADS = ["'", '"', "' OR '1'='1", '" OR "1"="1', "1' OR '1'='1", "1 OR 1=1"]


def create_session(timeout: int = 10) -> requests.Session:
    """Create a configured requests session with appropriate headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    session.timeout = timeout
    return session


def get_forms(session: requests.Session, url: str) -> list:
    """Extract all forms from a given URL."""
    try:
        response = session.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except requests.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")
        return []


def form_details(form) -> dict:
    """Extract details from an HTML form (action, method, inputs)."""
    action = form.attrs.get("action") or ""
    method = (form.attrs.get("method") or "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        if input_tag.attrs.get("name") is None:
            continue
        inputs.append({
            "type": input_tag.attrs.get("type", "text"),
            "name": input_tag.attrs.get("name"),
            "value": input_tag.attrs.get("value", ""),
        })

    return {"action": action, "method": method, "inputs": inputs}


def is_vulnerable(response: requests.Response) -> bool:
    """Check if the response contains SQL error signatures indicating injection."""
    try:
        text = response.content.decode(errors="ignore").lower()
        return any(sig in text for sig in SQL_ERROR_SIGNATURES)
    except (UnicodeDecodeError, AttributeError):
        return False


def build_form_url(base_url: str, action: str) -> str:
    """Resolve the full URL for form submission."""
    if not action:
        return base_url
    return urljoin(base_url, action)


def scan_form(
    session: requests.Session,
    base_url: str,
    form,
    verbose: bool = False,
) -> list[str]:
    """Scan a single form for SQL injection vulnerabilities."""
    details = form_details(form)
    vulnerabilities = []

    if not details["inputs"]:
        return vulnerabilities

    form_url = build_form_url(base_url, details["action"])

    for payload in SQL_PAYLOADS:
        data = {}
        for inp in details["inputs"]:
            if inp["type"] in ("submit", "button", "image"):
                continue
            if inp["type"] == "hidden":
                data[inp["name"]] = inp["value"] + payload
            else:
                data[inp["name"]] = payload

        try:
            if details["method"] == "post":
                response = session.post(form_url, data=data)
            else:
                response = session.get(form_url, params=data)

            if is_vulnerable(response):
                vuln_msg = f"Payload: {payload!r}"
                vulnerabilities.append(vuln_msg)
                if verbose:
                    print(f"    [VULN] {vuln_msg}")
        except requests.RequestException as e:
            if verbose:
                print(f"    [!] Request failed: {e}")

    return vulnerabilities


def scan_url(
    url: str,
    timeout: int = 10,
    verbose: bool = False,
) -> dict:
    """Scan a URL for SQL injection vulnerabilities in forms."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    session = create_session(timeout)
    results = {"url": url, "forms": 0, "vulnerabilities": []}

    forms = get_forms(session, url)
    results["forms"] = len(forms)

    if verbose:
        print(f"\n[*] Found {len(forms)} form(s) on {url}\n")

    for i, form in enumerate(forms, 1):
        if verbose:
            print(f"[*] Scanning form {i}/{len(forms)}...")
        vulns = scan_form(session, url, form, verbose)
        if vulns:
            results["vulnerabilities"].append({
                "form": i,
                "payloads": vulns,
            })

    return results


def print_report(results: dict) -> None:
    """Print a summary report of the scan results."""
    print("\n" + "=" * 60)
    print("SQL INJECTION SCAN REPORT")
    print("=" * 60)
    print(f"Target URL: {results['url']}")
    print(f"Forms analyzed: {results['forms']}")
    print("-" * 60)

    if results["vulnerabilities"]:
        print(f"[!] VULNERABLE: {len(results['vulnerabilities'])} form(s) may be susceptible")
        for v in results["vulnerabilities"]:
            print(f"    Form {v['form']}: {', '.join(v['payloads'])}")
        print("=" * 60)
        sys.exit(1)
    else:
        print("[+] No SQL injection vulnerabilities detected (based on error signatures)")
        print("=" * 60)
        sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SQL Injection Scanner - Detect SQL injection vulnerabilities in web forms",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scan.py https://example.com/login
  python scan.py https://testphp.vulnweb.com -v
  python scan.py example.com --timeout 15
        """,
    )
    parser.add_argument(
        "url",
        help="Target URL to scan (e.g., https://example.com)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )

    args = parser.parse_args()

    print(f"[*] Starting SQL injection scan on {args.url}")
    results = scan_url(args.url, timeout=args.timeout, verbose=args.verbose)
    print_report(results)


if __name__ == "__main__":
    main()
