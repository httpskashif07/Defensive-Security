#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner
For authorized security testing only.
"""

import argparse
import sys
import time
import re
import json
import urllib.parse
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from html import escape as html_escape

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[!] Missing dependency: pip install requests")

try:
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("[!] Missing dependency: pip install beautifulsoup4")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title: str
    severity: str          # High / Medium / Low / Info
    url: str
    description: str
    evidence: str
    remediation: str
    category: str


@dataclass
class ScanResult:
    target: str
    start_time: str
    end_time: str = ""
    pages_crawled: int = 0
    findings: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REQUEST_DELAY   = 0.5      # seconds between requests
REQUEST_TIMEOUT = 10       # seconds per request
MAX_PAGES       = 100      # crawler page cap
HEADERS = {
    "User-Agent": "Mozilla/5.0 (VulnScanner/1.0; authorized-security-testing)"
}

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
]

SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1; SELECT SLEEP(0)--",
    "1 AND 1=1",
    "1 AND 1=2",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "syntax error",
    "unclosed quotation", "sqlite_", "pg_query", "you have an error in your sql",
    "warning: mysql", "odbc", "jdbc", "sqlexception", "sqlstate",
    "microsoft ole db", "driver.*sql.*server", "unterminated string",
    "supplied argument is not a valid mysql", "division by zero",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https:evil.example.com",
]

REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnurl", "return_url",
    "redirect_uri", "redirect_url", "goto", "target", "destination",
    "rurl", "dest", "destination", "location", "back",
]

DIRECTORY_WORDLIST = [
    # Admin / management
    "admin", "administrator", "admins", "admin1", "adminpanel",
    "admin/login", "admin/dashboard", "admin/users", "admin/config",
    "manager", "management", "manage", "moderator", "superuser",
    "backend", "backoffice", "controlpanel", "cpanel", "webmaster",
    "staff", "ops", "internal",
    # Authentication
    "login", "signin", "signup", "register", "logout", "auth",
    "oauth", "sso", "account", "accounts", "profile", "user", "users",
    "password", "reset", "forgot",
    # API
    "api", "api/v1", "api/v2", "api/v3", "api/health", "api/status",
    "api/docs", "api/swagger", "swagger", "swagger-ui", "graphql",
    "rest", "rpc", "webhooks", "callback",
    # Dev / debug
    "debug", "dev", "devel", "development", "staging", "test", "testing",
    "demo", "sandbox", "qa", "uat", "beta", "alpha",
    "console", "shell", "terminal", "logs", "log", "errors", "error",
    "trace", "metrics", "healthz", "health", "ping", "status", "version",
    "info", "about",
    # Config / source
    "config", "configuration", "settings", "setup", "install", "installer",
    "deploy", "deployment",
    # Files / uploads
    "upload", "uploads", "files", "file", "media", "assets",
    "static", "public", "private", "downloads", "download",
    "images", "img", "css", "js", "fonts", "icons",
    "attachments", "docs", "documents", "data",
    # Backup / archive
    "backup", "backups", "bak", "old", "archive", "archives",
    "tmp", "temp", "cache",
    # Database
    "db", "database", "mysql", "phpmyadmin", "adminer", "pma",
    "mongo", "redis", "elastic",
    # Common app sections
    "dashboard", "home", "index", "main", "portal", "app",
    "search", "help", "support", "contact", "about", "faq",
    "news", "blog", "forum", "shop", "store", "cart", "checkout",
    "payment", "billing", "invoice", "order", "orders",
    "report", "reports", "stats", "statistics", "analytics",
    # Server / infra
    "server-status", "server-info", "nginx_status", "phpinfo",
    ".well-known", ".well-known/security.txt", ".well-known/acme-challenge",
    "cgi-bin", "scripts", "bin", "includes", "include", "lib",
    "vendor", "node_modules", "wp-admin", "wp-content", "wp-includes",
    "wp-login.php", "xmlrpc.php",
    # Version control / CI
    ".svn", ".hg", ".git",
    "jenkins", "gitlab", "bitbucket", "ci", "build", "dist",
    # Monitoring
    "kibana", "grafana", "prometheus", "jaeger", "zipkin",
]

SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
    "config.php", "config.yml", "config.yaml", "config.json",
    "database.yml", "settings.py", "wp-config.php",
    "backup.sql", "backup.zip", "backup.tar.gz", "db_backup.sql",
    "admin/", "phpmyadmin/", "adminer.php",
    "robots.txt", "sitemap.xml", ".htaccess", "web.config",
    "composer.json", "package.json", "requirements.txt",
    "phpinfo.php", "info.php", "test.php",
    "dump.sql", "database.sql", "data.sql",
    ".DS_Store", "thumbs.db",
    "README.md", "CHANGELOG.md",
]

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Content-Security-Policy (CSP) is missing. CSP prevents XSS and data injection attacks by declaring approved content sources.",
        "remediation": "Add a Content-Security-Policy header, e.g.: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "X-Frame-Options is missing. Without this header the page can be embedded in an iframe, enabling clickjacking attacks.",
        "remediation": "Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
    },
    "X-XSS-Protection": {
        "severity": "Low",
        "description": "X-XSS-Protection is missing or disabled. This header activates the browser's built-in XSS filter (legacy browsers).",
        "remediation": "Add X-XSS-Protection: 1; mode=block",
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "description": "HTTP Strict-Transport-Security (HSTS) is missing. Without HSTS, the site is vulnerable to SSL stripping and protocol downgrade attacks.",
        "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "description": "X-Content-Type-Options is missing. Browsers may MIME-sniff responses, potentially executing uploaded files as scripts.",
        "remediation": "Add X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Referrer-Policy is missing. Sensitive URL data may leak to third parties via the Referer header.",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Permissions-Policy (formerly Feature-Policy) is missing. Browser features like camera, microphone, and geolocation are unrestricted.",
        "remediation": "Add Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
}


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

class HttpClient:
    def __init__(self, delay: float = REQUEST_DELAY):
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False

    def get(self, url: str, params: Optional[dict] = None, allow_redirects: bool = True) -> Optional[requests.Response]:
        time.sleep(self.delay)
        try:
            return self.session.get(url, params=params, timeout=REQUEST_TIMEOUT,
                                    allow_redirects=allow_redirects)
        except requests.RequestException:
            return None

    def post(self, url: str, data: dict) -> Optional[requests.Response]:
        time.sleep(self.delay)
        try:
            return self.session.post(url, data=data, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            return None


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

def normalize_url(url: str, base: str) -> Optional[str]:
    """Resolve relative URLs and strip fragments. Returns None for non-HTTP/off-site links."""
    url = url.strip()
    if not url or url.startswith(("#", "mailto:", "tel:", "javascript:")):
        return None
    resolved = urllib.parse.urljoin(base, url)
    parsed = urllib.parse.urlparse(resolved)
    base_parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in ("http", "https"):
        return None
    # Stay on the same host
    if parsed.netloc != base_parsed.netloc:
        return None
    # Drop fragment
    clean = parsed._replace(fragment="").geturl()
    return clean


def extract_forms(soup: BeautifulSoup, page_url: str) -> list[dict]:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").lower()
        action_url = urllib.parse.urljoin(page_url, action) if action else page_url
        inputs = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                inputs.append({
                    "name": name,
                    "type": tag.get("type", "text"),
                    "value": tag.get("value", "test"),
                })
        forms.append({"action": action_url, "method": method, "inputs": inputs})
    return forms


def crawl(base_url: str, client: HttpClient) -> tuple[set[str], list[dict]]:
    """BFS crawler. Returns (visited_urls, list_of_forms)."""
    visited: set[str] = set()
    queue: list[str] = [base_url]
    all_forms: list[dict] = []

    print(f"\n[*] Crawling {base_url} ...")

    while queue and len(visited) < MAX_PAGES:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        print(f"    -> {url}")

        resp = client.get(url)
        if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        # Collect forms
        all_forms.extend(extract_forms(soup, url))

        # Collect links
        for tag in soup.find_all("a", href=True):
            link = normalize_url(tag["href"], url)
            if link and link not in visited:
                queue.append(link)

    print(f"[*] Crawl complete: {len(visited)} pages, {len(all_forms)} forms found.")
    return visited, all_forms


# ---------------------------------------------------------------------------
# Security Header Scanner
# ---------------------------------------------------------------------------

def scan_headers(url: str, client: HttpClient) -> list[Finding]:
    findings = []
    resp = client.get(url)
    if not resp:
        print(f"[!] Could not fetch {url} for header scan.")
        return findings

    print("\n[*] Scanning security headers ...")
    resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for header, meta in SECURITY_HEADERS.items():
        if header.lower() not in resp_headers_lower:
            findings.append(Finding(
                title=f"Missing Security Header: {header}",
                severity=meta["severity"],
                url=url,
                description=meta["description"],
                evidence=f"Header '{header}' not present in HTTP response.",
                remediation=meta["remediation"],
                category="Security Headers",
            ))
            print(f"    [MISSING {meta['severity']}] {header}")
        else:
            print(f"    [OK] {header}: {resp_headers_lower[header.lower()]}")

    # Extra: flag server version disclosure
    server = resp.headers.get("Server", "")
    if server and any(c.isdigit() for c in server):
        findings.append(Finding(
            title="Server Version Disclosure",
            severity="Low",
            url=url,
            description=f"The Server header discloses version information: '{server}'. This aids fingerprinting.",
            evidence=f"Server: {server}",
            remediation="Configure the web server to omit version details from the Server header.",
            category="Information Disclosure",
        ))

    return findings


# ---------------------------------------------------------------------------
# XSS Detection
# ---------------------------------------------------------------------------

def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return parsed._replace(query=new_query).geturl()


def scan_xss(pages: set[str], forms: list[dict], client: HttpClient) -> list[Finding]:
    findings = []
    seen: set[str] = set()
    print("\n[*] Testing for XSS ...")

    # Test URL parameters
    for url in pages:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            continue
        for param in params:
            for payload in XSS_PAYLOADS:
                test_url = _inject_param(url, param, payload)
                key = f"GET|{url}|{param}|{payload}"
                if key in seen:
                    continue
                seen.add(key)
                resp = client.get(test_url)
                if resp and payload in resp.text:
                    print(f"    [HIGH] XSS reflected in GET param '{param}' at {url}")
                    findings.append(Finding(
                        title=f"Reflected XSS in GET parameter '{param}'",
                        severity="High",
                        url=test_url,
                        description=(
                            f"The parameter '{param}' reflects user input unsanitized in the HTML response. "
                            "An attacker can craft a malicious URL that executes arbitrary JavaScript in the victim's browser."
                        ),
                        evidence=f"Payload '{payload}' was reflected verbatim in the response body.",
                        remediation=(
                            "Encode all output using context-appropriate encoding (HTML entity encoding for HTML context). "
                            "Implement a Content-Security-Policy. Use a framework that auto-escapes template output."
                        ),
                        category="XSS",
                    ))
                    break  # one finding per param is enough

    # Test form inputs
    for form in forms:
        if not form["inputs"]:
            continue
        for payload in XSS_PAYLOADS:
            data = {inp["name"]: payload for inp in form["inputs"]}
            key = f"FORM|{form['action']}|{payload}"
            if key in seen:
                continue
            seen.add(key)

            if form["method"] == "post":
                resp = client.post(form["action"], data)
            else:
                resp = client.get(form["action"], params=data)

            if resp and payload in resp.text:
                names = ", ".join(inp["name"] for inp in form["inputs"])
                print(f"    [HIGH] XSS reflected in form field(s) '{names}' at {form['action']}")
                findings.append(Finding(
                    title=f"Reflected XSS in Form ({form['method'].upper()} {form['action']})",
                    severity="High",
                    url=form["action"],
                    description=(
                        f"Form field(s) '{names}' reflect user input unsanitized in the HTML response."
                    ),
                    evidence=f"Payload '{payload}' was reflected verbatim in the response body.",
                    remediation=(
                        "Sanitize and encode all user-supplied data before rendering it in HTML. "
                        "Use templating engines with auto-escaping (e.g., Jinja2 autoescape=True). "
                        "Implement a strict Content-Security-Policy."
                    ),
                    category="XSS",
                ))
                break

    return findings


# ---------------------------------------------------------------------------
# SQL Injection Detection
# ---------------------------------------------------------------------------

def scan_sqli(pages: set[str], forms: list[dict], client: HttpClient) -> list[Finding]:
    findings = []
    seen: set[str] = set()
    print("\n[*] Testing for SQL Injection ...")

    def _check_sqli(resp: Optional[requests.Response], context: str) -> bool:
        if not resp:
            return False
        body_lower = resp.text.lower()
        return any(err in body_lower for err in SQLI_ERRORS)

    # URL parameters
    for url in pages:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            continue
        for param in params:
            for payload in SQLI_PAYLOADS:
                key = f"GET|{url}|{param}|sqli"
                if key in seen:
                    continue
                seen.add(key)
                test_url = _inject_param(url, param, payload)
                resp = client.get(test_url)
                if _check_sqli(resp, f"GET param '{param}'"):
                    print(f"    [HIGH] SQLi indicator in GET param '{param}' at {url}")
                    findings.append(Finding(
                        title=f"Possible SQL Injection in GET parameter '{param}'",
                        severity="High",
                        url=test_url,
                        description=(
                            f"The parameter '{param}' triggered a database error message when injected with "
                            f"the payload '{payload}'. This suggests unsanitized input is reaching SQL queries."
                        ),
                        evidence=f"Database error pattern detected in response when sending: {payload}",
                        remediation=(
                            "Use parameterized queries / prepared statements exclusively. "
                            "Never concatenate user input into SQL strings. "
                            "Apply the principle of least privilege to database accounts. "
                            "Use an ORM that handles escaping automatically."
                        ),
                        category="SQL Injection",
                    ))
                    break

    # Forms
    for form in forms:
        if not form["inputs"]:
            continue
        for payload in SQLI_PAYLOADS:
            key = f"FORM|{form['action']}|sqli"
            if key in seen:
                continue
            seen.add(key)
            data = {inp["name"]: payload for inp in form["inputs"]}
            if form["method"] == "post":
                resp = client.post(form["action"], data)
            else:
                resp = client.get(form["action"], params=data)
            if _check_sqli(resp, "form"):
                names = ", ".join(inp["name"] for inp in form["inputs"])
                print(f"    [HIGH] SQLi indicator in form field(s) '{names}' at {form['action']}")
                findings.append(Finding(
                    title=f"Possible SQL Injection in Form ({form['method'].upper()} {form['action']})",
                    severity="High",
                    url=form["action"],
                    description=(
                        f"Form field(s) '{names}' triggered a database error when injected with SQL payload '{payload}'."
                    ),
                    evidence=f"Database error pattern detected in response when sending: {payload}",
                    remediation=(
                        "Use parameterized queries / prepared statements exclusively. "
                        "Never concatenate user input into SQL strings."
                    ),
                    category="SQL Injection",
                ))
            break

    return findings


# ---------------------------------------------------------------------------
# Open Redirect Detection
# ---------------------------------------------------------------------------

def scan_open_redirect(pages: set[str], client: HttpClient) -> list[Finding]:
    findings = []
    seen: set[str] = set()
    print("\n[*] Testing for Open Redirects ...")

    for url in pages:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]

        for param in redirect_params:
            for payload in OPEN_REDIRECT_PAYLOADS:
                key = f"{url}|{param}|redirect"
                if key in seen:
                    continue
                seen.add(key)
                test_url = _inject_param(url, param, payload)
                resp = client.get(test_url, allow_redirects=False)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.example.com" in location:
                        print(f"    [HIGH] Open redirect via param '{param}' at {url}")
                        findings.append(Finding(
                            title=f"Open Redirect in Parameter '{param}'",
                            severity="High",
                            url=test_url,
                            description=(
                                f"The parameter '{param}' accepts arbitrary external URLs as redirect targets. "
                                "Attackers can craft phishing links that appear to originate from the trusted domain."
                            ),
                            evidence=f"Request to {test_url} redirected to: {location}",
                            remediation=(
                                "Validate redirect targets against an allowlist of trusted domains. "
                                "Use relative paths instead of absolute URLs for redirects. "
                                "If external redirects are required, display a confirmation page first."
                            ),
                            category="Open Redirect",
                        ))
                        break

    return findings


# ---------------------------------------------------------------------------
# Sensitive File Exposure
# ---------------------------------------------------------------------------

def scan_sensitive_files(base_url: str, client: HttpClient) -> list[Finding]:
    findings = []
    print("\n[*] Checking for sensitive file exposure ...")
    base = base_url.rstrip("/")

    for path in SENSITIVE_PATHS:
        url = f"{base}/{path}"
        resp = client.get(url)
        if not resp:
            continue

        if resp.status_code == 200 and len(resp.text) > 10:
            # Avoid false positives: check the response isn't just the 404 page
            # by looking for path-specific indicators
            is_likely_real = False
            text_lower = resp.text.lower()
            path_lower = path.lower()

            if path_lower in (".env", ".env.local", ".env.production", ".env.backup"):
                is_likely_real = "=" in resp.text and len(resp.text) < 50000
            elif path_lower.startswith(".git/"):
                is_likely_real = ("repositoryformatversion" in text_lower or
                                  "ref:" in resp.text or "object" in text_lower)
            elif path_lower.endswith(".sql"):
                is_likely_real = ("insert into" in text_lower or
                                  "create table" in text_lower or "dump" in text_lower)
            elif path_lower in ("phpinfo.php", "info.php", "test.php"):
                is_likely_real = "phpinfo" in text_lower or "php version" in text_lower
            elif path_lower in ("robots.txt", "sitemap.xml", "README.md", "CHANGELOG.md",
                                 "composer.json", "package.json", "requirements.txt"):
                is_likely_real = True  # These are routinely real
            elif path_lower.endswith((".yml", ".yaml", ".json")):
                is_likely_real = True
            elif path_lower.endswith((".zip", ".tar.gz", ".bak")):
                is_likely_real = True
            else:
                is_likely_real = True

            if is_likely_real:
                severity = "High"
                if path_lower in ("robots.txt", "sitemap.xml", "README.md",
                                   "CHANGELOG.md", "composer.json", "package.json",
                                   "requirements.txt"):
                    severity = "Low"
                elif path_lower in (".htaccess", "web.config"):
                    severity = "Medium"

                print(f"    [{severity}] Accessible: {url}")
                findings.append(Finding(
                    title=f"Sensitive File Exposed: /{path}",
                    severity=severity,
                    url=url,
                    description=(
                        f"The file '/{path}' is publicly accessible and may contain sensitive information "
                        "such as credentials, configuration data, or internal application details."
                    ),
                    evidence=f"HTTP {resp.status_code} response received for {url} ({len(resp.text)} bytes).",
                    remediation=(
                        f"Restrict access to '/{path}' via web server configuration. "
                        "Move sensitive files outside the web root. "
                        "Add these paths to your web server's deny rules."
                    ),
                    category="Sensitive File Exposure",
                ))

    return findings


# ---------------------------------------------------------------------------
# Directory Enumeration
# ---------------------------------------------------------------------------

# Status codes that indicate a directory/page actually exists
_DIR_HIT_CODES = {200, 201, 301, 302, 303, 307, 308, 401, 403}

# Severity based on what was found
_DIR_SEVERITY = {
    # High-value targets
    "admin": "High", "administrator": "High", "adminpanel": "High",
    "admin/login": "High", "admin/dashboard": "High",
    "manager": "High", "management": "High", "backend": "High",
    "backoffice": "High", "controlpanel": "High", "cpanel": "High",
    "debug": "High", "console": "High", "shell": "High", "terminal": "High",
    "phpmyadmin": "High", "pma": "High", "adminer": "High",
    "db": "High", "database": "High",
    "wp-admin": "High", "wp-login.php": "High", "xmlrpc.php": "High",
    "jenkins": "High", "gitlab": "High",
    ".git": "High", ".svn": "High", ".hg": "High",
    "backup": "High", "backups": "High", "bak": "High", "archive": "High",
    "config": "High", "configuration": "High", "settings": "High",
    "install": "High", "installer": "High", "setup": "High",
    "server-status": "High", "server-info": "High",
    "nginx_status": "High", "phpinfo": "High",
    "api/docs": "Medium", "swagger": "Medium", "swagger-ui": "Medium",
    "graphql": "Medium",
    "staging": "Medium", "dev": "Medium", "devel": "Medium",
    "development": "Medium", "test": "Medium", "beta": "Medium",
    "logs": "Medium", "log": "Medium", "errors": "Medium",
    "private": "Medium", "internal": "Medium",
    "kibana": "High", "grafana": "High", "prometheus": "High",
}

_DIR_DESCRIPTIONS = {
    "High": (
        "This directory is publicly reachable and is a high-value target. "
        "It may expose administrative controls, sensitive data, or server internals."
    ),
    "Medium": (
        "This directory is publicly reachable and may expose non-production environments, "
        "API documentation, or application logs."
    ),
    "Low": (
        "This directory is publicly reachable. Depending on its contents it may "
        "aid an attacker in fingerprinting or mapping the application."
    ),
}


def scan_directories(
    base_url: str,
    client: HttpClient,
    wordlist: Optional[list[str]] = None,
    extra_wordlist_path: Optional[str] = None,
) -> list[Finding]:
    """Probe common directory paths and report accessible ones."""
    findings: list[Finding] = []
    base = base_url.rstrip("/")

    paths = list(wordlist or DIRECTORY_WORDLIST)

    if extra_wordlist_path:
        try:
            with open(extra_wordlist_path, encoding="utf-8", errors="ignore") as fh:
                extras = [ln.strip().strip("/") for ln in fh if ln.strip() and not ln.startswith("#")]
            paths = list(dict.fromkeys(paths + extras))  # deduplicate, preserve order
            print(f"[*] Loaded {len(extras)} extra paths from {extra_wordlist_path}")
        except OSError as exc:
            print(f"[!] Could not read wordlist file: {exc}")

    print(f"\n[*] Directory enumeration ({len(paths)} paths) ...")

    # Establish a baseline: fetch a known-404 path to detect soft-404 pages
    canary = f"{base}/__canary_nonexistent_path_12345__/"
    canary_resp = client.get(canary, allow_redirects=True)
    canary_body = canary_resp.text if canary_resp else ""
    canary_len  = len(canary_body)

    found: list[dict] = []

    for path in paths:
        url = f"{base}/{path}"
        resp = client.get(url, allow_redirects=False)
        if not resp:
            continue

        code = resp.status_code

        if code not in _DIR_HIT_CODES:
            continue

        # Soft-404 filter: skip if body length is very close to the canary page
        body_len = len(resp.text)
        if canary_resp and canary_resp.status_code == 200 and code == 200:
            if abs(body_len - canary_len) < 50:
                continue  # likely a custom 404 that returns 200

        severity = _DIR_SEVERITY.get(path.split("/")[0], "Low")
        status_label = {
            200: "200 OK (accessible)",
            401: "401 Unauthorized (exists, auth required)",
            403: "403 Forbidden (exists, access denied)",
        }.get(code, f"{code} redirect")

        print(f"    [{severity}] {status_label} — /{path}")
        found.append({"path": path, "url": url, "code": code, "severity": severity})

    if not found:
        print("    [OK] No unexpected directories found.")
        return findings

    # Group into one finding per severity to keep the report tidy, but also
    # emit individual High findings so each one gets its own remediation note.
    high_dirs  = [d for d in found if d["severity"] == "High"]
    other_dirs = [d for d in found if d["severity"] != "High"]

    for d in high_dirs:
        code_label = {200: "200 OK", 401: "401 Unauthorized", 403: "403 Forbidden"}.get(
            d["code"], str(d["code"])
        )
        findings.append(Finding(
            title=f"Exposed Directory: /{d['path']}",
            severity="High",
            url=d["url"],
            description=_DIR_DESCRIPTIONS["High"],
            evidence=f"HTTP {code_label} received for {d['url']}",
            remediation=(
                f"Restrict access to '/{d['path']}' in your web server configuration. "
                "Require authentication for admin interfaces. "
                "Remove or relocate debug/backup directories outside the web root. "
                "Use IP allowlisting for sensitive management panels."
            ),
            category="Directory Enumeration",
        ))

    # Bundle medium/low together into a single finding per severity level
    for sev in ("Medium", "Low"):
        group = [d for d in other_dirs if d["severity"] == sev]
        if not group:
            continue
        url_list = "\n".join(
            f"  {d['url']}  [{d['code']}]" for d in group
        )
        findings.append(Finding(
            title=f"Exposed Directories ({sev}) — {len(group)} found",
            severity=sev,
            url=base_url,
            description=_DIR_DESCRIPTIONS[sev],
            evidence=f"The following {len(group)} paths returned non-404 responses:\n{url_list}",
            remediation=(
                "Review each exposed path. Restrict access where not needed publicly. "
                "Remove test/staging directories from production servers. "
                "Ensure directory listing is disabled on the web server."
            ),
            category="Directory Enumeration",
        ))

    return findings


# ---------------------------------------------------------------------------
# HTML Report Generator
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "High":   ("#dc2626", "#fef2f2", "H"),
    "Medium": ("#d97706", "#fffbeb", "M"),
    "Low":    ("#2563eb", "#eff6ff", "L"),
    "Info":   ("#6b7280", "#f9fafb", "I"),
}

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def _badge(severity: str) -> str:
    color, _, letter = SEVERITY_COLORS.get(severity, ("#6b7280", "#f9fafb", "?"))
    return (
        f'<span class="badge" style="background:{color}">'
        f'{html_escape(severity)}</span>'
    )


def generate_report(result: ScanResult, output_path: str) -> None:
    findings_by_severity = sorted(result.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    categories: dict[str, list[Finding]] = {}
    for f in findings_by_severity:
        categories.setdefault(f.category, []).append(f)

    # Build findings HTML
    findings_html = ""
    for cat, items in categories.items():
        findings_html += f'<h2 class="category-heading">{html_escape(cat)}</h2>\n'
        for idx, f in enumerate(items, 1):
            color, bg, _ = SEVERITY_COLORS.get(f.severity, ("#6b7280", "#f9fafb", "?"))
            findings_html += f"""
            <div class="finding" style="border-left:4px solid {color};background:{bg}">
              <div class="finding-header">
                {_badge(f.severity)}
                <span class="finding-title">{html_escape(f.title)}</span>
              </div>
              <table class="finding-table">
                <tr><th>URL</th><td><code>{html_escape(f.url)}</code></td></tr>
                <tr><th>Description</th><td>{html_escape(f.description)}</td></tr>
                <tr><th>Evidence</th><td><code>{html_escape(f.evidence)}</code></td></tr>
                <tr><th>Remediation</th><td>{html_escape(f.remediation)}</td></tr>
              </table>
            </div>
            """

    if not findings_html:
        findings_html = '<p class="no-findings">No vulnerabilities detected.</p>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerability Scan Report — {html_escape(result.target)}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
         background:#f1f5f9;color:#1e293b;line-height:1.6}}
    .container{{max-width:1000px;margin:0 auto;padding:24px}}
    header{{background:#0f172a;color:#f8fafc;padding:32px;border-radius:12px;margin-bottom:24px}}
    header h1{{font-size:1.8rem;font-weight:700}}
    header p{{opacity:.75;margin-top:4px}}
    .disclaimer{{background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;
                 padding:16px;margin-bottom:24px;font-size:.9rem}}
    .disclaimer strong{{color:#92400e}}
    .summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
              gap:16px;margin-bottom:32px}}
    .stat{{background:#fff;border-radius:8px;padding:20px;text-align:center;
           box-shadow:0 1px 3px rgba(0,0,0,.1)}}
    .stat .num{{font-size:2.2rem;font-weight:800}}
    .stat .lbl{{font-size:.8rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em}}
    .stat.high  .num{{color:#dc2626}}
    .stat.medium .num{{color:#d97706}}
    .stat.low   .num{{color:#2563eb}}
    .stat.info  .num{{color:#6b7280}}
    .stat.total .num{{color:#0f172a}}
    .meta{{background:#fff;border-radius:8px;padding:16px;margin-bottom:24px;
           box-shadow:0 1px 3px rgba(0,0,0,.1);font-size:.9rem}}
    .meta table{{width:100%;border-collapse:collapse}}
    .meta td{{padding:6px 12px}}
    .meta td:first-child{{font-weight:600;width:140px;color:#475569}}
    .category-heading{{font-size:1.2rem;font-weight:700;color:#334155;
                        margin:28px 0 12px;padding-bottom:6px;
                        border-bottom:2px solid #e2e8f0}}
    .finding{{border-radius:8px;padding:18px;margin-bottom:16px;
              box-shadow:0 1px 3px rgba(0,0,0,.08)}}
    .finding-header{{display:flex;align-items:center;gap:12px;margin-bottom:12px}}
    .badge{{color:#fff;font-size:.75rem;font-weight:700;padding:3px 10px;
            border-radius:999px;letter-spacing:.04em}}
    .finding-title{{font-size:1rem;font-weight:600}}
    .finding-table{{width:100%;border-collapse:collapse;font-size:.875rem}}
    .finding-table th{{width:130px;text-align:left;padding:6px 12px 6px 0;
                        color:#475569;font-weight:600;vertical-align:top}}
    .finding-table td{{padding:6px 0;vertical-align:top}}
    .finding-table code{{background:rgba(0,0,0,.06);padding:2px 6px;border-radius:4px;
                          font-size:.82rem;word-break:break-all}}
    .no-findings{{background:#f0fdf4;border:1px solid #86efac;border-radius:8px;
                  padding:20px;text-align:center;color:#166534}}
    footer{{text-align:center;color:#94a3b8;font-size:.8rem;margin-top:32px;padding:16px}}
  </style>
</head>
<body>
<div class="container">
  <header>
    <h1>Web Application Vulnerability Report</h1>
    <p>Target: {html_escape(result.target)}</p>
  </header>

  <div class="disclaimer">
    <strong>Legal Notice:</strong> This report was generated for authorized security testing purposes only.
    Scanning systems without explicit written permission is illegal and unethical.
    The tool operator confirmed ownership/authorization before the scan began.
  </div>

  <div class="summary">
    <div class="stat total">
      <div class="num">{len(result.findings)}</div>
      <div class="lbl">Total Findings</div>
    </div>
    <div class="stat high">
      <div class="num">{counts.get('High', 0)}</div>
      <div class="lbl">High</div>
    </div>
    <div class="stat medium">
      <div class="num">{counts.get('Medium', 0)}</div>
      <div class="lbl">Medium</div>
    </div>
    <div class="stat low">
      <div class="num">{counts.get('Low', 0)}</div>
      <div class="lbl">Low</div>
    </div>
    <div class="stat info">
      <div class="num">{counts.get('Info', 0)}</div>
      <div class="lbl">Info</div>
    </div>
  </div>

  <div class="meta">
    <table>
      <tr><td>Target</td><td>{html_escape(result.target)}</td></tr>
      <tr><td>Scan Started</td><td>{html_escape(result.start_time)}</td></tr>
      <tr><td>Scan Ended</td><td>{html_escape(result.end_time)}</td></tr>
      <tr><td>Pages Crawled</td><td>{result.pages_crawled}</td></tr>
    </table>
  </div>

  {findings_html}

  <footer>Generated by VulnScanner &bull; For authorized use only &bull; {html_escape(result.end_time)}</footer>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"\n[+] Report saved to: {output_path}")


# ---------------------------------------------------------------------------
# Disclaimer / ownership prompt
# ---------------------------------------------------------------------------

def confirm_ownership(target: str) -> bool:
    print("\n" + "="*65)
    print("  WEB APPLICATION VULNERABILITY SCANNER")
    print("="*65)
    print(f"\n  Target: {target}")
    print("\n  LEGAL DISCLAIMER")
    print("  ─────────────────────────────────────────────────────────")
    print("  This tool performs active security testing that sends")
    print("  probing HTTP requests to the target system. Scanning a")
    print("  system without explicit written permission from the owner")
    print("  is ILLEGAL and may violate:")
    print("    • Computer Fraud and Abuse Act (CFAA) — US")
    print("    • Computer Misuse Act — UK")
    print("    • Equivalent cybercrime laws in your jurisdiction")
    print("\n  Only proceed if you:")
    print("    [1] Own the target system, OR")
    print("    [2] Have written authorization from the owner to test it.")
    print("="*65)

    answer = input("\n  Do you own or have explicit authorization to test this target? [yes/no]: ").strip().lower()
    return answer in ("yes", "y")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Web Application Vulnerability Scanner — authorized testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python scanner.py --target https://example.com --output report.html",
    )
    parser.add_argument("--target",  required=True, help="Target base URL (e.g. https://example.com)")
    parser.add_argument("--output",  default="report.html", help="Output HTML report file (default: report.html)")
    parser.add_argument("--delay",   type=float, default=REQUEST_DELAY, help=f"Delay between requests in seconds (default: {REQUEST_DELAY})")
    parser.add_argument("--max-pages", type=int, default=MAX_PAGES, help=f"Maximum pages to crawl (default: {MAX_PAGES})")
    parser.add_argument("--skip-crawl",   action="store_true", help="Skip crawling; scan only the target URL")
    parser.add_argument("--skip-xss",     action="store_true", help="Skip XSS tests")
    parser.add_argument("--skip-sqli",    action="store_true", help="Skip SQL injection tests")
    parser.add_argument("--skip-redirect",action="store_true", help="Skip open redirect tests")
    parser.add_argument("--skip-files",   action="store_true", help="Skip sensitive file exposure checks")
    parser.add_argument("--skip-dirs",    action="store_true", help="Skip directory enumeration")
    parser.add_argument("--wordlist",     default=None, metavar="FILE",
                        help="Path to a custom wordlist file (one path per line) to extend directory enumeration")
    parser.add_argument("--yes",          action="store_true", help="Skip ownership confirmation prompt (CI use)")
    args = parser.parse_args()

    # Normalize target URL
    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Ownership disclaimer
    if not args.yes:
        if not confirm_ownership(target):
            print("\n[!] Scan aborted. Authorization not confirmed.")
            sys.exit(1)
        print("\n[*] Authorization confirmed. Starting scan ...\n")

    start_time = datetime.now()
    result = ScanResult(
        target=target,
        start_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
    )

    client = HttpClient(delay=args.delay)

    # ── Crawl ──────────────────────────────────────────────────────────────
    if args.skip_crawl:
        pages, forms = {target}, []
    else:
        pages, forms = crawl(target, client)
    result.pages_crawled = len(pages)

    # ── Security Headers ───────────────────────────────────────────────────
    result.findings.extend(scan_headers(target, client))

    # ── XSS ───────────────────────────────────────────────────────────────
    if not args.skip_xss:
        result.findings.extend(scan_xss(pages, forms, client))

    # ── SQLi ──────────────────────────────────────────────────────────────
    if not args.skip_sqli:
        result.findings.extend(scan_sqli(pages, forms, client))

    # ── Open Redirect ─────────────────────────────────────────────────────
    if not args.skip_redirect:
        result.findings.extend(scan_open_redirect(pages, client))

    # ── Sensitive Files ───────────────────────────────────────────────────
    if not args.skip_files:
        result.findings.extend(scan_sensitive_files(target, client))

    # ── Directory Enumeration ─────────────────────────────────────────────
    if not args.skip_dirs:
        result.findings.extend(
            scan_directories(target, client, extra_wordlist_path=args.wordlist)
        )

    # ── Report ────────────────────────────────────────────────────────────
    result.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    generate_report(result, args.output)

    # ── Summary ───────────────────────────────────────────────────────────
    high   = sum(1 for f in result.findings if f.severity == "High")
    medium = sum(1 for f in result.findings if f.severity == "Medium")
    low    = sum(1 for f in result.findings if f.severity == "Low")

    print("\n" + "="*50)
    print("  SCAN COMPLETE")
    print("="*50)
    print(f"  Pages crawled : {result.pages_crawled}")
    print(f"  Findings      : {len(result.findings)} total")
    print(f"    High        : {high}")
    print(f"    Medium      : {medium}")
    print(f"    Low         : {low}")
    print(f"  Report        : {args.output}")
    print("="*50)


if __name__ == "__main__":
    main()
