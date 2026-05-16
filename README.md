# Defensive Security Toolkit

A collection of Python-based defensive security tools for authorized penetration testing, vulnerability assessment, and network anomaly detection. Built for educational use and authorized lab environments (CompTIA PenTest+ / Security+).

> **Legal Disclaimer:** All tools in this repository are for **authorized security testing and educational purposes only**. Using these tools against systems without explicit written permission from the owner is **illegal** and may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in your jurisdiction. Always obtain written authorization before testing any system.

---

## Projects

### 1. Web Application Vulnerability Scanner (`scanner.py`)

A full-featured web application scanner that crawls a target, tests for common vulnerabilities, and generates a detailed HTML report.

**Capabilities:**
| Module | What it Detects |
|---|---|
| Security Headers | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc. |
| XSS | Reflected XSS in GET parameters and HTML form fields |
| SQL Injection | Error-based SQLi indicators in URL params and forms |
| Open Redirect | Unvalidated redirect parameters |
| Sensitive Files | Exposed `.env`, `.git/config`, backups, config files, SQL dumps |
| Directory Enumeration | Admin panels, debug endpoints, backup dirs, exposed APIs |

**Usage:**
```bash
pip install requests beautifulsoup4

python scanner.py --target https://example.com --output report.html
```

**Common flags:**
```
--target       Target base URL (required)
--output       Output HTML report file (default: report.html)
--delay        Seconds between requests (default: 0.5)
--max-pages    Max pages to crawl (default: 100)
--skip-crawl   Scan only the target URL, skip crawling
--skip-xss     Skip XSS tests
--skip-sqli    Skip SQL injection tests
--skip-dirs    Skip directory enumeration
--wordlist     Custom wordlist file for directory enumeration
--yes          Skip the authorization confirmation prompt (for CI)
```

**Example:**
```bash
python scanner.py --target http://localhost/dvwa --output dvwa_report.html --delay 1
```

---

### 2. SQL Injection Tester (`sql_injection.py`)

A focused SQL injection testing script for lab environments. Supports three injection techniques.

**Techniques:**
- **Error-based** — injects payloads and inspects responses for database error signatures
- **Boolean-based** — compares true/false payload responses to detect blind injection
- **Time-based** — uses `SLEEP`/`WAITFOR DELAY` payloads to detect blind time-based injection

**Supported databases:** MySQL, MSSQL, PostgreSQL, SQLite, Oracle

**Usage:**

Edit the target values at the bottom of the script:
```python
TARGET_URL = "http://localhost/vulnerabilities/sqli/"
PARAMS     = {"id": "1", "Submit": "Submit"}

scan(TARGET_URL, PARAMS, test_types=("error", "boolean", "time"))
```

Then run:
```bash
pip install requests
python sql_injection.py
```

---

### 3. Packet Analyzer & Anomaly Detector (`packet-analyzer/`)

A CLI-based live network packet capture and intrusion-detection tool. Sniffs traffic on a network interface, parses packets in real time, detects anomalies, and logs color-coded alerts to the terminal and a JSON file.

**Detection Rules:**
| Rule | Trigger | Severity |
|---|---|---|
| Port Scan | 1 source IP hits > 15 unique destination ports within 10s | HIGH |
| SYN Flood | > 100 pure-SYN packets from 1 source IP within 5s | HIGH |
| ICMP Flood | > 50 ICMP packets from 1 source IP within 5s | HIGH |
| Large Packet | Any single packet > 9,000 bytes | MEDIUM |

**Project Structure:**
```
packet-analyzer/
├── main.py       — Entry point & CLI
├── capture.py    — Scapy packet capture and parsing
├── detector.py   — Anomaly detection engine
├── alerts.py     — Terminal output + JSONL alert logging
├── config.py     — Detection thresholds (easy to tune)
├── geoip.py      — IP geolocation enrichment (optional)
└── report.py     — HTML report generator (optional)
```

**Installation (Linux / requires root):**
```bash
pip install scapy colorama
```

**Usage:**
```bash
# Basic — capture on eth0 until Ctrl+C
sudo python main.py -i eth0

# Capture for 60 seconds with verbose output
sudo python main.py -i wlan0 -d 60 -v

# Enable geolocation enrichment and generate HTML report
sudo python main.py -i eth0 --geo --report --show-ips

# Log alerts to a custom file
sudo python main.py -i eth0 -o /var/log/alerts.json
```

**CLI Flags:**
```
-i, --interface   Network interface (default: eth0)
-d, --duration    Capture duration in seconds (default: run until Ctrl+C)
-o, --output      Alerts JSONL output file (default: alerts.json)
-v, --verbose     Print every parsed packet to terminal
--dns-log         DNS query log file (default: dns_log.json)
--no-dns          Disable DNS query logging
--geo             Enrich alerts with IP geolocation via ip-api.com
--report          Write an HTML summary report when capture ends
--report-out      HTML report output path (default: report.html)
--show-ips        Print a summary of all unique source IPs at the end
```

---

## Requirements

| Tool | Python | Key Dependencies |
|---|---|---|
| `scanner.py` | 3.10+ | `requests`, `beautifulsoup4` |
| `sql_injection.py` | 3.10+ | `requests` |
| `packet-analyzer` | 3.10+ (Linux) | `scapy`, `colorama` |

Install all at once:
```bash
pip install requests beautifulsoup4 scapy colorama
```

---

## File Overview

```
Defensive Security/
├── scanner.py          — Web application vulnerability scanner
├── sql_injection.py    — SQL injection tester (lab use)
├── wordlist.txt        — Custom wordlist for directory enumeration
├── report.html         — Sample HTML vulnerability scan report
└── packet-analyzer/    — Network packet analyzer & anomaly detector
    ├── main.py
    ├── capture.py
    ├── detector.py
    ├── alerts.py
    ├── config.py
    ├── geoip.py
    ├── report.py
    └── Screenshots/
```

---

## Authorized Testing Environments

These tools are designed for use with:
- **DVWA** (Damn Vulnerable Web Application)
- **OWASP WebGoat**
- **Metasploitable**
- **HackTheBox / TryHackMe** lab machines
- Your own locally hosted test applications

---

## License

This project is intended for educational and authorized security testing purposes only. The author is not responsible for any misuse of these tools.
