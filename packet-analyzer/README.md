# Packet Analyzer & Anomaly Detector

A CLI-based network packet capture and intrusion-detection tool built with Python and Scapy. It sniffs live traffic on a network interface, parses packets in real time, detects four classes of network anomalies, and logs color-coded alerts to both the terminal and a JSON file.

> **Disclaimer:** This tool is for **educational use only**. Only capture traffic on networks you own or have explicit written permission to monitor. Unauthorized packet capture is illegal in most jurisdictions.

---

## Features

| Detection Rule | Trigger Condition | Severity |
|---|---|---|
| **Port Scan** | One source IP hits > 15 unique destination ports within 10 s | HIGH |
| **SYN Flood** | > 100 pure-SYN packets from one source IP within 5 s | HIGH |
| **ICMP Flood** | > 50 ICMP packets from one source IP within 5 s | HIGH |
| **Large Packet** | Any single packet > 9,000 bytes (jumbo frame threshold) | MEDIUM |

**Stretch-goal features** (enabled via flags):
- DNS query logging to `dns_log.json`
- IP geolocation enrichment via `ip-api.com` (free, no key required)
- HTML summary report after capture

---

## Project Structure

```
packet-analyzer/
├── main.py       ← Entry point & CLI
├── capture.py    ← Scapy sniff + packet parsing
├── detector.py   ← Anomaly detection engine (4 rules)
├── alerts.py     ← Terminal output + JSONL file logging
├── config.py     ← All detection thresholds (easy to tune)
├── geoip.py      ← IP geolocation with caching (stretch goal)
└── report.py     ← HTML report generator (stretch goal)
```

---

## Installation

**Requirements:** Linux, Python 3.10+, root/sudo privileges.

```bash
# 1. Clone / copy the project
cd packet-analyzer

# 2. Install Python dependencies
pip install scapy colorama

# 3. (Optional) Install requests for geolocation — built-in urllib is used by default
# No extra package needed.
```

---

## Usage

```bash
# Basic — capture on eth0 until Ctrl+C
sudo python main.py

# Specify interface and run for 60 seconds
sudo python main.py -i wlan0 -d 60

# Verbose mode: print every packet AND alerts
sudo python main.py -i eth0 -v

# Custom alerts file
sudo python main.py -i eth0 -o /var/log/alerts.json

# Enable geolocation enrichment on alerts
sudo python main.py -i eth0 --geo

# Generate HTML report when capture ends
sudo python main.py -i eth0 -d 120 --report

# Full example with all options
sudo python main.py -i eth0 -d 300 -v -o alerts.json --geo --report --report-out report.html
```

### All Flags

| Flag | Default | Description |
|---|---|---|
| `-i, --interface` | `eth0` | Network interface to capture on |
| `-d, --duration` | run forever | Capture duration in seconds |
| `-o, --output` | `alerts.json` | Alerts output file path |
| `-v, --verbose` | off | Print every parsed packet |
| `--dns-log` | `dns_log.json` | DNS query log file path |
| `--no-dns` | off | Disable DNS query logging |
| `--geo` | off | Add geolocation info to alerts |
| `--report` | off | Generate HTML report on exit |
| `--report-out` | `report.html` | HTML report output path |

---

## Example Output

### Terminal (verbose mode)
```
  Packet Analyzer & Anomaly Detector
  Interface : eth0
  Duration  : until Ctrl+C
  Alerts    : alerts.json
  ──────────────────────────────────────

[14:32:08.412] TCP   [S]    | 192.168.1.105:54321 -> 10.0.0.1:80              |    60 B
[14:32:08.413] TCP   [S]    | 192.168.1.105:54321 -> 10.0.0.1:443             |    60 B
[14:32:08.414] UDP          | 192.168.1.100:56789 -> 8.8.8.8:53               |    74 B  [DNS: google.com]
[14:32:10.001] HIGH   PORT_SCAN        | src: 192.168.1.105     | Scanned 16 unique ports in 1.6s
```

### Alert in `alerts.json` (JSONL format — one object per line)
```json
{"alert_type": "PORT_SCAN", "severity": "HIGH", "source_ip": "192.168.1.105", "detail": "Scanned 16 unique ports in 1.6s", "packets_involved": 16, "timestamp": "2024-01-15T14:32:10", "geo": "New York, United States"}
```

### Exit summary
```
  ──────────────────────────────────────────────────
  Capture Summary
  ──────────────────────────────────────────────────
  Packets captured :      8,412
  Alerts triggered :          5

  Breakdown by type:
    ICMP_FLOOD           1  █
    LARGE_PACKET         2  ██
    PORT_SCAN            2  ██
  ──────────────────────────────────────────────────
```

> **Screenshot placeholder** — add your own terminal screenshot here.

---

## How Each Detection Rule Works

### Port Scan
Each source IP has a sliding deque of `(timestamp, destination_port)` tuples. On every TCP/UDP packet, entries older than 10 seconds are dropped from the left. If the remaining set of **unique** destination ports exceeds 15, an alert fires. A 30-second cooldown prevents the same IP from re-alerting immediately.

### SYN Flood
Only **pure SYN** packets are counted (flags == `'S'`, no `'A'`). This filters out normal SYN-ACK handshake replies. Each source IP tracks a deque of timestamps; if > 100 SYN packets arrive in 5 seconds, an alert fires.

### ICMP Flood
Identical sliding-window logic to SYN Flood, applied to all ICMP packets. Threshold: > 50 packets in 5 seconds.

### Large Packet
Checked synchronously for every IP packet. Any frame exceeding 9,000 bytes triggers a MEDIUM-severity alert. This threshold is the standard jumbo frame boundary; values above it are unusual on most LANs and worth investigating.

---

## Tuning Thresholds

All thresholds live in `config.py` so you can adjust them without touching detection logic:

```python
PORT_SCAN_THRESHOLD  = 15   # unique ports
PORT_SCAN_WINDOW     = 10   # seconds
SYN_FLOOD_THRESHOLD  = 100  # SYN packets
SYN_FLOOD_WINDOW     = 5    # seconds
ICMP_FLOOD_THRESHOLD = 50   # ICMP packets
ICMP_FLOOD_WINDOW    = 5    # seconds
LARGE_PACKET_THRESHOLD = 9000  # bytes
ALERT_COOLDOWN       = 30   # seconds between repeated alerts per (IP, type)
```

---

## Alert Log Format

Alerts are written in **JSONL** (JSON Lines) format: one JSON object per line. This allows efficient append-only writes and safe concurrent reads without loading the whole file into memory.

To read all alerts in Python:
```python
import json
with open("alerts.json") as f:
    alerts = [json.loads(line) for line in f if line.strip()]
```

To pretty-print with `jq`:
```bash
cat alerts.json | jq .
```

---

## Dependencies

| Package | Purpose | Install |
|---|---|---|
| `scapy` | Packet capture and parsing | `pip install scapy` |
| `colorama` | Cross-platform terminal colors | `pip install colorama` |
| `argparse` | CLI argument parsing | stdlib |
| `collections` | `deque` for sliding windows | stdlib |
| `urllib` | Geolocation HTTP requests | stdlib |

---

## Legal Disclaimer

This software is provided for **educational purposes only**. Use it only on networks you own or have **explicit written permission** to monitor. The authors accept no liability for misuse. Unauthorized interception of network traffic may violate the Computer Fraud and Abuse Act (CFAA), Electronic Communications Privacy Act (ECPA), and equivalent laws in your jurisdiction.
