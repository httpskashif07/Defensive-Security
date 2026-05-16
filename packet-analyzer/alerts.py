# alerts.py — Terminal output and persistent JSON logging.

import json
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    _COLOR = True
except ImportError:
    # Graceful fallback when colorama is not installed
    _COLOR = False
    class Fore:   # type: ignore[no-redef]
        RED = YELLOW = GREEN = CYAN = WHITE = ""
    class Style:  # type: ignore[no-redef]
        RESET_ALL = BRIGHT = ""

_SEVERITY_COLOR = {
    "HIGH":   Fore.RED    + Style.BRIGHT,
    "MEDIUM": Fore.YELLOW + Style.BRIGHT,
    "LOW":    Fore.GREEN,
}


def trigger_alert(alert: dict, output_file: str) -> None:
    """
    Print a color-coded alert line to the terminal and append it to a
    JSONL (JSON Lines) file — one JSON object per line.  JSONL is used
    instead of a JSON array so we can append in O(1) without reading the
    whole file, and a crash mid-write can never corrupt earlier entries.
    """
    alert["timestamp"] = datetime.now().isoformat(timespec="seconds")

    color = _SEVERITY_COLOR.get(alert["severity"], Fore.WHITE)
    print(
        f"{color}"
        f"[{alert['timestamp']}] "
        f"[{alert['severity']:6s}] "
        f"{alert['alert_type']:15s} | "
        f"src: {alert['source_ip']:<15} | "
        f"{alert['detail']}"
        f"{Style.RESET_ALL}"
    )

    with open(output_file, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(alert) + "\n")


def log_dns_query(query: dict, dns_file: str) -> None:
    """Append a single DNS query record to the DNS log (JSONL format)."""
    query["timestamp"] = datetime.now().isoformat(timespec="seconds")
    with open(dns_file, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(query) + "\n")
