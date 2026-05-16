#!/usr/bin/env python3
# main.py — Entry point for the Packet Analyzer & Anomaly Detector.
#
# Run with:  sudo python main.py -i eth0
# Requires root (raw socket access).  Use Ctrl+C to stop early.

import argparse
import sys
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:   # type: ignore[no-redef]
        RED = YELLOW = GREEN = CYAN = WHITE = ""
    class Style:  # type: ignore[no-redef]
        RESET_ALL = BRIGHT = ""

from capture  import PacketCapture
from detector import AnomalyDetector
from alerts   import trigger_alert, log_dns_query


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="packet-analyzer",
        description="Live network packet analyzer with anomaly detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples\n"
            "--------\n"
            "  sudo python main.py -i eth0\n"
            "  sudo python main.py -i wlan0 -d 60 -v\n"
            "  sudo python main.py -i eth0 -o /var/log/alerts.json --geo --report\n"
        ),
    )
    p.add_argument("-i", "--interface", default="eth0", metavar="IFACE",
                   help="Network interface to capture on  (default: eth0)")
    p.add_argument("-d", "--duration", type=int, default=None, metavar="SECS",
                   help="Capture duration in seconds; omit to run until Ctrl+C")
    p.add_argument("-o", "--output", default="alerts.json", metavar="FILE",
                   help="Path for the alerts JSONL file  (default: alerts.json)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print every parsed packet to the terminal")
    p.add_argument("--dns-log", default="dns_log.json", metavar="FILE",
                   help="Path for the DNS query log       (default: dns_log.json)")
    p.add_argument("--no-dns", action="store_true",
                   help="Disable DNS query logging")
    p.add_argument("--geo", action="store_true",
                   help="Enrich alerts with IP geolocation via ip-api.com (requires internet)")
    p.add_argument("--report", action="store_true",
                   help="Write an HTML summary report when capture ends")
    p.add_argument("--report-out", default="report.html", metavar="FILE",
                   help="Path for the HTML report          (default: report.html)")
    p.add_argument("--show-ips", action="store_true",
                   help="Print a summary of all unique source IPs seen at the end")
    return p.parse_args()


# ── Display helpers ───────────────────────────────────────────────────────────

def _print_packet(pkt: dict) -> None:
    """Verbose mode: print one line per parsed packet."""
    ts    = datetime.fromtimestamp(pkt["timestamp"]).strftime("%H:%M:%S.%f")[:-3]
    proto = pkt["protocol"]

    if pkt["src_port"] is not None and pkt["dst_port"] is not None:
        flow = f"{pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}"
    else:
        flow = f"{pkt['src_ip']} -> {pkt['dst_ip']}"

    dns_tag = f"  [DNS: {pkt['dns_query']}]" if pkt["is_dns"] else ""
    flags   = f" [{pkt['flags']}]" if pkt.get("flags") else ""

    print(
        f"{Fore.CYAN}[{ts}]{Style.RESET_ALL} "
        f"{proto:<5}{flags:<5} | "
        f"{flow:<50} | "
        f"{pkt['size']:>5} B{dns_tag}"
    )


def _print_ip_summary(ip_counts: dict) -> None:
    if not ip_counts:
        return
    has_geo = any("geo" in data for data in ip_counts.values())
    bar = "─" * (75 if has_geo else 55)
    print(f"\n{Style.BRIGHT}{bar}")
    print("  Unique Source IPs Seen")
    print(bar + Style.RESET_ALL)
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1]["count"], reverse=True)
    for ip, data in sorted_ips:
        protos  = ", ".join(sorted(data["protocols"]))
        geo_tag = f"  {Fore.GREEN}{data['geo']}{Style.RESET_ALL}" if "geo" in data else ""
        print(f"  {ip:<20} {Fore.CYAN}({protos:<8}){Style.RESET_ALL}  → {data['count']:>6,} packets{geo_tag}")
    print(f"{Style.BRIGHT}{'─' * (75 if has_geo else 55)}{Style.RESET_ALL}\n")


def _print_summary(stats: dict) -> None:
    """Print the end-of-capture summary."""
    bar = "─" * 50
    print(f"\n{Style.BRIGHT}{bar}")
    print("  Capture Summary")
    print(bar + Style.RESET_ALL)
    print(f"  Packets captured : {stats['packets']:>10,}")
    print(f"  Alerts triggered : {stats['alerts']:>10,}")
    if stats["by_type"]:
        print(f"\n  Breakdown by type:")
        for atype, count in sorted(stats["by_type"].items()):
            bar_fill = "█" * min(count, 40)
            print(f"    {atype:<20} {count:>5}  {Fore.YELLOW}{bar_fill}{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}{'─' * 50}{Style.RESET_ALL}\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    args = _parse_args()

    # Lazy-load optional stretch-goal modules
    _geoip  = None
    _report = None

    if args.geo:
        try:
            import geoip as _g   # type: ignore[import]
            _geoip = _g
        except ImportError:
            print(f"{Fore.YELLOW}[WARN] geoip.py not found; --geo disabled.{Style.RESET_ALL}")

    if args.report:
        try:
            import report as _r  # type: ignore[import]
            _report = _r
        except ImportError:
            print(f"{Fore.YELLOW}[WARN] report.py not found; --report disabled.{Style.RESET_ALL}")

    detector = AnomalyDetector()
    stats: dict = {"packets": 0, "alerts": 0, "by_type": {}, "ip_counts": {}}

    def on_packet(pkt: dict) -> None:
        stats["packets"] += 1

        if args.show_ips:
            src = pkt["src_ip"]
            if src not in stats["ip_counts"]:
                stats["ip_counts"][src] = {"count": 0, "protocols": set()}
            stats["ip_counts"][src]["count"] += 1
            stats["ip_counts"][src]["protocols"].add(pkt["protocol"])

        if args.verbose:
            _print_packet(pkt)

        # Stretch goal: log DNS queries
        if pkt["is_dns"] and not args.no_dns:
            log_dns_query(
                {
                    "src_ip":    pkt["src_ip"],
                    "dst_ip":    pkt["dst_ip"],
                    "query":     pkt["dns_query"],
                    "protocol":  pkt["protocol"],
                },
                args.dns_log,
            )

        # Anomaly detection
        for alert in detector.analyze(pkt):

            # Stretch goal: geolocation enrichment
            if _geoip:
                geo = _geoip.lookup(alert["source_ip"])
                if geo:
                    alert["geo"] = f"{geo.get('city', '')}, {geo.get('country', '')}"

            trigger_alert(alert, args.output)
            stats["alerts"] += 1
            stats["by_type"][alert["alert_type"]] = (
                stats["by_type"].get(alert["alert_type"], 0) + 1
            )

    capture = PacketCapture(
        interface=args.interface,
        duration=args.duration,
        callback=on_packet,
    )

    # Banner
    print(f"\n{Style.BRIGHT}  Packet Analyzer & Anomaly Detector{Style.RESET_ALL}")
    print(f"  Interface : {args.interface}")
    print(f"  Duration  : {'until Ctrl+C' if args.duration is None else f'{args.duration}s'}")
    print(f"  Alerts    : {args.output}")
    if not args.no_dns:
        print(f"  DNS log   : {args.dns_log}")
    if args.geo:
        print(f"  Geo       : enabled")
    print(f"  {'─'*38}\n")

    try:
        capture.start()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user.{Style.RESET_ALL}")
    except PermissionError:
        print(
            f"\n{Fore.RED}[ERROR] Raw socket access denied.  "
            f"Run with:  sudo python main.py{Style.RESET_ALL}"
        )
        sys.exit(1)
    except OSError as exc:
        print(
            f"\n{Fore.RED}[ERROR] Cannot open interface '{args.interface}': {exc}\n"
            f"  List available interfaces with:  ip link show{Style.RESET_ALL}"
        )
        sys.exit(1)
    finally:
        _print_summary(stats)
        if args.show_ips:
            if _geoip:
                for ip in stats["ip_counts"]:
                    geo = _geoip.lookup(ip)
                    if geo:
                        stats["ip_counts"][ip]["geo"] = f"{geo.get('city', '')}, {geo.get('country', '')}  |  ISP: {geo.get('isp', 'Unknown')}"
            _print_ip_summary(stats["ip_counts"])
        if _report:
            _report.generate_html_report(args.output, args.report_out, stats)
            print(f"HTML report written to:  {args.report_out}\n")


if __name__ == "__main__":
    main()
