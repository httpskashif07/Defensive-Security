# detector.py — Stateful anomaly detection engine.
#
# Each rule tracks per-source-IP state in a sliding time window using a
# collections.deque.  Entries older than the window are trimmed from the
# left before every check, keeping memory and CPU usage constant even
# under heavy traffic.

import time
from collections import defaultdict, deque

from config import (
    PORT_SCAN_THRESHOLD,  PORT_SCAN_WINDOW,
    SYN_FLOOD_THRESHOLD,  SYN_FLOOD_WINDOW,
    ICMP_FLOOD_THRESHOLD, ICMP_FLOOD_WINDOW,
    LARGE_PACKET_THRESHOLD,
    ALERT_COOLDOWN,
)


class AnomalyDetector:

    def __init__(self) -> None:
        # Port scan: src_ip -> deque of (timestamp, dst_port) tuples
        self._port_scan: dict = defaultdict(deque)

        # Flood trackers: src_ip -> deque of plain timestamps
        self._syn_flood:  dict = defaultdict(deque)
        self._icmp_flood: dict = defaultdict(deque)

        # Cooldown registry: (src_ip, alert_type) -> last-fired timestamp
        self._last_alerted: dict = {}

    # ── Sliding-window helpers ────────────────────────────────────────────────

    def _trim(self, dq: deque, window: float) -> None:
        """Drop (timestamp, value) tuples older than `window` seconds."""
        cutoff = time.time() - window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def _trim_ts(self, dq: deque, window: float) -> None:
        """Drop plain timestamps older than `window` seconds."""
        cutoff = time.time() - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _cooldown_ok(self, src_ip: str, alert_type: str) -> bool:
        """
        Return True and record the firing time only when the cooldown has
        elapsed.  Prevents the same (ip, type) pair from flooding the log.
        """
        key  = (src_ip, alert_type)
        last = self._last_alerted.get(key, 0.0)
        if time.time() - last >= ALERT_COOLDOWN:
            self._last_alerted[key] = time.time()
            return True
        return False

    # ── Detection rules ───────────────────────────────────────────────────────

    def _check_port_scan(self, src_ip: str, dst_port: int, ts: float) -> dict | None:
        """Flag a source that probes more than PORT_SCAN_THRESHOLD unique ports."""
        dq = self._port_scan[src_ip]
        self._trim(dq, PORT_SCAN_WINDOW)
        dq.append((ts, dst_port))

        unique_ports = len({entry[1] for entry in dq})
        if unique_ports > PORT_SCAN_THRESHOLD and self._cooldown_ok(src_ip, "PORT_SCAN"):
            elapsed = (ts - dq[0][0]) if len(dq) > 1 else 0.0
            return {
                "alert_type":       "PORT_SCAN",
                "severity":         "HIGH",
                "source_ip":        src_ip,
                "detail":           f"Scanned {unique_ports} unique ports in {elapsed:.1f}s",
                "packets_involved": len(dq),
            }
        return None

    def _check_syn_flood(self, src_ip: str, ts: float) -> dict | None:
        """Flag a burst of pure-SYN packets (half-open connection flood)."""
        dq = self._syn_flood[src_ip]
        self._trim_ts(dq, SYN_FLOOD_WINDOW)
        dq.append(ts)

        if len(dq) > SYN_FLOOD_THRESHOLD and self._cooldown_ok(src_ip, "SYN_FLOOD"):
            elapsed = (ts - dq[0]) if len(dq) > 1 else 0.0
            return {
                "alert_type":       "SYN_FLOOD",
                "severity":         "HIGH",
                "source_ip":        src_ip,
                "detail":           f"{len(dq)} SYN packets in {elapsed:.1f}s",
                "packets_involved": len(dq),
            }
        return None

    def _check_icmp_flood(self, src_ip: str, ts: float) -> dict | None:
        """Flag a high-rate ICMP burst (ping flood / Smurf-style attack)."""
        dq = self._icmp_flood[src_ip]
        self._trim_ts(dq, ICMP_FLOOD_WINDOW)
        dq.append(ts)

        if len(dq) > ICMP_FLOOD_THRESHOLD and self._cooldown_ok(src_ip, "ICMP_FLOOD"):
            elapsed = (ts - dq[0]) if len(dq) > 1 else 0.0
            return {
                "alert_type":       "ICMP_FLOOD",
                "severity":         "HIGH",
                "source_ip":        src_ip,
                "detail":           f"{len(dq)} ICMP packets in {elapsed:.1f}s",
                "packets_involved": len(dq),
            }
        return None

    def _check_large_packet(self, src_ip: str, size: int) -> dict | None:
        """Flag any single packet that exceeds the jumbo-frame threshold."""
        if size > LARGE_PACKET_THRESHOLD and self._cooldown_ok(src_ip, "LARGE_PACKET"):
            return {
                "alert_type":       "LARGE_PACKET",
                "severity":         "MEDIUM",
                "source_ip":        src_ip,
                "detail":           f"Packet size {size:,} bytes (threshold: {LARGE_PACKET_THRESHOLD:,})",
                "packets_involved": 1,
            }
        return None

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, pkt: dict) -> list[dict]:
        """
        Run all detection rules against a parsed packet dict.
        Returns a (possibly empty) list of alert dicts ready for alerts.py.
        """
        results: list[dict] = []
        src_ip = pkt["src_ip"]
        ts     = pkt["timestamp"]

        # Port scan — any TCP/UDP packet with a destination port
        if pkt["dst_port"] is not None:
            hit = self._check_port_scan(src_ip, pkt["dst_port"], ts)
            if hit:
                results.append(hit)

        # SYN flood — pure SYN only (exclude SYN-ACK handshake replies)
        if pkt["protocol"] == "TCP" and pkt.get("flags"):
            flags = pkt["flags"]   # str representation from Scapy, e.g. 'S', 'SA', 'A'
            if "S" in flags and "A" not in flags:
                hit = self._check_syn_flood(src_ip, ts)
                if hit:
                    results.append(hit)

        # ICMP flood
        if pkt["protocol"] == "ICMP":
            hit = self._check_icmp_flood(src_ip, ts)
            if hit:
                results.append(hit)

        # Oversized packet (checked for every protocol)
        hit = self._check_large_packet(src_ip, pkt["size"])
        if hit:
            results.append(hit)

        return results
