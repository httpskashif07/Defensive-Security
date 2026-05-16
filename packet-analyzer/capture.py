# capture.py — Live packet capture and field extraction using Scapy.

import time

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR   # type: ignore[import]


class PacketCapture:
    """
    Wraps Scapy's sniff() to capture packets on a named interface and
    invoke a callback with a normalized dict for every IP-level packet.

    Non-IP frames (ARP, etc.) are silently skipped.
    Any exception raised while parsing a single packet is caught so that
    one malformed frame can never stop the capture.
    """

    def __init__(self, interface: str, duration: int | None, callback) -> None:
        self.interface = interface
        self.duration  = duration   # None → capture until Ctrl+C
        self.callback  = callback   # called with a packet-info dict

    def start(self) -> None:
        """Begin capture.  Blocks until duration expires or Ctrl+C is pressed."""
        sniff(
            iface=self.interface,
            timeout=self.duration,
            prn=self._handle,
            store=False,    # don't accumulate all packets in RAM
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _handle(self, packet) -> None:
        """Scapy per-packet callback."""
        try:
            info = self._parse(packet)
            if info is not None:
                self.callback(info)
        except Exception:
            pass    # skip silently; a bad frame must not kill the capture

    def _parse(self, packet) -> dict | None:
        """
        Extract and normalize fields from a Scapy packet.
        Returns None for non-IP frames.
        """
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        info: dict = {
            "timestamp": time.time(),
            "src_ip":    ip.src,
            "dst_ip":    ip.dst,
            "size":      len(packet),
            "protocol":  "OTHER",
            "src_port":  None,
            "dst_port":  None,
            "flags":     None,      # TCP flags as a string, e.g. 'S', 'SA'
            "is_dns":    False,
            "dns_query": None,
        }

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info["protocol"] = "TCP"
            info["src_port"] = tcp.sport
            info["dst_port"] = tcp.dport
            # str(tcp.flags) gives human-readable flag letters, e.g. 'S', 'FA'
            info["flags"]    = str(tcp.flags)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info["protocol"] = "UDP"
            info["src_port"] = udp.sport
            info["dst_port"] = udp.dport

        elif packet.haslayer(ICMP):
            info["protocol"] = "ICMP"

        # DNS detection works over both UDP/53 and TCP/53
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname
            info["is_dns"]    = True
            info["dns_query"] = (
                qname.decode("utf-8", errors="replace").rstrip(".")
                if isinstance(qname, bytes)
                else str(qname).rstrip(".")
            )

        return info
