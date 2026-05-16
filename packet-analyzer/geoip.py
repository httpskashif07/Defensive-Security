# geoip.py — Lightweight IP geolocation via the free ip-api.com endpoint.
#
# Results are cached in-process for CACHE_TTL seconds so that a sustained
# attack from one IP only costs one HTTP round-trip, not one per packet.
# Private / loopback / link-local addresses are never looked up.

import ipaddress
import json
import time
from urllib.error import URLError
from urllib.request import urlopen

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"), # Link-local
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),    # Multicast
    ipaddress.ip_network("240.0.0.0/4"),    # Reserved
]

_CACHE:     dict = {}
_CACHE_TTL: int  = 3600   # re-query after one hour


def is_private(ip: str) -> bool:
    """Return True if `ip` belongs to any private, loopback, or reserved range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True     # unparseable → treat as private / don't look up


def lookup(ip: str) -> dict | None:
    """
    Return a geolocation dict for a public IP address, or None on failure.

    The returned dict contains at least the keys 'country', 'city', and 'isp'.
    ip-api.com allows up to 45 requests/minute on the free tier; the in-process
    cache keeps usage well within that limit for typical capture sessions.
    """
    if is_private(ip):
        return None

    now   = time.time()
    entry = _CACHE.get(ip)
    if entry and now - entry.get("_ts", 0) < _CACHE_TTL:
        return entry

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp"
        with urlopen(url, timeout=3) as resp:
            data: dict = json.loads(resp.read().decode())

        if data.get("status") == "success":
            data["_ts"] = now
            _CACHE[ip]  = data
            return data

    except (URLError, json.JSONDecodeError, OSError):
        pass

    return None
