# config.py — Detection thresholds and global settings.
# Tune these values without touching any detection logic.

# ── Port Scan ──────────────────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD = 15    # unique destination ports in the window
PORT_SCAN_WINDOW    = 10    # seconds

# ── SYN Flood ─────────────────────────────────────────────────────────────────
SYN_FLOOD_THRESHOLD = 100   # pure-SYN packets in the window
SYN_FLOOD_WINDOW    = 5     # seconds

# ── ICMP Flood ────────────────────────────────────────────────────────────────
ICMP_FLOOD_THRESHOLD = 50   # ICMP packets in the window
ICMP_FLOOD_WINDOW    = 5    # seconds

# ── Large Packet ──────────────────────────────────────────────────────────────
LARGE_PACKET_THRESHOLD = 9000   # bytes — jumbo frame boundary

# ── Alert cooldown ────────────────────────────────────────────────────────────
# Seconds before the same (source IP, alert type) pair can fire again.
# Prevents terminal/log spam when an attack is sustained.
ALERT_COOLDOWN = 30
