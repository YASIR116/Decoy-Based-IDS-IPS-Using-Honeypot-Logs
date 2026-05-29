"""
blocker.py
Blocks malicious IPs via iptables.
Imported by main.py — not run standalone.
Can also be run directly for management commands.
"""

import os
import json
import subprocess
import logging
from datetime import datetime, timedelta

# ─── PATHS ────────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.expanduser("~/ids_project")
LOGS_DIR    = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

BLOCKED_IPS  = os.path.join(LOGS_DIR, "blocked_ips.json")
BLOCKER_LOG  = os.path.join(LOGS_DIR, "blocker.log")

# ─── CONFIG ───────────────────────────────────────────────────────────────────

AUTO_UNBLOCK_HOURS = 24

WHITELIST = {
    "127.0.0.1", "::1", "0.0.0.0",
    "192.168.31.66",   # your VM
    "192.168.31.1",    # your router
    "172.17.0.1", "172.17.0.2", "172.17.0.3",  # Docker
    "192.168.31.2",  "192.168.31.3",  "192.168.31.4",  "192.168.31.5",
    "192.168.31.6",  "192.168.31.7",  "192.168.31.8",  "192.168.31.9",
    "192.168.31.10", "192.168.31.11", "192.168.31.12", "192.168.31.13",
    "192.168.31.14", "192.168.31.15", "192.168.31.20", "192.168.31.25",
    "192.168.31.28", "192.168.31.43", "192.168.31.46", "192.168.31.50",
    "192.168.31.54", "192.168.31.71", "192.168.31.86", "192.168.31.100",
    "192.168.31.239", "192.168.31.240",
}

# ─── LOGGING ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(BLOCKER_LOG),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger("blocker")

# ─── IPTABLES ─────────────────────────────────────────────────────────────────

def _run(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0
    except Exception as e:
        log.error(f"Command failed {cmd}: {e}")
        return False

def is_blocked(ip):
    try:
        result = subprocess.run(
            ["sudo","iptables","-L","INPUT","-n"],
            capture_output=True, text=True
        )
        return ip in result.stdout
    except Exception:
        return False

def block_ip(ip):
    # Skip IPv6 — iptables only handles IPv4
    if ":" in str(ip):
        log.info(f"SKIP (IPv6): {ip}")
        return False
    # Skip invalid IPs
    if not ip or ip in ("0.0.0.0", ""):
        return False
    if ip in WHITELIST:
        log.warning(f"SKIP (whitelisted): {ip}")
        return False
    # Skip invalid/empty IPs
    if not ip or ip in ("0.0.0.0", "255.255.255.255"):
        log.info(f"SKIP (invalid IP): {ip}")
        return False
    if is_blocked(ip):
        log.info(f"SKIP (already blocked): {ip}")
        return False
    ok1 = _run(["sudo","iptables","-A","INPUT", "-s",ip,"-j","DROP"])
    ok2 = _run(["sudo","iptables","-A","OUTPUT","-d",ip,"-j","DROP"])
    if ok1 and ok2:
        log.warning(f"BLOCKED: {ip}")
        return True
    log.error(f"FAILED to block: {ip}")
    return False

def unblock_ip(ip):
    _run(["sudo","iptables","-D","INPUT", "-s",ip,"-j","DROP"])
    _run(["sudo","iptables","-D","OUTPUT","-d",ip,"-j","DROP"])
    log.info(f"UNBLOCKED: {ip}")

def list_iptables():
    try:
        result = subprocess.run(
            ["sudo","iptables","-L","INPUT","-n","--line-numbers"],
            capture_output=True, text=True
        )
        return result.stdout
    except Exception:
        return "Error reading iptables"

# ─── RECORDS ──────────────────────────────────────────────────────────────────

def _load():
    if os.path.exists(BLOCKED_IPS):
        try:
            with open(BLOCKED_IPS) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save(data):
    with open(BLOCKED_IPS,"w") as f:
        json.dump(data, f, indent=2)

def record(ip, if_score, rf_prob, threat):
    data = _load()
    data[ip] = {
        "ip":          ip,
        "blocked_at":  datetime.now().isoformat(),
        "unblock_at":  (datetime.now()+timedelta(hours=AUTO_UNBLOCK_HOURS)).isoformat(),
        "if_score":    if_score,
        "rf_prob":     rf_prob,
        "threat":      threat,
        "active":      True,
    }
    _save(data)

def check_auto_unblock():
    data    = _load()
    now     = datetime.now()
    changed = False
    for ip, d in data.items():
        if not d.get("active"):
            continue
        unblock_at = d.get("unblock_at")
        if unblock_at and now >= datetime.fromisoformat(unblock_at):
            unblock_ip(ip)
            data[ip]["active"] = False
            changed = True
            log.info(f"AUTO-UNBLOCKED: {ip}")
    if changed:
        _save(data)

def active_count():
    return sum(1 for d in _load().values() if d.get("active"))

# ─── HANDLE ONE DETECTION ─────────────────────────────────────────────────────

def handle(detection):
    """
    Called by main.py with a detection dict from detect.py.
    Blocks the IP and records it.
    Returns True if newly blocked.
    """
    ip     = detection["ip"]
    if_s   = detection["if_score"]
    rf_p   = detection["rf_prob"]
    threat = detection["threat"]

    if block_ip(ip):
        record(ip, if_s, rf_p, threat)
        return True
    return False

# ─── CLI COMMANDS ─────────────────────────────────────────────────────────────

def show():
    print("\n[*] iptables INPUT rules:")
    print(list_iptables())
    data = _load()
    if not data:
        print("[*] No IPs recorded.")
        return
    print(f"\n{'IP':<20} {'Blocked At':<22} {'Threat':<8} {'Status'}")
    print("-"*65)
    for ip, d in data.items():
        status = "ACTIVE" if d.get("active") else "unblocked"
        print(f"{ip:<20} {d['blocked_at'][:19]:<22} {d['threat']:<8} {status}")

def unblock_all():
    data = _load()
    for ip, d in data.items():
        if d.get("active"):
            unblock_ip(ip)
            data[ip]["active"] = False
    _save(data)
    print("[+] All IPs unblocked.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python blocker.py show")
        print("  python blocker.py unblock-all")
        print("  python blocker.py unblock <IP>")
    elif sys.argv[1] == "show":
        show()
    elif sys.argv[1] == "unblock-all":
        unblock_all()
    elif sys.argv[1] == "unblock" and len(sys.argv) > 2:
        unblock_ip(sys.argv[2])
    else:
        print("Unknown command.")
