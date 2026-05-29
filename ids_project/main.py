"""
main.py - Decoy-Based IDS/IPS System
Uses ML models (Isolation Forest + Random Forest) to detect and block malicious IPs
Run: sudo /home/jeyabalan/cowrie-env/bin/python3 /home/jeyabalan/ids_project/main.py
"""

import os
import sys
import re
import json
import time
import joblib
import logging
import subprocess
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict

# ─── ABSOLUTE PATHS ───────────────────────────────────────────────────────────
USER_HOME   = "/home/jeyabalan"
PROJECT_DIR = f"{USER_HOME}/ids_project"
MODELS_DIR  = f"{PROJECT_DIR}/models"
LOGS_DIR    = f"{PROJECT_DIR}/logs"
os.makedirs(LOGS_DIR, exist_ok=True)

IF_PATH      = f"{MODELS_DIR}/isolation_forest.pkl"
RF_PATH      = f"{MODELS_DIR}/random_forest.pkl"
SCALER_PATH  = f"{MODELS_DIR}/scaler.pkl"

COWRIE_LOG   = f"{USER_HOME}/cowrie/var/log/cowrie/cowrie.json"
DIONAEA_LOG  = "/opt/dionaea/logs/dionaea.log"
SURICATA_LOG = "/var/log/suricata/eve.json"
DETECTION_LOG= f"{LOGS_DIR}/detections.log"
BLOCKED_FILE = f"{LOGS_DIR}/blocked_ips.json"

# ─── ML THRESHOLDS ────────────────────────────────────────────────────────────
RF_THRESHOLD = 0.80   # Random Forest confidence threshold
IF_THRESHOLD = -0.3   # Isolation Forest anomaly score threshold

AUTO_UNBLOCK_HOURS = 24

# ─── WHITELIST ────────────────────────────────────────────────────────────────
WHITELIST = {
    "127.0.0.1", "::1", "0.0.0.0",
    "192.168.31.66", "192.168.31.1",
    "172.17.0.1", "172.17.0.2", "172.17.0.3",
    "192.168.31.2",  "192.168.31.3",  "192.168.31.4",  "192.168.31.5",
    "192.168.31.6",  "192.168.31.7",  "192.168.31.8",  "192.168.31.9",
    "192.168.31.10", "192.168.31.11", "192.168.31.12", "192.168.31.13",
    "192.168.31.14", "192.168.31.15", "192.168.31.20", "192.168.31.25",
    "192.168.31.28", "192.168.31.43", "192.168.31.46", "192.168.31.50",
    "192.168.31.54", "192.168.31.71", "192.168.31.86", "192.168.31.100",
    "192.168.31.239","192.168.31.240",
}

DEFAULT_CREDS = {
    ("root","root"),("root","123456"),("root","password"),
    ("admin","admin"),("admin","password"),("root","123456789"),
    ("ubuntu","ubuntu"),("pi","raspberry"),("root","toor"),
}

FEATURES = [
    "session_count","login_success_rate","login_failure_count",
    "total_login_attempts","command_count","unique_command_count",
    "avg_session_duration","max_session_duration","default_cred_attempts",
    "cowrie_download_attempts","dionaea_connections","dionaea_download_attempts",
    "dionaea_protocol_count","dionaea_error_count","suricata_alert_count",
    "suricata_priority1_count","suricata_proto_count","suricata_unique_sigs",
    "total_threat_score",
]

# ─── LOGGING ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(DETECTION_LOG),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger("ids")

# ─── IP DATA STORE ────────────────────────────────────────────────────────────
ip_data = defaultdict(lambda: {
    "session_count":0, "login_success":0, "login_failure":0,
    "total_logins":0, "command_count":0, "commands":[],
    "durations":[], "default_creds":0, "downloads":0,
    "d_connections":0, "d_downloads":0, "d_protocols":set(),
    "d_errors":0, "s_alerts":0, "s_p1":0,
    "s_protocols":set(), "s_sigs":set(),
})

blocked_ips   = set()
alerted_ips   = set()
block_records = {}

# ─── IPTABLES BLOCK ───────────────────────────────────────────────────────────
def block_ip(ip, reason, if_score, rf_prob):
    if ":" in str(ip) or not ip or ip == "0.0.0.0":
        return False
    if ip in WHITELIST or ip in blocked_ips:
        return False
    try:
        subprocess.run(["sudo","iptables","-A","INPUT", "-s",ip,"-j","DROP"], capture_output=True)
        subprocess.run(["sudo","iptables","-A","OUTPUT","-d",ip,"-j","DROP"], capture_output=True)
        blocked_ips.add(ip)
        block_records[ip] = {
            "ip": ip,
            "blocked_at": datetime.now().isoformat(),
            "unblock_at": (datetime.now()+timedelta(hours=AUTO_UNBLOCK_HOURS)).isoformat(),
            "reason": reason,
            "if_score": if_score,
            "rf_prob":  rf_prob,
        }
        with open(BLOCKED_FILE, "w") as f:
            json.dump(block_records, f, indent=2)
        log.warning(f"BLOCKED: {ip} | {reason}")
        return True
    except Exception as e:
        log.error(f"Block failed {ip}: {e}")
        return False

# ─── FEATURE EXTRACTOR ────────────────────────────────────────────────────────
def get_features(ip):
    d    = ip_data[ip]
    tot  = d["total_logins"]
    rate = round(d["login_success"]/tot, 2) if tot > 0 else 0.0
    durs = d["durations"]
    threat = round(
        d["login_failure"]  * 0.3 +
        d["default_creds"]  * 2.0 +
        d["downloads"]      * 3.0 +
        d["command_count"]  * 0.1 +
        d["d_connections"]  * 0.2 +
        d["d_downloads"]    * 2.0 +
        d["s_alerts"]       * 0.5 +
        d["s_p1"]           * 3.0, 2)
    return [
        d["session_count"], rate, d["login_failure"], tot,
        d["command_count"], len(set(d["commands"])),
        round(sum(durs)/len(durs),2) if durs else 0.0,
        round(max(durs),2) if durs else 0.0,
        d["default_creds"], d["downloads"],
        d["d_connections"], d["d_downloads"],
        len(d["d_protocols"]), d["d_errors"],
        d["s_alerts"], d["s_p1"],
        len(d["s_protocols"]), len(d["s_sigs"]),
        threat,
    ]

# ─── ML DETECTION ─────────────────────────────────────────────────────────────
def ml_detect_and_block(ip, iso, rf, scaler, stats):
    """
    Pure ML-based detection using Isolation Forest + Random Forest.
    No rule-based logic — only model predictions decide blocking.
    """
    if ip in WHITELIST or ip in alerted_ips:
        return
    if ":" in str(ip) or not ip:
        return

    try:
        feats    = get_features(ip)
        X        = np.array(feats).reshape(1, -1)
        X_scaled = scaler.transform(X)

        # Isolation Forest prediction
        if_pred  = iso.predict(X_scaled)[0]       # -1=anomaly, 1=normal
        if_score = float(iso.score_samples(X_scaled)[0])

        # Random Forest prediction
        rf_pred  = rf.predict(X_scaled)[0]         # 1=malicious, 0=benign
        rf_prob  = float(rf.predict_proba(X_scaled)[0][1])

        # Detection decision
        if_malicious = (if_pred == -1) and (if_score < IF_THRESHOLD)
        rf_malicious = (rf_pred == 1)  and (rf_prob  >= RF_THRESHOLD)

        if not (if_malicious or rf_malicious):
            return

        # Build reason string
        reasons = []
        if if_malicious:
            reasons.append(f"IsolationForest(score={if_score:.3f})")
        if rf_malicious:
            reasons.append(f"RandomForest(confidence={rf_prob:.3f})")
        reason = " + ".join(reasons)

        alerted_ips.add(ip)
        stats["detected"] += 1
        log.warning(f"DETECTED | {ip} | {reason} | threat={feats[-1]}")

        # Block via iptables
        if block_ip(ip, reason, if_score, rf_prob):
            stats["blocked"] += 1
            d = ip_data[ip]
            stats["recent"].append({
                "ip":     ip,
                "reason": reason,
                "time":   datetime.now().strftime("%H:%M:%S"),
            })

            print(f"\n{'='*62}")
            print(f"  *** MALICIOUS IP DETECTED AND BLOCKED ***")
            print(f"{'='*62}")
            print(f"  IP                : {ip}")
            print(f"  IF Score          : {if_score:.4f} (anomaly: {if_malicious})")
            print(f"  RF Confidence     : {rf_prob:.4f} (malicious: {rf_malicious})")
            print(f"  Threat Score      : {feats[-1]}")
            print(f"  Failed Logins     : {d['login_failure']}")
            print(f"  Commands Run      : {d['command_count']}")
            print(f"  Download Attempts : {d['downloads']}")
            print(f"  Suricata Alerts   : {d['s_alerts']}")
            print(f"  Time              : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*62}\n")
            sys.stdout.flush()

    except Exception as e:
        log.error(f"ML detection error for {ip}: {e}")

# ─── LOG PARSERS ──────────────────────────────────────────────────────────────
DIONAEA_RE = re.compile(
    r"\[\d{8} \d{2}:\d{2}:\d{2}\]\s+(\S+)\s+\S+-(debug|info|warning|error|critical):\s+(.*)"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def process_cowrie(line):
    try:
        e   = json.loads(line)
        ip  = e.get("src_ip","")
        eid = e.get("eventid","")
        if not ip or ip in WHITELIST or ":" in ip:
            return None
        d = ip_data[ip]
        if eid == "cowrie.session.connect":
            d["session_count"] += 1
        elif eid == "cowrie.session.closed":
            d["durations"].append(float(e.get("duration",0)))
        elif eid in ("cowrie.login.success","cowrie.login.failed"):
            d["total_logins"] += 1
            if eid == "cowrie.login.success":
                d["login_success"] += 1
            else:
                d["login_failure"] += 1
            u,p = e.get("username",""), e.get("password","")
            if (u,p) in DEFAULT_CREDS:
                d["default_creds"] += 1
        elif eid == "cowrie.command.input":
            cmd = e.get("input","").strip()
            if cmd:
                d["command_count"] += 1
                d["commands"].append(cmd)
                if any(k in cmd.lower() for k in ["wget","curl","tftp","ftp"]):
                    d["downloads"] += 1
        return ip
    except:
        return None

def process_dionaea(line):
    try:
        m = DIONAEA_RE.match(line)
        if not m:
            return None
        module, level, message = m.groups()
        ips = IP_RE.findall(message)
        ip  = ips[0] if ips else None
        if not ip or ip in WHITELIST or ":" in ip:
            return None
        d = ip_data[ip]
        if "connect" in message.lower():
            d["d_connections"] += 1
        if module in ["ftp","http","smb","tftp"]:
            d["d_protocols"].add(module)
        if "download" in message.lower() or "upload" in message.lower():
            d["d_downloads"] += 1
        if level in ["error","critical"]:
            d["d_errors"] += 1
        return ip
    except:
        return None

def process_suricata(line):
    try:
        e = json.loads(line)
        if e.get("event_type") != "alert":
            return None
        ip = e.get("src_ip","")
        if not ip or ip in WHITELIST or ":" in ip:
            return None
        d     = ip_data[ip]
        alert = e.get("alert",{})
        d["s_alerts"] += 1
        d["s_protocols"].add(e.get("proto",""))
        d["s_sigs"].add(alert.get("signature",""))
        if alert.get("severity",3) == 1:
            d["s_p1"] += 1
        return ip
    except:
        return None

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def main():
    print("="*62)
    print("  Decoy-Based IDS/IPS System")
    print("  Detection: Isolation Forest + Random Forest")
    print("  Blocking : iptables")
    print("="*62)

    # Verify models exist
    for p in [IF_PATH, RF_PATH, SCALER_PATH]:
        if not os.path.exists(p):
            print(f"[!] Missing model: {p}")
            print("[!] Run train_models.py first")
            sys.exit(1)

    # Load models
    print("[*] Loading ML models...")
    iso    = joblib.load(IF_PATH)
    rf     = joblib.load(RF_PATH)
    scaler = joblib.load(SCALER_PATH)
    print(f"[+] Isolation Forest loaded")
    print(f"[+] Random Forest loaded")
    print(f"[+] Scaler loaded")

    # Show log status
    print()
    for name, path in [("Cowrie",COWRIE_LOG),("Dionaea",DIONAEA_LOG),("Suricata",SURICATA_LOG)]:
        exists = os.path.exists(path)
        print(f"[+] {name:<10}: {'FOUND' if exists else 'NOT FOUND'} → {path}")

    print(f"\n[*] RF threshold  : >= {RF_THRESHOLD}")
    print(f"[*] IF threshold  : <  {IF_THRESHOLD}")
    print(f"[*] Whitelist     : {len(WHITELIST)} IPs")
    print(f"[*] Detection log : {DETECTION_LOG}")
    print(f"\n[*] Live monitoring started. Waiting for attacks...")
    print("-"*62)
    sys.stdout.flush()

    stats = {"detected":0, "blocked":0, "recent":[]}

    # Open log files and seek to end
    cow_file = open(COWRIE_LOG,   "r", errors="replace") if os.path.exists(COWRIE_LOG)   else None
    dio_file = open(DIONAEA_LOG,  "r", errors="replace") if os.path.exists(DIONAEA_LOG)  else None
    sur_file = open(SURICATA_LOG, "r", errors="replace") if os.path.exists(SURICATA_LOG) else None

    for f in [cow_file, dio_file, sur_file]:
        if f:
            f.seek(0, 2)

    loop = 0

    try:
        while True:
            updated = set()

            # Read new lines from all three logs
            if cow_file:
                for _ in range(500):
                    line = cow_file.readline()
                    if not line: break
                    ip = process_cowrie(line.strip())
                    if ip: updated.add(ip)

            if dio_file:
                for _ in range(500):
                    line = dio_file.readline()
                    if not line: break
                    ip = process_dionaea(line.strip())
                    if ip: updated.add(ip)

            if sur_file:
                for _ in range(500):
                    line = sur_file.readline()
                    if not line: break
                    ip = process_suricata(line.strip())
                    if ip: updated.add(ip)

            # Run ML detection on every updated IP
            for ip in updated:
                ml_detect_and_block(ip, iso, rf, scaler, stats)

            # Heartbeat every 3 seconds
            loop += 1
            if loop % 60 == 0:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"IPs tracked: {len(ip_data)} | "
                      f"Detected: {stats['detected']} | "
                      f"Blocked: {stats['blocked']}")
                sys.stdout.flush()

            # Auto unblock
            if loop % 7200 == 0:
                now = datetime.now()
                for ip, rec in list(block_records.items()):
                    if now >= datetime.fromisoformat(rec["unblock_at"]):
                        subprocess.run(["sudo","iptables","-D","INPUT", "-s",ip,"-j","DROP"], capture_output=True)
                        subprocess.run(["sudo","iptables","-D","OUTPUT","-d",ip,"-j","DROP"], capture_output=True)
                        blocked_ips.discard(ip)
                        log.info(f"AUTO-UNBLOCKED: {ip}")

            time.sleep(0.05)

    except KeyboardInterrupt:
        print(f"\n[*] IDS/IPS stopped.")
        print(f"[*] IPs tracked  : {len(ip_data)}")
        print(f"[*] IPs detected : {stats['detected']}")
        print(f"[*] IPs blocked  : {stats['blocked']}")
        if stats["recent"]:
            print(f"[*] Recent blocks:")
            for r in stats["recent"][-5:]:
                print(f"    [{r['time']}] {r['ip']:<20} {r['reason']}")
        for f in [cow_file, dio_file, sur_file]:
            if f: f.close()

if __name__ == "__main__":
    main()
