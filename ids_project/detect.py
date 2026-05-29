"""
detect.py
Monitors live honeypot logs, extracts features per IP,
runs both models, returns malicious IPs.
Imported by main.py — not run standalone.
"""

import os
import re
import json
import time
import joblib
import numpy as np
from datetime import datetime
from collections import defaultdict

# ─── PATHS ────────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.expanduser("~/ids_project")
MODELS_DIR  = os.path.join(BASE_DIR, "models")
IF_PATH     = os.path.join(MODELS_DIR, "isolation_forest.pkl")
RF_PATH     = os.path.join(MODELS_DIR, "random_forest.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")

COWRIE_LOG   = os.path.expanduser("~/cowrie/var/log/cowrie/cowrie.json")
DIONAEA_LOG  = "/opt/dionaea/logs/dionaea.log"
SURICATA_LOG = "/var/log/suricata/eve.json"

# ─── CONFIG ───────────────────────────────────────────────────────────────────

RF_THRESHOLD = 0.85
IF_THRESHOLD = -0.3

# Whitelist — these IPs will NEVER be blocked
WHITELIST = {
    # Localhost
    "127.0.0.1", "::1", "0.0.0.0",
    # Your VM
    "192.168.31.66",
    # Your router/gateway
    "192.168.31.1",
    # Docker internal IPs
    "172.17.0.1", "172.17.0.2", "172.17.0.3",
    # Whole LAN — 192.168.31.x devices
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

DIONAEA_RE = re.compile(
    r"\[\d{8} \d{2}:\d{2}:\d{2}\]\s+(\S+)\s+\S+-(debug|info|warning|error|critical):\s+(.*)"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ─── IP TRACKER ───────────────────────────────────────────────────────────────

class IPTracker:
    def __init__(self):
        self._new_ip_template = lambda: {
            "session_count":0,"login_success":0,"login_failure":0,
            "total_logins":0,"command_count":0,"commands":[],
            "durations":[],"default_creds":0,"downloads":0,
            "d_connections":0,"d_downloads":0,"d_protocols":set(),
            "d_errors":0,"s_alerts":0,"s_p1":0,
            "s_protocols":set(),"s_sigs":set(),
        }
        self.data = defaultdict(self._new_ip_template)

    def cowrie(self, event):
        ip  = event.get("src_ip","")
        eid = event.get("eventid","")
        if not ip or ip in WHITELIST:
            return
        d = self.data[ip]
        if eid == "cowrie.session.connect":
            d["session_count"] += 1
        elif eid == "cowrie.session.closed":
            d["durations"].append(float(event.get("duration",0)))
        elif eid in ("cowrie.login.success","cowrie.login.failed"):
            d["total_logins"] += 1
            if eid == "cowrie.login.success":
                d["login_success"] += 1
            else:
                d["login_failure"] += 1
            u = event.get("username","")
            p = event.get("password","")
            if (u,p) in DEFAULT_CREDS:
                d["default_creds"] += 1
        elif eid == "cowrie.command.input":
            cmd = event.get("input","").strip()
            if cmd:
                d["command_count"] += 1
                d["commands"].append(cmd)
                if any(k in cmd.lower() for k in ["wget","curl","tftp","ftp"]):
                    d["downloads"] += 1

    def dionaea(self, module, level, message, ip):
        if not ip or ip in WHITELIST:
            return
        d = self.data[ip]
        if "connect" in message.lower():
            d["d_connections"] += 1
        if module in ["ftp","http","smb","tftp"]:
            d["d_protocols"].add(module)
        if "download" in message.lower() or "upload" in message.lower():
            d["d_downloads"] += 1
        if level in ["error","critical"]:
            d["d_errors"] += 1

    def suricata(self, event):
        if event.get("event_type") != "alert":
            return
        ip = event.get("src_ip","")
        if not ip or ip in WHITELIST:
            return
        d     = self.data[ip]
        alert = event.get("alert",{})
        d["s_alerts"] += 1
        d["s_protocols"].add(event.get("proto",""))
        d["s_sigs"].add(alert.get("signature",""))
        if alert.get("severity",3) == 1:
            d["s_p1"] += 1

    def features(self, ip):
        d    = self.data[ip]
        tot  = d["total_logins"]
        rate = round(d["login_success"]/tot,2) if tot > 0 else 0.0
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

    def all_ips(self):
        return [ip for ip in self.data if ip not in WHITELIST]

# ─── LOG TAILER ───────────────────────────────────────────────────────────────

def tail(path):
    if not os.path.exists(path):
        return
    with open(path,"r",errors="replace") as f:
        f.seek(0,2)
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.1)

# ─── DETECTION ENGINE ─────────────────────────────────────────────────────────

class DetectionEngine:
    def __init__(self):
        print("[*] Loading models...")
        if not all(os.path.exists(p) for p in [IF_PATH,RF_PATH,SCALER_PATH]):
            print(f"[!] Models missing in {MODELS_DIR}")
            print("[!] Run: python train_models.py")
            exit(1)
        self.iso    = joblib.load(IF_PATH)
        self.rf     = joblib.load(RF_PATH)
        self.scaler = joblib.load(SCALER_PATH)
        self.tracker   = IPTracker()
        self.alerted   = set()
        self._cow_tail = tail(COWRIE_LOG)
        self._dio_tail = tail(DIONAEA_LOG)
        self._sur_tail = tail(SURICATA_LOG)
        print(f"[+] Models loaded from {MODELS_DIR}")
        print(f"[+] Watching:")
        print(f"    {COWRIE_LOG}")
        print(f"    {DIONAEA_LOG}")
        print(f"    {SURICATA_LOG}")

    def ingest(self):
        """Read new log lines. Returns set of updated IPs."""
        updated = set()

        for _ in range(50):
            try:
                line  = next(self._cow_tail)
                event = json.loads(line)
                ip    = event.get("src_ip","")
                self.tracker.cowrie(event)
                if ip and ip not in WHITELIST:
                    updated.add(ip)
            except (StopIteration, json.JSONDecodeError, TypeError):
                break

        for _ in range(50):
            try:
                line  = next(self._dio_tail)
                m     = DIONAEA_RE.match(line)
                if m:
                    module, level, message = m.groups()
                    ips = IP_RE.findall(message)
                    ip  = ips[0] if ips else ""
                    self.tracker.dionaea(module, level, message, ip)
                    if ip and ip not in WHITELIST:
                        updated.add(ip)
            except StopIteration:
                break

        for _ in range(50):
            try:
                line  = next(self._sur_tail)
                event = json.loads(line)
                ip    = event.get("src_ip","")
                self.tracker.suricata(event)
                if ip and ip not in WHITELIST:
                    updated.add(ip)
            except (StopIteration, json.JSONDecodeError, TypeError):
                break

        return updated

    def analyze(self, ip):
        """Analyze one IP. Returns dict or None if not malicious."""
        feats    = self.tracker.features(ip)
        X        = np.array(feats).reshape(1,-1)
        X_s      = self.scaler.transform(X)

        if_pred  = self.iso.predict(X_s)[0]
        if_score = float(self.iso.score_samples(X_s)[0])
        rf_prob  = float(self.rf.predict_proba(X_s)[0][1])

        if_bad   = (if_pred == -1) and (if_score < IF_THRESHOLD)
        rf_bad   = rf_prob >= RF_THRESHOLD
        threat   = feats[FEATURES.index("total_threat_score")]

        if (if_bad or rf_bad) and ip not in self.alerted:
            self.alerted.add(ip)
            return {
                "ip":        ip,
                "if_score":  round(if_score,4),
                "rf_prob":   round(rf_prob,4),
                "threat":    threat,
                "if_bad":    if_bad,
                "rf_bad":    rf_bad,
                "timestamp": datetime.now().isoformat(),
            }
        return None
