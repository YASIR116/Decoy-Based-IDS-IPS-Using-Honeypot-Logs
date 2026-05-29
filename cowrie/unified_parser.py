import json
import sqlite3
import csv
import re
import os
import glob
from collections import defaultdict
from datetime import datetime

# ─── CONFIG ───────────────────────────────────────────────────────────────────

# Cowrie — auto picks all cowrie.json* files
COWRIE_LOG_DIR = os.path.expanduser("~/cowrie/var/log/cowrie/")
COWRIE_LOGS    = glob.glob(os.path.join(COWRIE_LOG_DIR, "cowrie.json*"))

# Dionaea — single log file (rotates internally)
DIONAEA_LOG    = "/opt/dionaea/logs/dionaea.log"

# Suricata — auto picks all eve.json* and fast.log* files
SURICATA_DIR   = "/var/log/suricata/"
SURICATA_EVES  = sorted(glob.glob(os.path.join(SURICATA_DIR, "eve.json*")))
SURICATA_FASTS = sorted(glob.glob(os.path.join(SURICATA_DIR, "fast.log*")))

# Output files — saved in ~/ids_project/
PROJECT_DIR = os.path.expanduser("~/ids_project/")
os.makedirs(PROJECT_DIR, exist_ok=True)

DB_PATH  = os.path.join(PROJECT_DIR, "ids_dataset.db")
CSV_PATH = os.path.join(PROJECT_DIR, "ids_ml_features.csv")

# Suricata: ignore these noisy/benign event types
SURICATA_SKIP_EVENTS = {"stats", "dns", "mdns"}

# Known default credentials (high-signal for brute force)
DEFAULT_CREDS = {
    ("root", "root"), ("root", "123456"), ("root", "password"),
    ("admin", "admin"), ("admin", "password"), ("root", "123456789"),
    ("ubuntu", "ubuntu"), ("pi", "raspberry"), ("root", "toor"),
}

# ─── 1. COWRIE PARSER ─────────────────────────────────────────────────────────

def parse_cowrie_logs(paths):
    sessions       = {}
    login_attempts = []
    commands       = []
    raw_logs       = []

    ip_data = defaultdict(lambda: {
        "login_success": 0, "login_failure": 0,
        "command_count": 0, "commands": [],
        "session_ids": set(), "session_durations": [],
        "protocols": set(), "client_versions": set(),
        "default_cred_attempts": 0, "download_attempts": 0,
    })

    for path in paths:
        if not os.path.exists(path):
            print(f"[!] Cowrie log not found: {path}")
            continue

        print(f"    Reading: {path}")
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                src_ip     = event.get("src_ip", "unknown")
                eid        = event.get("eventid", "")
                session_id = event.get("session", "")
                timestamp  = event.get("timestamp", "")

                raw_logs.append({
                    "source": "cowrie", "event_id": eid,
                    "session_id": session_id, "src_ip": src_ip,
                    "raw_json": json.dumps(event), "timestamp": timestamp,
                })

                if eid == "cowrie.session.connect":
                    sessions[session_id] = {
                        "session_id": session_id, "src_ip": src_ip,
                        "dst_ip": event.get("dst_ip", ""),
                        "src_port": event.get("src_port", 0),
                        "dst_port": event.get("dst_port", 0),
                        "protocol": event.get("protocol", ""),
                        "start_time": timestamp, "end_time": "",
                        "duration": 0.0, "client_version": "",
                        "sensor": event.get("sensor", ""),
                    }
                    ip_data[src_ip]["session_ids"].add(session_id)
                    ip_data[src_ip]["protocols"].add(event.get("protocol", ""))

                elif eid == "cowrie.client.version":
                    version = event.get("version", "")
                    if session_id in sessions:
                        sessions[session_id]["client_version"] = version
                    ip_data[src_ip]["client_versions"].add(version)

                elif eid == "cowrie.session.closed":
                    duration = float(event.get("duration", 0))
                    if session_id in sessions:
                        sessions[session_id]["end_time"] = timestamp
                        sessions[session_id]["duration"] = duration
                    ip_data[src_ip]["session_durations"].append(duration)

                elif eid == "cowrie.login.success":
                    username = event.get("username", "")
                    password = event.get("password", "")
                    login_attempts.append({
                        "source": "cowrie", "session_id": session_id,
                        "src_ip": src_ip, "username": username,
                        "password": password, "success": 1,
                        "timestamp": timestamp,
                    })
                    ip_data[src_ip]["login_success"] += 1
                    if (username, password) in DEFAULT_CREDS:
                        ip_data[src_ip]["default_cred_attempts"] += 1

                elif eid == "cowrie.login.failed":
                    username = event.get("username", "")
                    password = event.get("password", "")
                    login_attempts.append({
                        "source": "cowrie", "session_id": session_id,
                        "src_ip": src_ip, "username": username,
                        "password": password, "success": 0,
                        "timestamp": timestamp,
                    })
                    ip_data[src_ip]["login_failure"] += 1
                    if (username, password) in DEFAULT_CREDS:
                        ip_data[src_ip]["default_cred_attempts"] += 1

                elif eid == "cowrie.command.input":
                    cmd = event.get("input", "").strip()
                    if cmd:
                        ip_data[src_ip]["command_count"] += 1
                        ip_data[src_ip]["commands"].append(cmd)
                        commands.append({
                            "session_id": session_id, "src_ip": src_ip,
                            "command": cmd, "timestamp": timestamp,
                        })
                        if any(kw in cmd.lower() for kw in ["wget", "curl", "tftp", "ftp"]):
                            ip_data[src_ip]["download_attempts"] += 1

    print(f"[+] Cowrie sessions      : {len(sessions)}")
    print(f"[+] Cowrie login attempts: {len(login_attempts)}")
    print(f"[+] Cowrie commands      : {len(commands)}")
    return sessions, login_attempts, commands, raw_logs, ip_data


# ─── 2. DIONAEA PARSER ────────────────────────────────────────────────────────

DIONAEA_PATTERN = re.compile(
    r"\[(\d{8} \d{2}:\d{2}:\d{2})\]\s+(\S+)\s+\S+-(debug|info|warning|error|critical):\s+(.*)"
)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def parse_dionaea_log(path):
    if not os.path.exists(path):
        print(f"[!] Dionaea log not found: {path}")
        return [], defaultdict(lambda: {
            "connection_count": 0, "protocols": set(),
            "download_attempts": 0, "events": [],
        })

    events  = []
    ip_data = defaultdict(lambda: {
        "connection_count": 0, "protocols": set(),
        "download_attempts": 0, "events": [],
    })

    print(f"    Reading: {path}")
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            match = DIONAEA_PATTERN.match(line)
            if not match:
                continue

            raw_ts, module, level, message = match.groups()

            try:
                ts = datetime.strptime(raw_ts, "%d%m%Y %H:%M:%S").isoformat()
            except ValueError:
                ts = raw_ts

            ips    = IP_PATTERN.findall(message)
            src_ip = ips[0] if ips else "unknown"

            event  = {
                "timestamp": ts, "module": module,
                "level": level, "message": message,
                "src_ip": src_ip,
            }
            events.append(event)

            if src_ip != "unknown":
                ip_data[src_ip]["events"].append(level)
                if "connect" in message.lower() or "connection" in message.lower():
                    ip_data[src_ip]["connection_count"] += 1
                if module in ["ftp", "http", "smb", "tftp"]:
                    ip_data[src_ip]["protocols"].add(module)
                if "download" in message.lower() or "upload" in message.lower():
                    ip_data[src_ip]["download_attempts"] += 1

    print(f"[+] Dionaea events       : {len(events)}")
    print(f"[+] Dionaea unique IPs   : {len(ip_data)}")
    return events, ip_data


# ─── 3. SURICATA PARSER ───────────────────────────────────────────────────────

FAST_PATTERN = re.compile(
    r"(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.*?)\s+\[\*\*\]\s+"
    r"\[Classification:\s*(.*?)\]\s+\[Priority:\s*(\d+)\]\s+\{(\w+)\}\s+"
    r"([\d\.]+):(\d+)\s+->\s+([\d\.]+):(\d+)"
)

def parse_suricata_logs(eve_paths, fast_paths):
    alerts  = []
    ip_data = defaultdict(lambda: {
        "alert_count": 0, "priority1_count": 0,
        "protocols": set(), "classifications": set(),
        "dest_ports": set(), "signatures": [],
    })

    for eve_path in eve_paths:
        if not os.path.exists(eve_path):
            continue
        print(f"    Reading: {eve_path}")
        with open(eve_path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event_type = event.get("event_type", "")
                if event_type in SURICATA_SKIP_EVENTS:
                    continue

                src_ip = event.get("src_ip", "unknown")
                proto  = event.get("proto", "")
                ts     = event.get("timestamp", "")

                if event_type == "alert":
                    alert_info = event.get("alert", {})
                    priority   = alert_info.get("severity", 3)
                    signature  = alert_info.get("signature", "")
                    category   = alert_info.get("category", "")

                    alerts.append({
                        "timestamp": ts, "src_ip": src_ip,
                        "dest_ip": event.get("dest_ip", "unknown"),
                        "src_port": event.get("src_port", 0),
                        "dest_port": event.get("dest_port", 0),
                        "proto": proto, "signature": signature,
                        "category": category, "priority": priority,
                        "raw_json": json.dumps(event),
                    })

                    ip_data[src_ip]["alert_count"]     += 1
                    ip_data[src_ip]["protocols"].add(proto)
                    ip_data[src_ip]["classifications"].add(category)
                    ip_data[src_ip]["signatures"].append(signature)
                    if priority == 1:
                        ip_data[src_ip]["priority1_count"] += 1
                    ip_data[src_ip]["dest_ports"].add(event.get("dest_port", 0))

    for fast_path in fast_paths:
        if not os.path.exists(fast_path):
            continue
        print(f"    Reading: {fast_path}")
        with open(fast_path, "r", errors="replace") as f:
            for line in f:
                line = line.strip()
                match = FAST_PATTERN.match(line)
                if not match:
                    continue

                ts, sid, rule, classification, priority, proto, \
                src_ip, src_port, dest_ip, dest_port = match.groups()

                alerts.append({
                    "timestamp": ts, "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "src_port": int(src_port), "dest_port": int(dest_port),
                    "proto": proto, "signature": rule,
                    "category": classification, "priority": int(priority),
                    "raw_json": "",
                })

                ip_data[src_ip]["alert_count"]     += 1
                ip_data[src_ip]["protocols"].add(proto)
                ip_data[src_ip]["classifications"].add(classification)
                ip_data[src_ip]["signatures"].append(rule)
                if int(priority) == 1:
                    ip_data[src_ip]["priority1_count"] += 1
                ip_data[src_ip]["dest_ports"].add(int(dest_port))

    print(f"[+] Suricata alerts      : {len(alerts)}")
    print(f"[+] Suricata unique IPs  : {len(ip_data)}")
    return alerts, ip_data


# ─── 4. DATABASE INIT ─────────────────────────────────────────────────────────

def init_db(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cowrie_sessions (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id     TEXT UNIQUE,
            src_ip         TEXT,
            dst_ip         TEXT,
            src_port       INTEGER,
            dst_port       INTEGER,
            protocol       TEXT,
            start_time     TEXT,
            end_time       TEXT,
            duration       REAL,
            client_version TEXT,
            sensor         TEXT
        );

        CREATE TABLE IF NOT EXISTS cowrie_logins (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            src_ip     TEXT,
            username   TEXT,
            password   TEXT,
            success    INTEGER,
            timestamp  TEXT
        );

        CREATE TABLE IF NOT EXISTS cowrie_commands (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            src_ip     TEXT,
            command    TEXT,
            is_unique  INTEGER,
            timestamp  TEXT
        );

        CREATE TABLE IF NOT EXISTS dionaea_events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            module    TEXT,
            level     TEXT,
            message   TEXT,
            src_ip    TEXT
        );

        CREATE TABLE IF NOT EXISTS suricata_alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT,
            src_ip     TEXT,
            dest_ip    TEXT,
            src_port   INTEGER,
            dest_port  INTEGER,
            proto      TEXT,
            signature  TEXT,
            category   TEXT,
            priority   INTEGER,
            raw_json   TEXT
        );

        CREATE TABLE IF NOT EXISTS ml_features (
            id                        INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip                    TEXT UNIQUE,
            source                    TEXT,
            session_count             INTEGER DEFAULT 0,
            login_success_rate        REAL    DEFAULT 0,
            login_failure_count       INTEGER DEFAULT 0,
            total_login_attempts      INTEGER DEFAULT 0,
            command_count             INTEGER DEFAULT 0,
            unique_command_count      INTEGER DEFAULT 0,
            avg_session_duration      REAL    DEFAULT 0,
            max_session_duration      REAL    DEFAULT 0,
            default_cred_attempts     INTEGER DEFAULT 0,
            cowrie_download_attempts  INTEGER DEFAULT 0,
            dionaea_connections       INTEGER DEFAULT 0,
            dionaea_download_attempts INTEGER DEFAULT 0,
            dionaea_protocol_count    INTEGER DEFAULT 0,
            dionaea_error_count       INTEGER DEFAULT 0,
            suricata_alert_count      INTEGER DEFAULT 0,
            suricata_priority1_count  INTEGER DEFAULT 0,
            suricata_proto_count      INTEGER DEFAULT 0,
            suricata_unique_sigs      INTEGER DEFAULT 0,
            total_threat_score        REAL    DEFAULT 0,
            label                     TEXT    DEFAULT 'malicious'
        );
    """)
    conn.commit()


# ─── 5. INSERT DATA ───────────────────────────────────────────────────────────

def insert_cowrie(conn, sessions, logins, commands):
    for s in sessions.values():
        conn.execute("""
            INSERT INTO cowrie_sessions
                (session_id,src_ip,dst_ip,src_port,dst_port,protocol,
                 start_time,end_time,duration,client_version,sensor)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(session_id) DO UPDATE SET
                end_time=excluded.end_time,
                duration=excluded.duration,
                client_version=excluded.client_version
        """, (s["session_id"],s["src_ip"],s["dst_ip"],s["src_port"],
              s["dst_port"],s["protocol"],s["start_time"],s["end_time"],
              s["duration"],s["client_version"],s["sensor"]))

    seen = defaultdict(set)
    for l in logins:
        conn.execute("""
            INSERT INTO cowrie_logins
                (session_id,src_ip,username,password,success,timestamp)
            VALUES (?,?,?,?,?,?)
        """, (l["session_id"],l["src_ip"],l["username"],
              l["password"],l["success"],l["timestamp"]))

    for c in commands:
        is_unique = 1 if c["command"] not in seen[c["session_id"]] else 0
        seen[c["session_id"]].add(c["command"])
        conn.execute("""
            INSERT INTO cowrie_commands
                (session_id,src_ip,command,is_unique,timestamp)
            VALUES (?,?,?,?,?)
        """, (c["session_id"],c["src_ip"],c["command"],is_unique,c["timestamp"]))

    conn.commit()


def insert_dionaea(conn, events):
    for e in events:
        conn.execute("""
            INSERT INTO dionaea_events (timestamp,module,level,message,src_ip)
            VALUES (?,?,?,?,?)
        """, (e["timestamp"],e["module"],e["level"],e["message"],e["src_ip"]))
    conn.commit()


def insert_suricata(conn, alerts):
    for a in alerts:
        conn.execute("""
            INSERT INTO suricata_alerts
                (timestamp,src_ip,dest_ip,src_port,dest_port,
                 proto,signature,category,priority,raw_json)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (a["timestamp"],a["src_ip"],a["dest_ip"],a["src_port"],
              a["dest_port"],a["proto"],a["signature"],
              a["category"],a["priority"],a["raw_json"]))
    conn.commit()


def build_ml_features(conn, cowrie_ip, dionaea_ip, suricata_ip):
    all_ips = set(cowrie_ip.keys()) | set(dionaea_ip.keys()) | set(suricata_ip.keys())
    all_ips.discard("unknown")

    rows = 0
    for ip in all_ips:
        c = cowrie_ip.get(ip, {})
        d = dionaea_ip.get(ip, {})
        s = suricata_ip.get(ip, {})

        total_logins = c.get("login_success", 0) + c.get("login_failure", 0)
        login_rate   = round(c.get("login_success", 0) / total_logins, 2) if total_logins > 0 else 0.0
        durations    = c.get("session_durations", [])
        avg_dur      = round(sum(durations) / len(durations), 2) if durations else 0.0
        max_dur      = round(max(durations), 2) if durations else 0.0
        unique_cmds  = len(set(c.get("commands", [])))
        d_errors     = sum(1 for e in d.get("events", []) if e in ["error", "critical"])
        unique_sigs  = len(set(s.get("signatures", [])))

        threat_score = round(
            (c.get("login_failure", 0)         * 0.3) +
            (c.get("default_cred_attempts", 0) * 2.0) +
            (c.get("download_attempts", 0)     * 3.0) +
            (c.get("command_count", 0)         * 0.1) +
            (d.get("connection_count", 0)      * 0.2) +
            (d.get("download_attempts", 0)     * 2.0) +
            (s.get("alert_count", 0)           * 0.5) +
            (s.get("priority1_count", 0)       * 3.0),
        2)

        sources = []
        if ip in cowrie_ip:   sources.append("cowrie")
        if ip in dionaea_ip:  sources.append("dionaea")
        if ip in suricata_ip: sources.append("suricata")
        source = "+".join(sources)

        conn.execute("""
            INSERT INTO ml_features (
                src_ip, source,
                session_count, login_success_rate, login_failure_count,
                total_login_attempts, command_count, unique_command_count,
                avg_session_duration, max_session_duration,
                default_cred_attempts, cowrie_download_attempts,
                dionaea_connections, dionaea_download_attempts,
                dionaea_protocol_count, dionaea_error_count,
                suricata_alert_count, suricata_priority1_count,
                suricata_proto_count, suricata_unique_sigs,
                total_threat_score, label
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(src_ip) DO UPDATE SET
                source=excluded.source,
                session_count=excluded.session_count,
                login_success_rate=excluded.login_success_rate,
                login_failure_count=excluded.login_failure_count,
                total_login_attempts=excluded.total_login_attempts,
                command_count=excluded.command_count,
                unique_command_count=excluded.unique_command_count,
                avg_session_duration=excluded.avg_session_duration,
                max_session_duration=excluded.max_session_duration,
                default_cred_attempts=excluded.default_cred_attempts,
                cowrie_download_attempts=excluded.cowrie_download_attempts,
                dionaea_connections=excluded.dionaea_connections,
                dionaea_download_attempts=excluded.dionaea_download_attempts,
                dionaea_protocol_count=excluded.dionaea_protocol_count,
                dionaea_error_count=excluded.dionaea_error_count,
                suricata_alert_count=excluded.suricata_alert_count,
                suricata_priority1_count=excluded.suricata_priority1_count,
                suricata_proto_count=excluded.suricata_proto_count,
                suricata_unique_sigs=excluded.suricata_unique_sigs,
                total_threat_score=excluded.total_threat_score,
                label=excluded.label
        """, (
            ip, source,
            len(c.get("session_ids", set())), login_rate,
            c.get("login_failure", 0), total_logins,
            c.get("command_count", 0), unique_cmds,
            avg_dur, max_dur,
            c.get("default_cred_attempts", 0), c.get("download_attempts", 0),
            d.get("connection_count", 0), d.get("download_attempts", 0),
            len(d.get("protocols", set())), d_errors,
            s.get("alert_count", 0), s.get("priority1_count", 0),
            len(s.get("protocols", set())), unique_sigs,
            threat_score, "malicious"
        ))
        rows += 1

    conn.commit()
    print(f"[+] ML features          : {rows} rows")


# ─── 6. CSV EXPORT ────────────────────────────────────────────────────────────

def export_csv(conn, path):
    cursor = conn.execute("SELECT * FROM ml_features")
    cols   = [d[0] for d in cursor.description]
    rows   = cursor.fetchall()
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        writer.writerows(rows)
    print(f"[+] CSV exported         : {path} ({len(rows)} rows, {len(cols)} cols)")


# ─── 7. MAIN ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  Unified Honeypot Log Parser")
    print("  Sources: Cowrie + Dionaea + Suricata")
    print("=" * 55)

    print(f"\n[*] Output directory     : {PROJECT_DIR}")
    print(f"[*] Database             : {DB_PATH}")
    print(f"[*] CSV                  : {CSV_PATH}")

    print(f"\n[*] Found {len(COWRIE_LOGS)} Cowrie log file(s)")
    print(f"[*] Found {len(SURICATA_EVES)} Suricata eve.json file(s)")
    print(f"[*] Found {len(SURICATA_FASTS)} Suricata fast.log file(s)")

    print("\n[*] Parsing Cowrie logs...")
    sessions, logins, commands, _, cowrie_ip = parse_cowrie_logs(COWRIE_LOGS)

    print("\n[*] Parsing Dionaea logs...")
    dionaea_events, dionaea_ip = parse_dionaea_log(DIONAEA_LOG)

    print("\n[*] Parsing Suricata logs...")
    suricata_alerts, suricata_ip = parse_suricata_logs(SURICATA_EVES, SURICATA_FASTS)

    print("\n[*] Building database...")
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    insert_cowrie(conn, sessions, logins, commands)
    insert_dionaea(conn, dionaea_events)
    insert_suricata(conn, suricata_alerts)

    print("\n[*] Building ML features...")
    build_ml_features(conn, cowrie_ip, dionaea_ip, suricata_ip)

    print("\n[*] Exporting CSV...")
    export_csv(conn, CSV_PATH)
    conn.close()

    print("\n[✓] Done! Files saved to:")
    print(f"    DB  → {DB_PATH}")
    print(f"    CSV → {CSV_PATH}")


if __name__ == "__main__":
    main()
