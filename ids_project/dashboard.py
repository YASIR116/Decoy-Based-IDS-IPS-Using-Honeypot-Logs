#!/usr/bin/env python3
"""
IDS/IPS Dashboard — dashboard.py
Run with: python3 ~/ids_project/dashboard.py
Then open: http://192.168.0.8:5000
"""

import os, subprocess, signal, json, re, threading, time
from datetime import datetime
from collections import deque
from flask import Flask, jsonify, render_template_string, request

# ─── PATHS ────────────────────────────────────────────────────────────────────
USER_HOME    = "/home/jeyabalan"
BASE_DIR     = f"{USER_HOME}/ids_project"
VENV_PYTHON  = f"{USER_HOME}/cowrie-env/bin/python3"
MAIN_PY      = f"{BASE_DIR}/main.py"
START_SH     = f"{USER_HOME}/start_honeypot.sh"
STOP_SH      = f"{USER_HOME}/stop_honeypot.sh"
DETECT_LOG   = f"{BASE_DIR}/logs/detections.log"
BLOCK_LOG    = f"{BASE_DIR}/logs/blocked.log"

# ─── STATE ────────────────────────────────────────────────────────────────────
detection_proc  = None          # subprocess for main.py
live_log_buffer = deque(maxlen=200)   # last 200 log lines
log_lock        = threading.Lock()

app = Flask(__name__)

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def run_cmd(cmd, use_sudo=False, timeout=10):
    try:
        full = (["sudo"] if use_sudo else []) + cmd
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return True, "Command launched (running in background)"
    except Exception as e:
        return False, str(e)

def run_bg(cmd):
    """Fire and forget — for start/stop scripts that take long."""
    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        return True, "Launched in background"
    except Exception as e:
        return False, str(e)

def proc_running(name):
    r = subprocess.run(["pgrep", "-f", name], capture_output=True, text=True)
    return r.returncode == 0

def docker_running(container):
    r = subprocess.run(["docker", "ps", "--filter", f"name={container}",
                        "--format", "{{.Names}}"], capture_output=True, text=True)
    return container in r.stdout

def get_status():
    return {
        "cowrie":   proc_running("twistd"),
        "dionaea":  docker_running("dionaea"),
        "suricata": proc_running("suricata"),
        "detection": detection_proc is not None and detection_proc.poll() is None,
    }

def get_blocked_ips():
    """
    Read blocked IPs from blocked.log (written by main.py).
    Cross-check with live iptables to show only currently active blocks.
    """
    result = []
    seen = set()

    # Get currently active iptables DROP rules
    try:
        ipt = subprocess.run(
            ["sudo", "iptables", "-L", "INPUT", "-n"],
            capture_output=True, text=True
        )
        ipt_lines = ipt.stdout
    except Exception:
        ipt_lines = ""

    # Parse blocked.log — format: [YYYY-MM-DD HH:MM:SS] BLOCKED <ip> | Reason: ...
    if os.path.exists(BLOCK_LOG):
        try:
            with open(BLOCK_LOG) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    ts_match  = re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]', line)
                    blocked_at = ts_match.group(1) if ts_match else ""
                    ip_match  = re.search(r'BLOCKED\s+([\d\.]+)', line)
                    if not ip_match:
                        continue
                    ip = ip_match.group(1)
                    if ip in seen:
                        continue
                    reason_match = re.search(r'Reason:\s*(.+)', line)
                    reason = reason_match.group(1).strip() if reason_match else "ML detection"
                    if ip in ipt_lines:
                        seen.add(ip)
                        result.append({"ip": ip, "blocked_at": blocked_at, "reason": reason})
        except Exception:
            pass

    # Fallback: parse iptables directly for any IPs not in log
    try:
        for line in ipt_lines.splitlines():
            if "DROP" in line:
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    ip = ip_match.group(1)
                    if ip not in seen and ip not in ("0.0.0.0",):
                        seen.add(ip)
                        result.append({"ip": ip, "blocked_at": "active", "reason": "iptables rule"})
    except Exception:
        pass

    return result

def read_log_tail(path, n=50):
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            lines = f.readlines()
        return [l.strip() for l in lines[-n:] if l.strip()]
    except Exception:
        return []

def stream_detection_output(proc):
    """Background thread: read main.py stdout into buffer."""
    for line in iter(proc.stdout.readline, ""):
        line = line.strip()
        if line:
            ts = datetime.now().strftime("%H:%M:%S")
            with log_lock:
                live_log_buffer.append({"time": ts, "msg": line})
    # Process ended
    with log_lock:
        live_log_buffer.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "msg": "[Detection process ended]"
        })

# ─── API ROUTES ───────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    return jsonify(get_status())

@app.route("/api/honeypot/start", methods=["POST"])
@app.route("/api/honeypot/start", methods=["POST"])
def honeypot_start():
    ok, out = run_bg(["bash", START_SH])
    return jsonify({"ok": ok, "output": "Honeypot starting in background..."})

@app.route("/api/honeypot/stop", methods=["POST"])
def honeypot_stop():
    ok, out = run_bg(["bash", STOP_SH])
    return jsonify({"ok": ok, "output": "Honeypot stopping in background..."})

@app.route("/api/detection/start", methods=["POST"])
def detection_start():
    global detection_proc
    if detection_proc and detection_proc.poll() is None:
        return jsonify({"ok": False, "msg": "Detection already running"})
    try:
        detection_proc = subprocess.Popen(
            ["sudo", VENV_PYTHON, MAIN_PY],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        t = threading.Thread(target=stream_detection_output,
                             args=(detection_proc,), daemon=True)
        t.start()
        with log_lock:
            live_log_buffer.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "msg": "[Detection started — PID " + str(detection_proc.pid) + "]"
            })
        return jsonify({"ok": True, "pid": detection_proc.pid})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})

@app.route("/api/detection/stop", methods=["POST"])
def detection_stop():
    global detection_proc
    if not detection_proc or detection_proc.poll() is not None:
        return jsonify({"ok": False, "msg": "Detection not running"})
    try:
        subprocess.run(["sudo", "kill", str(detection_proc.pid)],
                       capture_output=True)
        detection_proc = None
        with log_lock:
            live_log_buffer.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "msg": "[Detection stopped by user]"
            })
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})

@app.route("/api/logs/live")
def api_logs_live():
    with log_lock:
        return jsonify(list(live_log_buffer))

@app.route("/api/logs/detections")
def api_logs_detections():
    return jsonify(read_log_tail(DETECT_LOG, 100))

@app.route("/api/blocked")
def api_blocked():
    return jsonify(get_blocked_ips())

@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    ip = request.json.get("ip", "")
    if not ip:
        return jsonify({"ok": False})
    ok, out = run_cmd(
        [VENV_PYTHON, f"{BASE_DIR}/blocker.py", "unblock", ip]
    )
    return jsonify({"ok": ok, "output": out})

@app.route("/api/unblock_all", methods=["POST"])
def api_unblock_all():
    ok, out = run_cmd([VENV_PYTHON, f"{BASE_DIR}/blocker.py", "unblock-all"])
    return jsonify({"ok": ok, "output": out})

@app.route("/api/stats")
def api_stats():
    blocked = get_blocked_ips()
    det_lines = read_log_tail(DETECT_LOG, 1000)
    return jsonify({
        "total_blocked":    len(blocked),
        "total_detections": len(det_lines),
        "uptime":           datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })

# ─── HTML DASHBOARD ───────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HoneyShield — IDS/IPS Control</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:        #050a0e;
    --panel:     #0a1520;
    --border:    #0d2137;
    --accent:    #00d4ff;
    --green:     #00ff88;
    --red:       #ff3355;
    --yellow:    #ffcc00;
    --dim:       #2a4a6a;
    --text:      #c8e8ff;
    --textdim:   #4a7a9a;
    --mono:      'Share Tech Mono', monospace;
    --sans:      'Rajdhani', sans-serif;
  }

  * { margin:0; padding:0; box-sizing:border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Scanline effect */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,212,255,0.015) 2px,
      rgba(0,212,255,0.015) 4px
    );
    pointer-events: none;
    z-index: 9999;
  }

  /* Grid bg */
  body::after {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,212,255,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,0.04) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  /* ── HEADER ── */
  header {
    position: relative;
    z-index: 10;
    padding: 20px 32px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: linear-gradient(180deg, rgba(0,212,255,0.06) 0%, transparent 100%);
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .logo-icon {
    width: 42px; height: 42px;
    border: 2px solid var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
    box-shadow: 0 0 20px rgba(0,212,255,0.4), inset 0 0 10px rgba(0,212,255,0.1);
    animation: pulse 3s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { box-shadow: 0 0 20px rgba(0,212,255,0.4), inset 0 0 10px rgba(0,212,255,0.1); }
    50%       { box-shadow: 0 0 35px rgba(0,212,255,0.7), inset 0 0 15px rgba(0,212,255,0.2); }
  }

  .logo-text h1 {
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 4px;
    color: var(--accent);
    text-shadow: 0 0 20px rgba(0,212,255,0.6);
  }

  .logo-text p {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--textdim);
    letter-spacing: 2px;
  }

  .header-time {
    font-family: var(--mono);
    font-size: 13px;
    color: var(--textdim);
    text-align: right;
  }

  #clock { color: var(--accent); font-size: 16px; display: block; margin-top: 2px; }

  /* ── LAYOUT ── */
  .container {
    position: relative;
    z-index: 10;
    max-width: 1400px;
    margin: 0 auto;
    padding: 24px 32px;
    display: grid;
    grid-template-columns: 340px 1fr;
    grid-template-rows: auto auto 1fr;
    gap: 20px;
  }

  /* ── PANELS ── */
  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }

  .panel-header {
    padding: 12px 18px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 10px;
    background: rgba(0,212,255,0.04);
  }

  .panel-header h2 {
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 3px;
    color: var(--accent);
  }

  .panel-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--accent);
    box-shadow: 0 0 8px var(--accent);
  }

  .panel-body { padding: 18px; }

  /* ── STAT CARDS ── */
  .stats-row {
    grid-column: 1 / -1;
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
  }

  .stat-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 18px 20px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.3s;
  }

  .stat-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: var(--accent-color, var(--accent));
    box-shadow: 0 0 12px var(--accent-color, var(--accent));
  }

  .stat-card.green  { --accent-color: var(--green); }
  .stat-card.red    { --accent-color: var(--red); }
  .stat-card.yellow { --accent-color: var(--yellow); }

  .stat-label {
    font-size: 10px;
    letter-spacing: 2px;
    color: var(--textdim);
    margin-bottom: 10px;
  }

  .stat-value {
    font-family: var(--mono);
    font-size: 32px;
    color: var(--accent-color, var(--accent));
    text-shadow: 0 0 20px var(--accent-color, var(--accent));
    line-height: 1;
  }

  .stat-sub {
    font-size: 11px;
    color: var(--textdim);
    margin-top: 6px;
  }

  /* ── SERVICE STATUS ── */
  .service-list { display: flex; flex-direction: column; gap: 10px; }

  .service-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 14px;
    background: rgba(0,0,0,0.3);
    border-radius: 6px;
    border: 1px solid var(--border);
    transition: border-color 0.3s;
  }

  .service-item.active { border-color: rgba(0,255,136,0.3); }

  .service-left { display: flex; align-items: center; gap: 12px; }

  .service-indicator {
    width: 10px; height: 10px;
    border-radius: 50%;
    background: var(--dim);
    transition: all 0.5s;
    flex-shrink: 0;
  }

  .service-indicator.on {
    background: var(--green);
    box-shadow: 0 0 10px var(--green), 0 0 20px rgba(0,255,136,0.4);
    animation: blink 2s ease-in-out infinite;
  }

  .service-indicator.off { background: var(--dim); }

  @keyframes blink {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.5; }
  }

  .service-name { font-size: 14px; font-weight: 600; letter-spacing: 1px; }
  .service-desc { font-size: 11px; color: var(--textdim); }

  .service-badge {
    font-family: var(--mono);
    font-size: 10px;
    padding: 3px 8px;
    border-radius: 4px;
    letter-spacing: 1px;
    transition: all 0.3s;
  }

  .badge-on  { background: rgba(0,255,136,0.15); color: var(--green);  border: 1px solid rgba(0,255,136,0.3); }
  .badge-off { background: rgba(255,51,85,0.1);  color: var(--red);    border: 1px solid rgba(255,51,85,0.2); }

  /* ── CONTROL BUTTONS ── */
  .controls { display: flex; flex-direction: column; gap: 10px; margin-top: 10px; }

  .control-group { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }

  .btn {
    padding: 11px 14px;
    border-radius: 6px;
    border: 1px solid;
    font-family: var(--sans);
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 2px;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    position: relative;
    overflow: hidden;
  }

  .btn::after {
    content: '';
    position: absolute;
    inset: 0;
    opacity: 0;
    transition: opacity 0.2s;
    background: currentColor;
  }

  .btn:hover::after { opacity: 0.08; }
  .btn:active { transform: scale(0.97); }

  .btn-start {
    background: rgba(0,255,136,0.08);
    border-color: rgba(0,255,136,0.4);
    color: var(--green);
  }

  .btn-stop {
    background: rgba(255,51,85,0.08);
    border-color: rgba(255,51,85,0.3);
    color: var(--red);
  }

  .btn-detect {
    background: rgba(0,212,255,0.08);
    border-color: rgba(0,212,255,0.4);
    color: var(--accent);
    grid-column: 1 / -1;
    padding: 13px;
    font-size: 13px;
  }

  .btn-detect.active {
    background: rgba(0,212,255,0.15);
    border-color: var(--accent);
    box-shadow: 0 0 20px rgba(0,212,255,0.2);
  }

  .btn-danger {
    background: rgba(255,51,85,0.06);
    border-color: rgba(255,51,85,0.2);
    color: var(--red);
    font-size: 11px;
    padding: 8px;
  }

  .btn:disabled {
    opacity: 0.35;
    cursor: not-allowed;
    transform: none !important;
  }

  /* spinning indicator */
  .spin { display: inline-block; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── LOG TERMINAL ── */
  .log-terminal {
    background: #020c14;
    border-radius: 6px;
    border: 1px solid var(--border);
    height: 340px;
    overflow-y: auto;
    padding: 12px;
    font-family: var(--mono);
    font-size: 12px;
    scroll-behavior: smooth;
  }

  .log-terminal::-webkit-scrollbar { width: 4px; }
  .log-terminal::-webkit-scrollbar-track { background: transparent; }
  .log-terminal::-webkit-scrollbar-thumb { background: var(--dim); border-radius: 2px; }

  .log-line {
    display: flex;
    gap: 10px;
    padding: 2px 0;
    line-height: 1.6;
    border-bottom: 1px solid rgba(255,255,255,0.02);
    animation: fadein 0.3s ease;
  }

  @keyframes fadein { from { opacity: 0; transform: translateX(-4px); } to { opacity: 1; transform: none; } }

  .log-time { color: var(--dim); flex-shrink: 0; }

  .log-msg { color: var(--text); flex: 1; word-break: break-all; }
  .log-msg.block  { color: var(--red);    font-weight: bold; }
  .log-msg.detect { color: var(--yellow); }
  .log-msg.start  { color: var(--green);  }
  .log-msg.info   { color: var(--textdim); }

  /* ── BLOCKED IPS ── */
  .blocked-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-height: 280px;
    overflow-y: auto;
  }

  .blocked-list::-webkit-scrollbar { width: 4px; }
  .blocked-list::-webkit-scrollbar-thumb { background: var(--dim); border-radius: 2px; }

  .blocked-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    background: rgba(255,51,85,0.05);
    border: 1px solid rgba(255,51,85,0.2);
    border-radius: 6px;
    animation: fadein 0.4s ease;
  }

  .blocked-ip {
    font-family: var(--mono);
    font-size: 13px;
    color: var(--red);
  }

  .blocked-meta { font-size: 11px; color: var(--textdim); margin-top: 2px; }

  .btn-unblock {
    background: transparent;
    border: 1px solid rgba(255,51,85,0.3);
    color: var(--red);
    font-family: var(--mono);
    font-size: 10px;
    padding: 4px 8px;
    border-radius: 4px;
    cursor: pointer;
    letter-spacing: 1px;
    transition: all 0.2s;
    flex-shrink: 0;
  }

  .btn-unblock:hover { background: rgba(255,51,85,0.15); }

  .empty-state {
    text-align: center;
    color: var(--textdim);
    font-family: var(--mono);
    font-size: 12px;
    padding: 30px;
  }

  /* ── RIGHT COLUMN ── */
  .right-col {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  /* ── TOAST ── */
  #toast {
    position: fixed;
    bottom: 24px;
    right: 24px;
    z-index: 9999;
    background: var(--panel);
    border: 1px solid var(--accent);
    border-radius: 8px;
    padding: 12px 20px;
    font-family: var(--mono);
    font-size: 13px;
    color: var(--accent);
    box-shadow: 0 0 30px rgba(0,212,255,0.3);
    opacity: 0;
    transform: translateY(10px);
    transition: all 0.3s;
    max-width: 360px;
  }

  #toast.show { opacity: 1; transform: translateY(0); }
  #toast.error { border-color: var(--red); color: var(--red); box-shadow: 0 0 30px rgba(255,51,85,0.3); }

  /* ── DETECTION LOG TABS ── */
  .tabs {
    display: flex;
    gap: 2px;
    padding: 0 18px;
    background: rgba(0,0,0,0.3);
    border-bottom: 1px solid var(--border);
  }

  .tab {
    padding: 10px 16px;
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--textdim);
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: all 0.2s;
  }

  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab:hover  { color: var(--text); }

  .tab-panel { display: none; }
  .tab-panel.active { display: block; padding: 14px 18px; }

  /* ── THREAT METER ── */
  .threat-level {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-top: 10px;
  }

  .threat-bar-wrap {
    flex: 1;
    height: 6px;
    background: rgba(255,255,255,0.05);
    border-radius: 3px;
    overflow: hidden;
  }

  .threat-bar {
    height: 100%;
    border-radius: 3px;
    transition: width 1s ease, background 1s ease;
    background: var(--green);
  }

  .threat-label {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--textdim);
    width: 60px;
    text-align: right;
  }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">🛡</div>
    <div class="logo-text">
      <h1>HONEYSHIELD</h1>
      <p>DECOY-BASED IDS/IPS CONTROL PANEL</p>
    </div>
  </div>
  <div class="header-time">
    <span style="letter-spacing:2px;font-size:11px;">SYSTEM TIME</span>
    <span id="clock">--:--:--</span>
  </div>
</header>

<div class="container">

  <!-- STAT CARDS -->
  <div class="stats-row">
    <div class="stat-card">
      <div class="stat-label">TOTAL BLOCKED</div>
      <div class="stat-value" id="stat-blocked">0</div>
      <div class="stat-sub">IPs in iptables</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">DETECTIONS</div>
      <div class="stat-value" id="stat-detections">0</div>
      <div class="stat-sub">logged threats</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-label">ACTIVE SERVICES</div>
      <div class="stat-value" id="stat-services">0<span style="font-size:16px;color:var(--textdim)">/3</span></div>
      <div class="stat-sub">honeypot components</div>
    </div>
    <div class="stat-card red">
      <div class="stat-label">DETECTION ENGINE</div>
      <div class="stat-value" id="stat-engine" style="font-size:18px;padding-top:6px;">OFFLINE</div>
      <div class="stat-sub" id="stat-engine-sub">ML models idle</div>
    </div>
  </div>

  <!-- LEFT COLUMN: Controls -->
  <div style="display:flex;flex-direction:column;gap:20px;">

    <!-- Services Status -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-dot"></div>
        <h2>HONEYPOT SERVICES</h2>
      </div>
      <div class="panel-body">
        <div class="service-list">
          <div class="service-item" id="svc-cowrie">
            <div class="service-left">
              <div class="service-indicator off" id="ind-cowrie"></div>
              <div>
                <div class="service-name">COWRIE</div>
                <div class="service-desc">SSH / Telnet · Port 2222</div>
              </div>
            </div>
            <span class="service-badge badge-off" id="badge-cowrie">OFFLINE</span>
          </div>
          <div class="service-item" id="svc-dionaea">
            <div class="service-left">
              <div class="service-indicator off" id="ind-dionaea"></div>
              <div>
                <div class="service-name">DIONAEA</div>
                <div class="service-desc">FTP / HTTP / SMB / MySQL</div>
              </div>
            </div>
            <span class="service-badge badge-off" id="badge-dionaea">OFFLINE</span>
          </div>
          <div class="service-item" id="svc-suricata">
            <div class="service-left">
              <div class="service-indicator off" id="ind-suricata"></div>
              <div>
                <div class="service-name">SURICATA</div>
                <div class="service-desc">Network IDS · eth0</div>
              </div>
            </div>
            <span class="service-badge badge-off" id="badge-suricata">OFFLINE</span>
          </div>
        </div>

        <!-- Threat meter -->
        <div style="margin-top:18px;">
          <div style="font-size:11px;letter-spacing:2px;color:var(--textdim);margin-bottom:8px;">THREAT LEVEL</div>
          <div class="threat-level">
            <div class="threat-bar-wrap">
              <div class="threat-bar" id="threat-bar" style="width:0%"></div>
            </div>
            <div class="threat-label" id="threat-label">LOW</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Controls -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-dot"></div>
        <h2>CONTROLS</h2>
      </div>
      <div class="panel-body">
        <div class="controls">
          <div style="font-size:11px;letter-spacing:2px;color:var(--textdim);margin-bottom:4px;">HONEYPOT</div>
          <div class="control-group">
            <button class="btn btn-start" id="btn-hstart" onclick="honeypotStart()">
              ▶ START
            </button>
            <button class="btn btn-stop" id="btn-hstop" onclick="honeypotStop()">
              ■ STOP
            </button>
          </div>

          <div style="height:8px;"></div>
          <div style="font-size:11px;letter-spacing:2px;color:var(--textdim);margin-bottom:4px;">DETECTION ENGINE</div>
          <div class="control-group">
            <button class="btn btn-detect" id="btn-detect" onclick="toggleDetection()">
              ⬡ START DETECTION
            </button>
          </div>

          <div style="height:8px;"></div>
          <div style="font-size:11px;letter-spacing:2px;color:var(--textdim);margin-bottom:4px;">FIREWALL</div>
          <button class="btn btn-danger" onclick="unblockAll()" style="width:100%">
            ✕ UNBLOCK ALL IPs
          </button>
        </div>
      </div>
    </div>

  </div><!-- end left col -->

  <!-- RIGHT COLUMN -->
  <div class="right-col">

    <!-- Live Log -->
    <div class="panel" style="flex:1;">
      <div class="panel-header">
        <div class="panel-dot"></div>
        <h2>LIVE MONITOR</h2>
        <div style="margin-left:auto;display:flex;gap:8px;">
          <button onclick="clearLog()" style="background:transparent;border:1px solid var(--border);color:var(--textdim);font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:4px;cursor:pointer;letter-spacing:1px;">CLEAR</button>
          <button onclick="toggleAutoScroll()" id="btn-scroll" style="background:transparent;border:1px solid var(--border);color:var(--accent);font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:4px;cursor:pointer;letter-spacing:1px;">AUTO-SCROLL ON</button>
        </div>
      </div>

      <div class="tabs">
        <div class="tab active" onclick="switchTab('live', this)">LIVE OUTPUT</div>
        <div class="tab" onclick="switchTab('detections', this)">DETECTIONS</div>
      </div>

      <div class="tab-panel active" id="tab-live">
        <div class="log-terminal" id="log-live">
          <div class="log-line">
            <span class="log-time">--:--:--</span>
            <span class="log-msg info">Waiting for detection engine to start...</span>
          </div>
        </div>
      </div>

      <div class="tab-panel" id="tab-detections">
        <div class="log-terminal" id="log-detections">
          <div class="log-line">
            <span class="log-time">--:--:--</span>
            <span class="log-msg info">No detections yet.</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Blocked IPs -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-dot" style="background:var(--red);box-shadow:0 0 8px var(--red);"></div>
        <h2>BLOCKED IPs</h2>
        <span id="blocked-count" style="margin-left:auto;font-family:var(--mono);font-size:12px;color:var(--red);">0 active</span>
      </div>
      <div class="panel-body">
        <div class="blocked-list" id="blocked-list">
          <div class="empty-state">[ NO IPs BLOCKED ]</div>
        </div>
      </div>
    </div>

  </div><!-- end right col -->

</div><!-- end container -->

<!-- Toast -->
<div id="toast"></div>

<script>
// ── STATE ──────────────────────────────────────────────────────────────────
let detectionRunning = false;
let autoScroll = true;
let lastLogCount = 0;
let lastDetCount = 0;

// ── CLOCK ──────────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toTimeString().split(' ')[0];
}
setInterval(updateClock, 1000);
updateClock();

// ── TOAST ──────────────────────────────────────────────────────────────────
function toast(msg, isError=false) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'show' + (isError ? ' error' : '');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.className = '', 3500);
}

// ── TAB SWITCH ─────────────────────────────────────────────────────────────
function switchTab(name, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
}

// ── AUTO SCROLL ────────────────────────────────────────────────────────────
function toggleAutoScroll() {
  autoScroll = !autoScroll;
  document.getElementById('btn-scroll').textContent =
    'AUTO-SCROLL ' + (autoScroll ? 'ON' : 'OFF');
}

function clearLog() {
  document.getElementById('log-live').innerHTML = '';
  lastLogCount = 0;
}

// ── STATUS POLL ────────────────────────────────────────────────────────────
function updateStatus(status) {
  const services = { cowrie: 'cowrie', dionaea: 'dionaea', suricata: 'suricata' };
  let activeCount = 0;

  for (const [key, id] of Object.entries(services)) {
    const on = status[key];
    if (on) activeCount++;
    const ind = document.getElementById('ind-' + id);
    const badge = document.getElementById('badge-' + id);
    const item = document.getElementById('svc-' + id);
    ind.className = 'service-indicator ' + (on ? 'on' : 'off');
    badge.className = 'service-badge ' + (on ? 'badge-on' : 'badge-off');
    badge.textContent = on ? 'ONLINE' : 'OFFLINE';
    item.className = 'service-item' + (on ? ' active' : '');
  }

  document.getElementById('stat-services').innerHTML =
    activeCount + '<span style="font-size:16px;color:var(--textdim)">/3</span>';

  // Detection engine status
  const detOn = status.detection;
  detectionRunning = detOn;
  const engEl = document.getElementById('stat-engine');
  engEl.textContent = detOn ? 'ONLINE' : 'OFFLINE';
  engEl.style.color = detOn ? 'var(--green)' : 'var(--red)';
  engEl.style.textShadow = detOn ? '0 0 20px var(--green)' : 'none';
  document.getElementById('stat-engine-sub').textContent =
    detOn ? 'ML models active' : 'ML models idle';

  const btn = document.getElementById('btn-detect');
  btn.textContent = detOn ? '⬡ STOP DETECTION' : '⬡ START DETECTION';
  btn.className = 'btn btn-detect' + (detOn ? ' active' : '');

  // Threat meter
  const pct = Math.min(100, activeCount * 25 + (detOn ? 25 : 0));
  updateThreatMeter(pct, activeCount, detOn);
}

function updateThreatMeter(pct, services, detection) {
  const bar = document.getElementById('threat-bar');
  const lbl = document.getElementById('threat-label');
  bar.style.width = pct + '%';
  if (pct === 0)       { bar.style.background = 'var(--dim)';    lbl.textContent = 'IDLE'; }
  else if (pct < 40)   { bar.style.background = 'var(--green)';  lbl.textContent = 'LOW'; }
  else if (pct < 70)   { bar.style.background = 'var(--yellow)'; lbl.textContent = 'MEDIUM'; }
  else                 { bar.style.background = 'var(--accent)';  lbl.textContent = 'ACTIVE'; }
}

async function pollStatus() {
  try {
    const r = await fetch('/api/status');
    const s = await r.json();
    updateStatus(s);
  } catch(e) {}
}

// ── STATS POLL ─────────────────────────────────────────────────────────────
async function pollStats() {
  try {
    const r = await fetch('/api/stats');
    const s = await r.json();
    document.getElementById('stat-blocked').textContent    = s.total_blocked;
    document.getElementById('stat-detections').textContent = s.total_detections;
  } catch(e) {}
}

// ── LIVE LOG POLL ──────────────────────────────────────────────────────────
function classifyMsg(msg) {
  const m = msg.toLowerCase();
  if (m.includes('block'))   return 'block';
  if (m.includes('detect') || m.includes('threat') || m.includes('fast rule')) return 'detect';
  if (m.includes('start') || m.includes('loaded') || m.includes('watching')) return 'start';
  return '';
}

async function pollLiveLog() {
  try {
    const r = await fetch('/api/logs/live');
    const lines = await r.json();
    if (lines.length === lastLogCount) return;
    lastLogCount = lines.length;

    const el = document.getElementById('log-live');
    el.innerHTML = '';
    for (const line of lines) {
      const div = document.createElement('div');
      div.className = 'log-line';
      const cls = classifyMsg(line.msg);
      div.innerHTML = `<span class="log-time">${line.time}</span><span class="log-msg ${cls}">${escHtml(line.msg)}</span>`;
      el.appendChild(div);
    }
    if (autoScroll) el.scrollTop = el.scrollHeight;
  } catch(e) {}
}

async function pollDetections() {
  try {
    const r = await fetch('/api/logs/detections');
    const lines = await r.json();
    if (lines.length === lastDetCount) return;
    lastDetCount = lines.length;

    const el = document.getElementById('log-detections');
    el.innerHTML = '';
    if (lines.length === 0) {
      el.innerHTML = '<div class="log-line"><span class="log-time">--:--:--</span><span class="log-msg info">No detections yet.</span></div>';
      return;
    }
    for (const line of lines.slice(-100)) {
      const div = document.createElement('div');
      div.className = 'log-line';
      const cls = line.toLowerCase().includes('block') ? 'block' : 'detect';
      div.innerHTML = `<span class="log-msg ${cls}">${escHtml(line)}</span>`;
      el.appendChild(div);
    }
    el.scrollTop = el.scrollHeight;
  } catch(e) {}
}

// ── BLOCKED IPs ────────────────────────────────────────────────────────────
async function pollBlocked() {
  try {
    const r = await fetch('/api/blocked');
    const ips = await r.json();
    document.getElementById('blocked-count').textContent =
      ips.length + ' active';
    const el = document.getElementById('blocked-list');
    if (ips.length === 0) {
      el.innerHTML = '<div class="empty-state">[ NO IPs BLOCKED ]</div>';
      return;
    }
    el.innerHTML = '';
    for (const item of ips) {
      el.innerHTML += `
        <div class="blocked-item">
          <div>
            <div class="blocked-ip">${escHtml(item.ip)}</div>
            <div class="blocked-meta">${escHtml(item.blocked_at)}</div>
          </div>
          <button class="btn-unblock" onclick="unblockIP('${escHtml(item.ip)}')">UNBLOCK</button>
        </div>`;
    }
  } catch(e) {}
}

// ── ACTIONS ────────────────────────────────────────────────────────────────
async function honeypotStart() {
  setBusy('btn-hstart', true);
  toast('Starting honeypots...');
  try {
    const r = await fetch('/api/honeypot/start', { method: 'POST' });
    const d = await r.json();
    toast(d.ok ? '✓ Honeypots started' : '✗ ' + d.output, !d.ok);
  } catch(e) { toast('✗ Error: ' + e, true); }
  setBusy('btn-hstart', false);
}

async function honeypotStop() {
  setBusy('btn-hstop', true);
  toast('Stopping honeypots...');
  try {
    const r = await fetch('/api/honeypot/stop', { method: 'POST' });
    const d = await r.json();
    toast(d.ok ? '✓ Honeypots stopped' : '✗ ' + d.output, !d.ok);
  } catch(e) { toast('✗ Error: ' + e, true); }
  setBusy('btn-hstop', false);
}

async function toggleDetection() {
  setBusy('btn-detect', true);
  if (!detectionRunning) {
    toast('Starting detection engine...');
    try {
      const r = await fetch('/api/detection/start', { method: 'POST' });
      const d = await r.json();
      toast(d.ok ? '✓ Detection started (PID ' + d.pid + ')' : '✗ ' + d.msg, !d.ok);
    } catch(e) { toast('✗ ' + e, true); }
  } else {
    toast('Stopping detection engine...');
    try {
      const r = await fetch('/api/detection/stop', { method: 'POST' });
      const d = await r.json();
      toast(d.ok ? '✓ Detection stopped' : '✗ ' + d.msg, !d.ok);
    } catch(e) { toast('✗ ' + e, true); }
  }
  setBusy('btn-detect', false);
  await pollStatus();
}

async function unblockIP(ip) {
  toast('Unblocking ' + ip + '...');
  try {
    const r = await fetch('/api/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    const d = await r.json();
    toast(d.ok ? '✓ Unblocked ' + ip : '✗ Failed', !d.ok);
    await pollBlocked();
  } catch(e) { toast('✗ ' + e, true); }
}

async function unblockAll() {
  if (!confirm('Unblock all IPs?')) return;
  toast('Unblocking all...');
  try {
    const r = await fetch('/api/unblock_all', { method: 'POST' });
    const d = await r.json();
    toast(d.ok ? '✓ All IPs unblocked' : '✗ Failed', !d.ok);
    await pollBlocked();
    await pollStats();
  } catch(e) { toast('✗ ' + e, true); }
}

// ── UTILS ──────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function setBusy(id, busy) {
  const btn = document.getElementById(id);
  if (!btn) return;
  btn.disabled = busy;
  if (busy) btn.dataset.orig = btn.innerHTML;
  btn.innerHTML = busy
    ? '<span class="spin">⟳</span>'
    : (btn.dataset.orig || btn.innerHTML);
}

// ── POLLING INTERVALS ──────────────────────────────────────────────────────
pollStatus();
pollStats();
pollLiveLog();
pollDetections();
pollBlocked();

setInterval(pollStatus,     2000);
setInterval(pollStats,      5000);
setInterval(pollLiveLog,    1000);
setInterval(pollDetections, 3000);
setInterval(pollBlocked,    3000);
</script>
</body>
</html>"""

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)

LOG_DIR = f"{BASE_DIR}/logs"

if __name__ == "__main__":
    os.makedirs(LOG_DIR, exist_ok=True)
    print("=" * 55)
    print("  HoneyShield Dashboard")
    print(f"  Open: http://192.168.0.8:5000")
    print("=" * 55)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
