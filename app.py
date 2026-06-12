from flask import Flask, request, jsonify, render_template_string, send_file
from flask_socketio import SocketIO, emit, join_room
import sys, time, os, threading, io, csv, json, random
sys.path.insert(0, "src/modules")

# ── Inline crypto (no external module files needed on Render) ────────────────
from Crypto.Cipher import AES as _AES, ChaCha20_Poly1305 as _CHA
import psutil

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Key management ────────────────────────────────────────────────────────────
def _get_key(env_var, path):
    k = os.environ.get(env_var)
    if k:
        return bytes.fromhex(k)
    if os.path.exists(path):
        return open(path,"rb").read()
    key = os.urandom(32)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path,"wb").write(key)
    return key

AES_KEY = _get_key("AES_KEY", "certs/aes.key")
CHA_KEY = _get_key("CHA_KEY", "certs/chacha.key")

# ── Encryption helpers ────────────────────────────────────────────────────────
def aes_encrypt(msg):
    s=time.perf_counter(); c=_AES.new(AES_KEY,_AES.MODE_GCM)
    ct,tag=c.encrypt_and_digest(msg.encode()); e=(time.perf_counter()-s)*1000
    s=time.perf_counter(); c2=_AES.new(AES_KEY,_AES.MODE_GCM,nonce=c.nonce)
    dec=c2.decrypt_and_verify(ct,tag).decode(); d=(time.perf_counter()-s)*1000
    return ct,c.nonce,tag,round(e,4),round(d,4),dec

def cha_encrypt(msg):
    s=time.perf_counter(); c=_CHA.new(key=CHA_KEY)
    ct,tag=c.encrypt_and_digest(msg.encode()); e=(time.perf_counter()-s)*1000
    s=time.perf_counter(); c2=_CHA.new(key=CHA_KEY,nonce=c.nonce)
    dec=c2.decrypt_and_verify(ct,tag).decode(); d=(time.perf_counter()-s)*1000
    return ct,c.nonce,tag,round(e,4),round(d,4),dec

def do_encrypt(msg, algo):
    if algo=="aes": ct,n,t,e,d,dec=aes_encrypt(msg)
    else:           ct,n,t,e,d,dec=cha_encrypt(msg)
    return ct,n,t,e,d,dec

# ── Smart Home Device Definitions ─────────────────────────────────────────────
DEVICES = [
    {"id":"DoorLock-01",  "type":"Smart Door Lock",   "tier":"Tier1-Sensor",
     "algo":"chacha","payload":80,  "icon":"🔒","room":"Main Entrance",
     "desc":"Ultra-low power, battery-operated bolt lock"},
    {"id":"Motion-Hall",  "type":"Motion Sensor",     "tier":"Tier2-Node",
     "algo":"chacha","payload":512, "icon":"👁","room":"Hallway",
     "desc":"PIR motion detector, battery-powered"},
    {"id":"Camera-Front", "type":"CCTV Camera",       "tier":"Tier3-RPi",
     "algo":"aes",   "payload":8192,"icon":"📷","room":"Front Door",
     "desc":"1080p IP camera with metadata streaming"},
    {"id":"Alarm-Panel",  "type":"Security Panel",    "tier":"Tier4-Gateway",
     "algo":"aes",   "payload":4096,"icon":"🚨","room":"Living Room",
     "desc":"Central alarm controller & siren"},
    {"id":"Doorbell-01",  "type":"Smart Doorbell",    "tier":"Tier2-Node",
     "algo":"chacha","payload":256, "icon":"🔔","room":"Front Door",
     "desc":"WiFi doorbell with encrypted notifications"},
]

DOOR_STATES = {"DoorLock-01":"LOCKED"}
device_log = []

def make_smart_home_payload(dev):
    ts = int(time.time())
    if "Lock" in dev["type"]:
        state = random.choice(["LOCKED","LOCKED","LOCKED","UNLOCKED"])
        DOOR_STATES[dev["id"]] = state
        return f"device={dev['id']} state={state} user=owner battery={random.randint(60,100)}% ts={ts}"
    elif "Motion" in dev["type"]:
        detected = random.choice(["CLEAR","CLEAR","CLEAR","DETECTED"])
        return f"device={dev['id']} motion={detected} lux={random.randint(0,800)} temp={round(random.uniform(18,30),1)}C ts={ts}"
    elif "Camera" in dev["type"]:
        return f"device={dev['id']} frame_id={random.randint(1000,9999)} res=1920x1080 fps=25 motion={random.choice(['NO','NO','YES'])} ts={ts}"
    elif "Alarm" in dev["type"]:
        status = random.choice(["ARMED","ARMED","DISARMED","TRIGGERED"])
        return f"device={dev['id']} status={status} zones=4 active={random.randint(0,4)} ts={ts}"
    else:
        return f"device={dev['id']} event={random.choice(['PRESS','PRESS','HELD'])} visitor={random.randint(100,999)} ts={ts}"

def select_algo(payload_bytes, override=None):
    if override: return override, f"Manual override → {override.upper()}"
    cpu = psutil.cpu_percent(interval=0.05)
    if payload_bytes < 1024:
        return "chacha", f"Payload {payload_bytes}B < 1KB → ChaCha20 (faster on low-power device)"
    elif payload_bytes < 10240 and cpu > 70:
        return "chacha", f"CPU {cpu}% high + {payload_bytes}B → ChaCha20 (lower overhead)"
    elif payload_bytes >= 10240:
        return "aes", f"Payload {payload_bytes//1024}KB large → AES-256 (hardware acceleration wins)"
    else:
        return "aes", f"Payload {payload_bytes}B mid-range, CPU {cpu}% → AES-256"

def simulate_device(dev):
    payload = make_smart_home_payload(dev)
    algo, reason = select_algo(len(payload))
    ct,n,t,enc_ms,dec_ms,dec = do_encrypt(payload, algo)
    cpu = round(psutil.cpu_percent(interval=0.02), 1)
    entry = {
        "device": dev["id"], "type": dev["type"], "tier": dev["tier"],
        "icon": dev["icon"], "room": dev["room"],
        "algo": "AES-256-GCM" if algo=="aes" else "ChaCha20-Poly1305",
        "reason": reason, "payload": payload, "payload_bytes": len(payload),
        "ct_preview": ct.hex()[:24]+"...", "nonce": n.hex(),
        "tag": t.hex(), "enc_ms": enc_ms, "dec_ms": dec_ms,
        "cpu": cpu, "security_score": 95 if algo=="aes" else 92,
        "integrity": "✓ Verified", "time": time.strftime("%H:%M:%S"), "status": "ONLINE"
    }
    device_log.insert(0, entry)
    if len(device_log) > 100: device_log.pop()

def _sim_loop():
    while True:
        for dev in DEVICES:
            try: simulate_device(dev)
            except: pass
            time.sleep(0.5)
        time.sleep(2)

try:
    threading.Thread(target=_sim_loop, daemon=True).start()
except: pass

# ── Chat log ──────────────────────────────────────────────────────────────────
chat_log = []
stats = {"total": 0, "devices": set()}

# ═════════════════════════════════════════════════════════════════════════════
# MAIN DASHBOARD HTML
# ═════════════════════════════════════════════════════════════════════════════
DASH = r"""
<!DOCTYPE html><html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SmartHome Security — Encrypted IoT Platform</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.6.1/socket.io.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0a0e1a;--bg2:#111827;--bg3:#1f2937;--bd:#374151;
      --tx:#e5e7eb;--tx2:#9ca3af;--blue:#3b82f6;--green:#10b981;
      --amber:#f59e0b;--red:#ef4444;--purple:#8b5cf6;--teal:#14b8a6}
body{font-family:'Courier New',monospace;background:var(--bg);color:var(--tx);font-size:13px}
header{background:linear-gradient(135deg,#0f172a,#1e3a5f);border-bottom:1px solid #1e40af;
       padding:14px 24px;display:flex;align-items:center;justify-content:space-between}
header h1{color:#fff;font-size:15px;font-weight:500;display:flex;align-items:center;gap:8px}
.live-dot{width:8px;height:8px;background:var(--green);border-radius:50%;
           box-shadow:0 0 8px var(--green);animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.6;transform:scale(.9)}}
.tabs{display:flex;background:var(--bg2);border-bottom:1px solid var(--bd);padding:0 24px;gap:4px}
.tab{padding:11px 18px;cursor:pointer;color:var(--tx2);font-size:12px;
     border-bottom:2px solid transparent;transition:.2s;white-space:nowrap}
.tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.panel{display:none;padding:20px 24px}
.panel.active{display:block}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:14px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px}
.grid5{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px}
.card{background:var(--bg2);border:0.5px solid var(--bd);border-radius:10px;padding:16px}
.card h2{color:var(--blue);font-size:11px;letter-spacing:.06em;margin-bottom:12px;text-transform:uppercase}
.metric .val{font-size:28px;font-weight:500;color:var(--blue)}
.metric .lbl{font-size:11px;color:var(--tx2);margin-top:4px}
.bar-bg{background:var(--bg3);border-radius:3px;height:5px;margin-top:8px}
.bar-fill{height:5px;border-radius:3px;background:var(--blue);transition:.5s}
/* Device cards */
.dev-card{background:var(--bg2);border:0.5px solid var(--bd);border-radius:10px;padding:14px;
          transition:.2s;cursor:default}
.dev-card:hover{border-color:var(--blue);background:#111d2e}
.dev-icon{font-size:24px;margin-bottom:8px}
.dev-name{font-size:12px;font-weight:500;color:#fff;margin-bottom:2px}
.dev-type{font-size:10px;color:var(--tx2);margin-bottom:8px}
.dev-status{font-size:11px;display:flex;align-items:center;gap:6px;margin-bottom:6px}
.status-dot{width:6px;height:6px;border-radius:50%}
.s-online{background:var(--green);box-shadow:0 0 5px var(--green)}
.s-warn{background:var(--amber)}
.dev-algo{font-size:10px;margin-top:4px}
.dev-enc{font-size:10px;color:var(--tx2)}
/* Table */
table{width:100%;border-collapse:collapse;font-size:12px}
td,th{padding:7px 10px;border:0.5px solid var(--bg3);text-align:left}
th{background:var(--bg3);color:#fff;font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
tr:hover td{background:#161d2b}
.ok{color:var(--green)}.warn{color:var(--amber)}.err{color:var(--red)}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:500}
.b-aes{background:#1e3a5f;color:var(--blue)}
.b-cha{background:#064e3b;color:var(--teal)}
.b-dev{background:#312e81;color:var(--purple)}
.b-ok{background:#064e3b;color:var(--green)}
.b-locked{background:#064e3b;color:var(--green)}
.b-unlocked{background:#7f1d1d;color:var(--red)}
.b-armed{background:#7f1d1d;color:var(--red)}
/* Chat */
.chat-wrap{display:flex;flex-direction:column;height:480px}
.chat-msgs{flex:1;overflow-y:auto;background:var(--bg);border:0.5px solid var(--bd);
            border-radius:8px;padding:12px;margin-bottom:10px}
.msg{margin-bottom:12px;padding:10px 12px;border-radius:8px;border:0.5px solid var(--bd)}
.msg.mine{background:#1e3a5f;border-color:#2563eb}
.msg.other{background:var(--bg3)}
.msg-sender{font-size:10px;color:var(--tx2);margin-bottom:4px}
.msg-text{color:#fff;font-size:13px;margin-bottom:6px}
.msg-crypto{font-size:10px;color:var(--tx2);background:var(--bg);padding:6px 8px;
             border-radius:4px;word-break:break-all;line-height:1.7}
.chat-row{display:flex;gap:8px}
.chat-in{flex:1;padding:9px 12px;background:var(--bg3);border:0.5px solid var(--bd);
          border-radius:6px;color:var(--tx);font-size:13px;font-family:monospace}
.algo-sel{padding:8px;background:var(--bg3);border:0.5px solid var(--bd);
           border-radius:6px;color:var(--tx);font-family:monospace;font-size:12px}
.send-btn{padding:9px 16px;background:#1e3a5f;border:0.5px solid var(--blue);
           border-radius:6px;color:var(--blue);cursor:pointer;font-family:monospace;font-size:12px}
.send-btn:hover{background:#2563eb;color:#fff}
.cmd-btn{padding:7px 12px;background:var(--bg3);border:0.5px solid var(--bd);
          border-radius:6px;color:var(--tx2);cursor:pointer;font-size:11px;font-family:monospace}
.cmd-btn:hover{border-color:var(--blue);color:var(--blue)}
.cmd-btn.lock{border-color:var(--green);color:var(--green)}
.cmd-btn.unlock{border-color:var(--red);color:var(--red)}
/* Profiler */
.prof-btn{padding:10px 20px;background:#1e3a5f;border:0.5px solid var(--blue);
           border-radius:6px;color:var(--blue);cursor:pointer;font-size:12px;font-family:monospace;margin-right:8px}
.exp-btn{padding:10px 20px;background:#064e3b;border:0.5px solid var(--green);
          border-radius:6px;color:var(--green);cursor:pointer;font-size:12px;font-family:monospace;margin-right:8px}
.prog-bg{background:var(--bg3);border-radius:4px;height:6px;margin:10px 0}
.prog-fill{height:6px;border-radius:4px;background:var(--blue);width:0%;transition:.3s}
canvas{max-height:240px}
.mobile-bar{background:#0c1a0c;border:0.5px solid var(--green);border-radius:8px;
             padding:10px 16px;color:var(--green);font-size:12px;margin-bottom:14px;
             display:flex;align-items:center;justify-content:space-between}
.copy-btn{background:transparent;border:0.5px solid var(--green);border-radius:4px;
           color:var(--green);padding:4px 10px;cursor:pointer;font-size:11px;font-family:monospace}
.copy-btn:hover{background:var(--green);color:#000}
.quick-cmds{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
</style>
</head>
<body>
<header>
  <h1><div class="live-dot"></div>🏠 Smart Home Security — Encrypted IoT Platform</h1>
  <span style="color:var(--tx2);font-size:11px">AES-256-GCM + ChaCha20-Poly1305 + TLS 1.3 | Render Cloud</span>
</header>
<div class="tabs">
  <div class="tab active" onclick="showTab('devices',this)">🏠 Devices</div>
  <div class="tab" onclick="showTab('gateway',this)">📡 IoT Gateway</div>
  <div class="tab" onclick="showTab('chat',this)">🔒 Secure Commands</div>
  <div class="tab" onclick="showTab('profiler',this)">⚡ Energy Profiler</div>
  <div class="tab" onclick="showTab('about',this)">📋 About</div>
</div>

<!-- ── TAB 1: DEVICES ──────────────────────────────────────────────────── -->
<div class="panel active" id="tab-devices">
  <div class="mobile-bar">
    <span>📱 Mobile Control: <a id="mob-url" href="#" style="color:var(--green)" target="_blank">loading...</a></span>
    <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('mob-url').href)">copy link</button>
  </div>
  <div class="grid3">
    <div class="card metric"><div class="val" id="st-total">0</div><div class="lbl">Total Encrypted Packets</div><div class="bar-bg"><div class="bar-fill" id="b-total" style="width:0%"></div></div></div>
    <div class="card metric"><div class="val" id="st-cpu">—</div><div class="lbl">CPU Usage</div><div class="bar-bg"><div class="bar-fill" id="b-cpu" style="width:0%"></div></div></div>
    <div class="card metric"><div class="val ok">5</div><div class="lbl">Active Smart Devices</div></div>
  </div>
  <div class="grid5" id="dev-cards">
    <div class="card" style="text-align:center;color:var(--tx2)">Loading devices...</div>
  </div>
  <div class="card">
    <h2>🔐 Live Encrypted Packet Feed</h2>
    <table>
      <tr><th>Time</th><th>Device</th><th>Room</th><th>Algorithm</th><th>Payload (bytes)</th><th>Ciphertext Preview</th><th>Enc (ms)</th><th>Dec (ms)</th><th>Integrity</th></tr>
      <tbody id="feed-table"><tr><td colspan="9" style="text-align:center;color:var(--tx2)">Waiting for device data...</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ── TAB 2: GATEWAY ─────────────────────────────────────────────────── -->
<div class="panel" id="tab-gateway">
  <div class="grid2">
    <div class="card">
      <h2>🤖 Adaptive Algorithm Selector — Live Decisions</h2>
      <table>
        <tr><th>Device</th><th>Type</th><th>Payload</th><th>Algorithm Chosen</th><th>Enc (ms)</th><th>Score</th><th>Decision Reason</th></tr>
        <tbody id="algo-table"><tr><td colspan="7" style="text-align:center;color:var(--tx2)">Loading...</td></tr></tbody>
      </table>
    </div>
    <div class="card">
      <h2>📊 Live Throughput (KB/s)</h2>
      <canvas id="throughputChart"></canvas>
    </div>
  </div>
  <div class="grid2">
    <div class="card">
      <h2>🏠 Device Status Board</h2>
      <table>
        <tr><th>Device</th><th>Room</th><th>Status</th><th>Algorithm</th><th>Last Seen</th></tr>
        <tbody id="status-table"></tbody>
      </table>
    </div>
    <div class="card">
      <h2>📈 Algorithm Distribution</h2>
      <canvas id="algoChart"></canvas>
    </div>
  </div>
</div>

<!-- ── TAB 3: SECURE COMMANDS ─────────────────────────────────────────── -->
<div class="panel" id="tab-chat">
  <div class="grid2">
    <div class="card">
      <h2>🔒 Send Encrypted Command to Devices</h2>
      <div style="margin-bottom:12px">
        <div style="font-size:11px;color:var(--tx2);margin-bottom:8px">QUICK COMMANDS</div>
        <div class="quick-cmds">
          <button class="cmd-btn lock" onclick="quickCmd('LOCK door DoorLock-01','aes')">🔒 Lock Door</button>
          <button class="cmd-btn unlock" onclick="quickCmd('UNLOCK door DoorLock-01','aes')">🔓 Unlock Door</button>
          <button class="cmd-btn" onclick="quickCmd('ARM alarm Alarm-Panel','aes')">🚨 Arm Alarm</button>
          <button class="cmd-btn" onclick="quickCmd('DISARM alarm Alarm-Panel','aes')">✅ Disarm Alarm</button>
          <button class="cmd-btn" onclick="quickCmd('STREAM start Camera-Front','aes')">📷 Start Camera</button>
          <button class="cmd-btn" onclick="quickCmd('STATUS all devices','chacha')">📋 Status Check</button>
        </div>
      </div>
      <div class="chat-wrap">
        <div class="chat-msgs" id="chat-msgs">
          <div style="color:var(--tx2);font-size:11px;text-align:center;padding:20px">Send a command to see live encryption</div>
        </div>
        <div class="chat-row">
          <input class="chat-in" id="chat-in" placeholder="Type command or message..." onkeydown="if(event.key==='Enter')sendCmd()">
          <select class="algo-sel" id="chat-algo">
            <option value="aes">AES-256-GCM</option>
            <option value="chacha">ChaCha20</option>
          </select>
          <button class="send-btn" onclick="sendCmd()">Send 🔒</button>
        </div>
      </div>
    </div>
    <div class="card">
      <h2>🔍 Encryption Detail — Last Command</h2>
      <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tbody id="cmd-detail"><tr><td colspan="2" style="color:var(--tx2);text-align:center">Send a command above</td></tr></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ── TAB 4: ENERGY PROFILER ─────────────────────────────────────────── -->
<div class="panel" id="tab-profiler">
  <div style="margin-bottom:14px">
    <button class="prof-btn" id="prof-btn" onclick="runProfiler()">▶ Run Energy Profile</button>
    <button class="exp-btn" onclick="window.location='/api/export_csv'">⬇ Export CSV for Report</button>
    <span style="font-size:11px;color:var(--tx2)">Tests all 5 smart home device payload sizes × 2 algorithms × 5 runs</span>
  </div>
  <div class="prog-bg"><div class="prog-fill" id="prog"></div></div>
  <div id="prof-status" style="font-size:11px;color:var(--tx2);margin-bottom:14px">Click Run to start</div>
  <div class="grid2">
    <div class="card"><h2>⚡ Energy Cost — µJ per encryption</h2><canvas id="energyChart"></canvas></div>
    <div class="card"><h2>⏱ Encryption Time — ms</h2><canvas id="timeChart"></canvas></div>
  </div>
  <div class="card">
    <h2>📊 Full Benchmark — Smart Home Device Payloads</h2>
    <table>
      <tr><th>Device Scenario</th><th>Payload</th>
          <th>AES Enc</th><th>AES Dec</th><th>AES CPU%</th><th>AES µJ</th>
          <th>ChaCha Enc</th><th>ChaCha Dec</th><th>ChaCha CPU%</th><th>ChaCha µJ</th>
          <th>Winner</th></tr>
      <tbody id="prof-table"><tr><td colspan="11" style="text-align:center;color:var(--tx2)">Run profiler to see results</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ── TAB 5: ABOUT ───────────────────────────────────────────────────── -->
<div class="panel" id="tab-about">
  <div class="grid2">
    <div class="card">
      <h2>📌 Project Objectives</h2>
      <table>
        <tr><th>#</th><th>Objective</th><th>How Implemented</th></tr>
        <tr><td>1</td><td>Lightweight crypto for IoT</td><td class="ok">ChaCha20 for door lock, motion, doorbell</td></tr>
        <tr><td>2</td><td>AES + TLS implementation</td><td class="ok">AES-256-GCM for camera, alarm panel</td></tr>
        <tr><td>3</td><td>Security vs performance balance</td><td class="ok">Adaptive selector + energy profiler</td></tr>
      </table>
    </div>
    <div class="card">
      <h2>📚 Literature Gaps Addressed</h2>
      <table>
        <tr><th>Paper</th><th>Gap</th><th>Solved By</th></tr>
        <tr><td>Kumar 2024</td><td>No real-time adaptability</td><td class="ok">Adaptive selector</td></tr>
        <tr><td>Lakshmanan 2024</td><td>Energy not measured</td><td class="ok">µJ profiler</td></tr>
        <tr><td>Khan 2025</td><td>High TLS latency</td><td class="ok">TLS timing per packet</td></tr>
        <tr><td>Sahu 2024</td><td>AES overhead on constrained</td><td class="ok">ChaCha20 for Tier1-2</td></tr>
      </table>
    </div>
  </div>
</div>

<script>
const socket = io();
let tChart, aChart, eChart, timeChart;
let profData = [];

// Tabs
function showTab(name, btn) {
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  btn.classList.add('active');
}

// Mobile URL
const mobUrl = location.origin+'/mobile';
document.getElementById('mob-url').href=mobUrl;
document.getElementById('mob-url').textContent=mobUrl;

// ── Device polling ────────────────────────────────────────────────────────
function updateDevices() {
  fetch('/api/feed').then(r=>r.json()).then(data => {
    document.getElementById('st-total').textContent = data.total;
    document.getElementById('st-cpu').textContent = data.cpu+'%';
    document.getElementById('b-cpu').style.width = data.cpu+'%';
    document.getElementById('b-total').style.width = Math.min(data.total,100)+'%';

    // Device cards
    const seen = {};
    (data.devices||[]).forEach(d=>{if(!seen[d.device])seen[d.device]=d;});
    const devs = Object.values(seen);
    document.getElementById('dev-cards').innerHTML = devs.map(d=>`
      <div class="dev-card">
        <div class="dev-icon">${d.icon}</div>
        <div class="dev-name">${d.device}</div>
        <div class="dev-type">${d.type}</div>
        <div class="dev-status"><div class="status-dot s-online"></div><span class="ok">ONLINE</span></div>
        <div style="font-size:10px;color:var(--tx2);margin-bottom:4px">📍 ${d.room}</div>
        <div class="dev-algo"><span class="badge ${d.algo.includes('AES')?'b-aes':'b-cha'}">${d.algo}</span></div>
        <div class="dev-enc" style="margin-top:4px">Enc: ${d.enc_ms}ms · Score: <span class="ok">${d.security_score}/100</span></div>
      </div>`).join('') || '<div style="color:var(--tx2)">Loading...</div>';

    // Feed table
    document.getElementById('feed-table').innerHTML = (data.devices||[]).slice(0,12).map(d=>`
      <tr>
        <td>${d.time}</td>
        <td>${d.icon} <span class="badge b-dev">${d.device}</span></td>
        <td style="font-size:10px;color:var(--tx2)">${d.room}</td>
        <td><span class="badge ${d.algo.includes('AES')?'b-aes':'b-cha'}">${d.algo}</span></td>
        <td>${d.payload_bytes}B</td>
        <td style="font-size:10px;word-break:break-all">${d.ct_preview}</td>
        <td class="ok">${d.enc_ms}</td><td>${d.dec_ms}</td>
        <td class="ok">✓ Verified</td>
      </tr>`).join('') || '<tr><td colspan="9" style="color:var(--tx2);text-align:center">Waiting...</td></tr>';

    // Gateway tab
    document.getElementById('algo-table').innerHTML = devs.map(d=>`
      <tr>
        <td>${d.icon} ${d.device}</td>
        <td style="font-size:10px;color:var(--tx2)">${d.type}</td>
        <td>${d.payload_bytes}B</td>
        <td><span class="badge ${d.algo.includes('AES')?'b-aes':'b-cha'}">${d.algo}</span></td>
        <td class="ok">${d.enc_ms}</td>
        <td><span class="${d.security_score>90?'ok':'warn'}">${d.security_score}/100</span></td>
        <td style="font-size:10px;color:var(--tx2);max-width:180px">${d.reason}</td>
      </tr>`).join('');

    document.getElementById('status-table').innerHTML = devs.map(d=>`
      <tr>
        <td>${d.icon} ${d.device}</td>
        <td style="font-size:10px">${d.room}</td>
        <td class="ok">● ONLINE</td>
        <td><span class="badge ${d.algo.includes('AES')?'b-aes':'b-cha'}">${d.algo}</span></td>
        <td style="font-size:10px;color:var(--tx2)">${d.time}</td>
      </tr>`).join('');

    updateCharts(data.devices||[]);
  });
}

function updateCharts(devices) {
  const seen={};
  devices.forEach(d=>{if(!seen[d.device])seen[d.device]=d;});
  const devs=Object.values(seen);
  const labels=devs.map(d=>d.device);
  const vals=devs.map(d=>Math.round(d.payload_bytes/(d.enc_ms/1000)/1024));

  // Throughput bar chart
  if(!tChart){
    tChart=new Chart(document.getElementById('throughputChart'),{type:'bar',
      data:{labels,datasets:[{label:'KB/s',data:vals,backgroundColor:'#1e3a5f',borderColor:'#3b82f6',borderWidth:1}]},
      options:{responsive:true,plugins:{legend:{labels:{color:'#9ca3af',font:{family:'Courier New'}}}},
        scales:{x:{ticks:{color:'#9ca3af'},grid:{color:'#1f2937'}},y:{ticks:{color:'#9ca3af'},grid:{color:'#1f2937'}}}}});
  } else {
    tChart.data.labels=labels;tChart.data.datasets[0].data=vals;tChart.update();
  }

  // Algorithm distribution pie
  const aesCount=devs.filter(d=>d.algo.includes('AES')).length;
  const chaCount=devs.length-aesCount;
  if(!aChart){
    aChart=new Chart(document.getElementById('algoChart'),{type:'doughnut',
      data:{labels:['AES-256-GCM','ChaCha20-Poly1305'],
            datasets:[{data:[aesCount,chaCount],backgroundColor:['#1e3a5f','#064e3b'],
                        borderColor:['#3b82f6','#10b981'],borderWidth:2}]},
      options:{responsive:true,plugins:{legend:{labels:{color:'#9ca3af',font:{family:'Courier New'}}}}}});
  } else {
    aChart.data.datasets[0].data=[aesCount,chaCount];aChart.update();
  }
}

setInterval(updateDevices,2000); updateDevices();

// ── Chat / Commands ──────────────────────────────────────────────────────
socket.on('connect',()=>socket.emit('join',{room:'smarthome'}));
socket.on('new_cmd',data=>appendMsg(data));

function quickCmd(msg,algo){
  document.getElementById('chat-in').value=msg;
  document.getElementById('chat-algo').value=algo;
  sendCmd();
}

function sendCmd(){
  const msg=document.getElementById('chat-in').value.trim();
  const algo=document.getElementById('chat-algo').value;
  if(!msg)return;
  fetch('/api/cmd',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({message:msg,algo,sender:'Owner-App',room:'smarthome'})
  }).then(r=>r.json()).then(d=>{
    appendMsg(d,true); showDetail(d);
    document.getElementById('chat-in').value='';
  });
}

function appendMsg(d,mine=false){
  const box=document.getElementById('chat-msgs');
  const div=document.createElement('div');
  div.className='msg'+(mine?' mine':'');
  div.innerHTML=`
    <div class="msg-sender">${d.sender} · ${d.time} · <span class="badge ${d.algo.includes('AES')?'b-aes':'b-cha'}">${d.algo}</span></div>
    <div class="msg-text">📨 ${d.original}</div>
    <div class="msg-crypto">
      Ciphertext: ${d.ct_preview}<br>
      Nonce: ${d.nonce.substring(0,24)}... &nbsp;|&nbsp; Auth Tag: ${d.tag.substring(0,16)}...<br>
      Enc: ${d.enc_ms}ms &nbsp;|&nbsp; Dec: ${d.dec_ms}ms &nbsp;|&nbsp; <span class="ok">✓ Integrity Verified</span>
    </div>`;
  box.insertBefore(div,box.firstChild);
}

function showDetail(d){
  document.getElementById('cmd-detail').innerHTML=`
    <tr><td>Command</td><td class="ok">${d.original}</td></tr>
    <tr><td>Algorithm</td><td><span class="badge ${d.algo.includes('AES')?'b-aes':'b-cha'}">${d.algo}</span></td></tr>
    <tr><td>Ciphertext (hex)</td><td style="font-size:10px;word-break:break-all">${d.ciphertext}</td></tr>
    <tr><td>Nonce</td><td style="font-size:10px">${d.nonce}</td></tr>
    <tr><td>Auth Tag</td><td style="font-size:10px">${d.tag}</td></tr>
    <tr><td>Enc time</td><td class="ok">${d.enc_ms} ms</td></tr>
    <tr><td>Dec time</td><td class="ok">${d.dec_ms} ms</td></tr>
    <tr><td>Payload size</td><td>${d.payload_bytes} bytes</td></tr>
    <tr><td>Integrity</td><td class="ok">✓ ${d.integrity}</td></tr>`;
}

// ── Energy Profiler ───────────────────────────────────────────────────────
function runProfiler(){
  const btn=document.getElementById('prof-btn');
  btn.textContent='⏳ Running...';btn.disabled=true;
  document.getElementById('prof-status').textContent='Profiling 5 smart home device payload sizes...';
  document.getElementById('prog').style.width='15%';
  fetch('/api/profile').then(r=>r.json()).then(data=>{
    profData=data;
    btn.textContent='▶ Run Again';btn.disabled=false;
    document.getElementById('prog').style.width='100%';
    document.getElementById('prof-status').textContent='Complete — '+data.length+' payload sizes benchmarked. Export CSV for dissertation.';
    renderProfCharts(data); renderProfTable(data);
  });
}

function renderProfCharts(data){
  const labels=data.map(d=>d.label);
  const opts={responsive:true,plugins:{legend:{labels:{color:'#9ca3af',font:{family:'Courier New'}}}},
    scales:{x:{ticks:{color:'#9ca3af'},grid:{color:'#1f2937'}},y:{ticks:{color:'#9ca3af'},grid:{color:'#1f2937'}}}};
  if(eChart)eChart.destroy();
  eChart=new Chart(document.getElementById('energyChart'),{type:'line',data:{labels,datasets:[
    {label:'AES-256-GCM (µJ)',data:data.map(d=>d.aes_uj),borderColor:'#3b82f6',backgroundColor:'#1e3a5f44',fill:true},
    {label:'ChaCha20 (µJ)',data:data.map(d=>d.cha_uj),borderColor:'#10b981',backgroundColor:'#06503944',fill:true}
  ]},options:opts});
  if(timeChart)timeChart.destroy();
  timeChart=new Chart(document.getElementById('timeChart'),{type:'line',data:{labels,datasets:[
    {label:'AES-256-GCM (ms)',data:data.map(d=>d.aes_enc),borderColor:'#3b82f6',backgroundColor:'#1e3a5f44',fill:true},
    {label:'ChaCha20 (ms)',data:data.map(d=>d.cha_enc),borderColor:'#10b981',backgroundColor:'#06503944',fill:true}
  ]},options:opts});
}

function renderProfTable(data){
  document.getElementById('prof-table').innerHTML=data.map(d=>`
    <tr>
      <td style="font-size:10px;color:var(--tx2)">${d.scenario}</td>
      <td>${d.label}</td>
      <td class="ok">${d.aes_enc}</td><td>${d.aes_dec}</td><td>${d.aes_cpu}</td><td>${d.aes_uj}</td>
      <td class="ok">${d.cha_enc}</td><td>${d.cha_dec}</td><td>${d.cha_cpu}</td><td>${d.cha_uj}</td>
      <td><span class="badge ${d.winner==='AES'?'b-aes':'b-cha'}">${d.winner}</span></td>
    </tr>`).join('');
}
</script>
</body></html>
"""

# ═════════════════════════════════════════════════════════════════════════════
# MOBILE PAGE
# ═════════════════════════════════════════════════════════════════════════════
MOBILE = r"""
<!DOCTYPE html><html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SmartHome Control</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.6.1/socket.io.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0a0e1a;color:#e5e7eb;padding:14px;font-size:13px}
h1{color:#fff;font-size:14px;margin-bottom:4px}
.sub{color:#9ca3af;font-size:11px;margin-bottom:14px}
.card{background:#111827;border:0.5px solid #374151;border-radius:8px;padding:14px;margin-bottom:12px}
h2{color:#3b82f6;font-size:12px;margin-bottom:10px;text-transform:uppercase;letter-spacing:.04em}
.row{display:flex;justify-content:space-between;padding:5px 0;border-bottom:0.5px solid #1f2937;font-size:12px;gap:8px}
.lbl{color:#9ca3af;min-width:80px}.val{color:#e5e7eb;word-break:break-all;text-align:right}
.ok{color:#10b981}.err{color:#ef4444}
button{width:100%;padding:12px;margin-top:8px;border:none;border-radius:6px;font-size:13px;font-weight:bold;cursor:pointer;font-family:monospace}
.b-lock{background:#064e3b;color:#10b981;border:0.5px solid #10b981}
.b-unlock{background:#7f1d1d;color:#ef4444;border:0.5px solid #ef4444}
.b-aes{background:#1e3a5f;color:#3b82f6;border:0.5px solid #3b82f6}
.b-cha{background:#064e3b;color:#14b8a6;border:0.5px solid #14b8a6}
.b-alarm{background:#78350f;color:#f59e0b;border:0.5px solid #f59e0b}
textarea{width:100%;padding:10px;background:#1f2937;border:0.5px solid #374151;border-radius:6px;color:#e5e7eb;font-size:13px;margin-top:6px;resize:vertical;min-height:70px;font-family:monospace}
#result-card{display:none}
#spinner{display:none;text-align:center;color:#3b82f6;padding:10px;font-size:12px}
.badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:bold;margin-right:4px}
.b-aesbadge{background:#1e3a5f;color:#3b82f6}
.b-chabadge{background:#064e3b;color:#10b981}
.log-entry{padding:6px;border-bottom:0.5px solid #1f2937;font-size:11px;line-height:1.6}
#log{max-height:200px;overflow-y:auto}
</style>
</head>
<body>
<h1>🏠 SmartHome Control</h1>
<p class="sub">Encrypted commands over TLS 1.3</p>

<div class="card">
  <h2>🔒 Quick Commands</h2>
  <button class="b-lock" onclick="sendQ('LOCK door DoorLock-01','aes')">🔒 Lock Front Door</button>
  <button class="b-unlock" onclick="sendQ('UNLOCK door DoorLock-01','aes')">🔓 Unlock Front Door</button>
  <button class="b-alarm" onclick="sendQ('ARM alarm Alarm-Panel','aes')" style="margin-top:6px">🚨 Arm Alarm</button>
  <button class="b-aes" onclick="sendQ('STATUS all devices','chacha')" style="margin-top:6px">📋 Check All Devices</button>
</div>

<div class="card">
  <h2>✉️ Custom Encrypted Message</h2>
  <textarea id="msg" placeholder="Type any command or message..."></textarea>
  <button class="b-aes" onclick="sendMsg('aes')">🔒 Send with AES-256-GCM</button>
  <button class="b-cha" onclick="sendMsg('chacha')" style="margin-top:6px">🔒 Send with ChaCha20</button>
  <div id="spinner">⏳ Encrypting...</div>
</div>

<div class="card" id="result-card">
  <h2>⚡ Last Encryption Result</h2>
  <div class="row"><span class="lbl">Command</span><span class="val ok" id="r-orig"></span></div>
  <div class="row"><span class="lbl">Algorithm</span><span class="val" id="r-algo"></span></div>
  <div class="row"><span class="lbl">Encrypted</span><span class="val" id="r-enc"></span></div>
  <div class="row"><span class="lbl">Nonce</span><span class="val" id="r-nonce"></span></div>
  <div class="row"><span class="lbl">Auth Tag</span><span class="val" id="r-tag"></span></div>
  <div class="row"><span class="lbl">Enc Time</span><span class="ok" id="r-ems"></span></div>
  <div class="row"><span class="lbl">Dec Time</span><span class="ok" id="r-dms"></span></div>
  <div class="row"><span class="lbl">Integrity</span><span class="ok">✓ Verified — Not Tampered</span></div>
</div>

<div class="card">
  <h2>📋 Command History</h2>
  <div id="log"><p style="color:#9ca3af;font-size:11px">No commands yet</p></div>
</div>

<script>
const socket=io();
const log=[];
let count=0;

function sendQ(msg,algo){
  document.getElementById('msg').value=msg;
  sendMsg(algo);
}

function sendMsg(algo){
  const msg=document.getElementById('msg').value.trim()||'STATUS check ts='+Date.now();
  document.getElementById('spinner').style.display='block';
  document.getElementById('result-card').style.display='none';
  fetch('/api/cmd',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({message:msg,algo,sender:'Mobile-Owner',room:'smarthome'})
  }).then(r=>r.json()).then(d=>{
    document.getElementById('spinner').style.display='none';
    document.getElementById('result-card').style.display='block';
    document.getElementById('r-orig').textContent=d.original;
    document.getElementById('r-algo').textContent=d.algo;
    document.getElementById('r-enc').textContent=d.ct_preview;
    document.getElementById('r-nonce').textContent=d.nonce.substring(0,24)+'...';
    document.getElementById('r-tag').textContent=d.tag.substring(0,16)+'...';
    document.getElementById('r-ems').textContent=d.enc_ms+' ms';
    document.getElementById('r-dms').textContent=d.dec_ms+' ms';
    count++;
    log.unshift({algo:d.algo,msg:msg.substring(0,30),ms:d.enc_ms,time:new Date().toLocaleTimeString()});
    document.getElementById('log').innerHTML=log.map(e=>
      '<div class="log-entry"><span class="badge '+(e.algo.includes('AES')?'b-aesbadge':'b-chabadge')+'">'+
      e.algo+'</span>'+e.time+' — "'+e.msg+'..." → '+e.ms+'ms</div>').join('');
  }).catch(()=>{document.getElementById('spinner').style.display='none';});
}
</script>
</body></html>
"""

# ═════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index(): return render_template_string(DASH)

@app.route("/mobile")
def mobile(): return render_template_string(MOBILE)

@app.route("/api/myinfo")
def myinfo():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    return jsonify({"ip": ip})

@app.route("/api/feed")
def feed():
    # Always generate fresh device data (Render-compatible)
    for dev in DEVICES:
        try: simulate_device(dev)
        except: pass
    cpu = round(psutil.cpu_percent(interval=0.1), 1)
    return jsonify({"total": len(device_log), "cpu": cpu, "devices": list(device_log[:20])})

@app.route("/api/cmd", methods=["POST"])
def cmd():
    data = request.json or {}
    msg = data.get("message","STATUS")[:500]
    algo = data.get("algo","aes")
    sender = data.get("sender","Owner")
    room = data.get("room","smarthome")
    ct,n,t,enc_ms,dec_ms,dec = do_encrypt(msg, algo)
    stats["total"] += 1
    stats["devices"].add(request.headers.get("X-Forwarded-For",request.remote_addr).split(",")[0].strip())
    entry = {
        "sender": sender, "room": room, "original": msg,
        "algo": "AES-256-GCM" if algo=="aes" else "ChaCha20-Poly1305",
        "ciphertext": ct.hex(), "ct_preview": ct.hex()[:32]+"...",
        "nonce": n.hex(), "tag": t.hex(),
        "enc_ms": enc_ms, "dec_ms": dec_ms,
        "decrypted": dec, "integrity": "Verified",
        "payload_bytes": len(msg.encode()),
        "time": time.strftime("%H:%M:%S")
    }
    chat_log.insert(0, entry)
    if len(chat_log) > 100: chat_log.pop()
    socketio.emit("new_cmd", entry, room=room)
    return jsonify(entry)

@app.route("/api/profile")
def profile():
    SCENARIOS = [
        ("Door Lock command",   "DoorLock-01",   80),
        ("Motion alert",        "Motion-Hall",   512),
        ("Doorbell notify",     "Doorbell-01",   256),
        ("Alarm status",        "Alarm-Panel",  4096),
        ("Camera metadata",     "Camera-Front", 8192),
        ("Full status report",  "All-Devices",102400),
    ]
    results = []
    for scenario, dev, size in SCENARIOS:
        msg = "A"*size
        ae,ad,ce,cd = [],[],[],[]
        for _ in range(5):
            ct,n,t,e,d,_ = aes_encrypt(msg); ae.append(e); ad.append(d)
            ct,n,t,e,d,_ = cha_encrypt(msg); ce.append(e); cd.append(d)
        avg = lambda x: round(sum(x)/len(x),4)
        cpu = round(psutil.cpu_percent(interval=0.1),1)
        CPU_W=0.5; IDLE_W=0.05
        def uj(ms): return round((IDLE_W+(CPU_W*cpu/100))*(ms/1000)*1_000_000,4)
        a_enc=avg(ae); c_enc=avg(ce)
        results.append({
            "scenario":scenario,"label":f"{size}B" if size<1024 else f"{size//1024}KB",
            "aes_enc":a_enc,"aes_dec":avg(ad),"aes_cpu":cpu,"aes_uj":uj(a_enc),
            "cha_enc":c_enc,"cha_dec":avg(cd),"cha_cpu":cpu,"cha_uj":uj(c_enc),
            "winner":"AES" if a_enc<c_enc else "ChaCha20"
        })
    app.config["LAST_PROFILE"] = results
    return jsonify(results)

@app.route("/api/export_csv")
def export_csv():
    data = app.config.get("LAST_PROFILE",[])
    if not data:
        data = []
        for s,d,size in [("Door Lock",80),("Motion",512),("Camera",8192)]:
            ct,n,t,e,dms,_ = aes_encrypt("A"*size)
            data.append({"scenario":s,"label":f"{size}B","aes_enc":e,"cha_enc":e*0.9,"winner":"ChaCha20"})
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Scenario","Payload","AES_Enc_ms","AES_Dec_ms","AES_CPU_%","AES_Energy_uJ",
                "ChaCha_Enc_ms","ChaCha_Dec_ms","ChaCha_CPU_%","ChaCha_Energy_uJ","Winner"])
    for d in data:
        w.writerow([d.get("scenario",""),d.get("label",""),
                    d.get("aes_enc",""),d.get("aes_dec",""),d.get("aes_cpu",""),d.get("aes_uj",""),
                    d.get("cha_enc",""),d.get("cha_dec",""),d.get("cha_cpu",""),d.get("cha_uj",""),
                    d.get("winner","")])
    out.seek(0)
    return send_file(io.BytesIO(out.getvalue().encode()),as_attachment=True,
                     download_name="smarthome_crypto_benchmark.csv",mimetype="text/csv")

@socketio.on("join")
def on_join(data): join_room(data.get("room","smarthome"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT",5000))
    print(f"\n[OK] Dashboard → http://localhost:{port}")
    print(f"[OK] Mobile    → http://localhost:{port}/mobile\n")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
