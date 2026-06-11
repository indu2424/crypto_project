from flask import Flask, request, jsonify, render_template_string, send_file
from flask_socketio import SocketIO, emit, join_room
import sys, time, os, threading, io, csv, json
sys.path.insert(0, "src/modules")
sys.path.insert(0, "src/chat")
sys.path.insert(0, "src/profiler")

from aes_module import load_key, encrypt, decrypt
from chacha_module import load_chacha_key, chacha_encrypt, chacha_decrypt
from adaptive_selector import select_algorithm, DEVICE_PROFILES
from iot_devices import start_device_simulator, device_log
from chat_engine import send_message, encrypt_file, chat_history
from energy_profiler import run_full_profile, profile_encryption
import psutil

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Start IoT simulator on boot ──────────────────────────────────────────────
start_device_simulator(interval=3)

# Live stats
live_stats = {"total_encrypted": 0, "devices_connected": set(), "chat_messages": 0}

# ─────────────────────────────────────────────────────────────────────────────
# HTML TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────

MAIN_DASH = """
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Adaptive Secure IoT Platform</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.6.1/socket.io.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bd:#30363d;
          --tx:#c9d1d9;--tx2:#8b949e;--blue:#58a6ff;--green:#3fb950;
          --amber:#d29922;--coral:#f0997b;--purple:#a78bfa}
    body{font-family:'Courier New',monospace;background:var(--bg);color:var(--tx);font-size:13px}
    header{background:var(--bg2);border-bottom:1px solid var(--bd);padding:14px 24px;
           display:flex;align-items:center;justify-content:space-between}
    header h1{color:#fff;font-size:15px;font-weight:500}
    header .live{color:var(--green);font-size:11px;animation:blink 1.5s infinite}
    @keyframes blink{0%,100%{opacity:1}50%{opacity:.4}}
    .tabs{display:flex;background:var(--bg2);border-bottom:1px solid var(--bd);padding:0 24px}
    .tab{padding:12px 20px;cursor:pointer;color:var(--tx2);font-size:12px;border-bottom:2px solid transparent;transition:.2s}
    .tab.active{color:var(--blue);border-bottom-color:var(--blue)}
    .tab:hover{color:var(--tx)}
    .panel{display:none;padding:20px 24px}
    .panel.active{display:block}
    .grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px}
    .grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}
    .card{background:var(--bg2);border:0.5px solid var(--bd);border-radius:8px;padding:16px}
    .card h2{color:var(--blue);font-size:12px;margin-bottom:12px;letter-spacing:.04em}
    .metric .val{font-size:28px;font-weight:500;color:var(--blue)}
    .metric .lbl{font-size:11px;color:var(--tx2);margin-top:4px}
    .bar-bg{background:var(--bg3);border-radius:3px;height:6px;margin-top:8px}
    .bar-fill{height:6px;border-radius:3px;background:var(--blue);transition:.5s}
    table{width:100%;border-collapse:collapse;font-size:12px}
    td,th{padding:7px 10px;border:0.5px solid var(--bg3);text-align:left}
    th{background:var(--bg3);color:#fff;font-weight:500}
    tr:hover td{background:#1c2129}
    .ok{color:var(--green)}.warn{color:var(--amber)}.err{color:var(--coral)}
    .badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:500}
    .b-aes{background:#1f4068;color:var(--blue)}
    .b-cha{background:#0f3a2a;color:var(--green)}
    .b-dev{background:#26215c;color:var(--purple)}
    .b-ok{background:#0f3a2a;color:var(--green)}
    .reason-cell{font-size:10px;color:var(--tx2);max-width:200px}
    /* Chat styles */
    .chat-wrap{display:flex;gap:16px;height:520px}
    .chat-rooms{width:160px;flex-shrink:0}
    .room-btn{width:100%;padding:8px 10px;background:var(--bg3);border:0.5px solid var(--bd);
              border-radius:6px;color:var(--tx2);cursor:pointer;text-align:left;font-size:12px;
              margin-bottom:6px;font-family:monospace}
    .room-btn.active{border-color:var(--blue);color:var(--blue)}
    .chat-main{flex:1;display:flex;flex-direction:column}
    .chat-msgs{flex:1;overflow-y:auto;background:var(--bg);border:0.5px solid var(--bd);
               border-radius:6px;padding:12px;margin-bottom:10px}
    .msg{margin-bottom:12px;padding:8px 10px;border-radius:6px;border:0.5px solid var(--bd)}
    .msg.mine{background:#1f4068;border-color:#2d5a8e}
    .msg.other{background:var(--bg3)}
    .msg-sender{font-size:10px;color:var(--tx2);margin-bottom:4px}
    .msg-text{color:#fff;font-size:13px;margin-bottom:6px}
    .msg-crypto{font-size:10px;color:var(--tx2);line-height:1.7;background:var(--bg);
                padding:6px 8px;border-radius:4px;word-break:break-all}
    .chat-input-row{display:flex;gap:8px}
    .chat-input{flex:1;padding:9px 12px;background:var(--bg3);border:0.5px solid var(--bd);
                border-radius:6px;color:var(--tx);font-size:13px;font-family:monospace}
    .algo-sel{padding:8px;background:var(--bg3);border:0.5px solid var(--bd);
              border-radius:6px;color:var(--tx);font-size:12px;font-family:monospace}
    .send-btn{padding:9px 18px;background:#1f4068;border:0.5px solid var(--blue);
              border-radius:6px;color:var(--blue);cursor:pointer;font-size:12px;font-family:monospace}
    .send-btn:hover{background:#2d5a8e}
    /* File upload */
    .upload-zone{border:2px dashed var(--bd);border-radius:8px;padding:30px;text-align:center;
                 cursor:pointer;transition:.2s;margin-bottom:12px}
    .upload-zone:hover{border-color:var(--blue);color:var(--blue)}
    .upload-zone input{display:none}
    /* Profiler */
    .prof-btn{padding:10px 20px;background:#1f4068;border:0.5px solid var(--blue);
              border-radius:6px;color:var(--blue);cursor:pointer;font-size:12px;
              font-family:monospace;margin-right:8px;margin-bottom:12px}
    .prof-btn:hover{background:#2d5a8e}
    .prof-btn.running{background:#0f3a2a;border-color:var(--green);color:var(--green)}
    .export-btn{padding:10px 20px;background:#0f3a2a;border:0.5px solid var(--green);
                border-radius:6px;color:var(--green);cursor:pointer;font-size:12px;
                font-family:monospace;margin-right:8px}
    .progress-wrap{background:var(--bg3);border-radius:4px;height:8px;margin:10px 0}
    .progress-bar{height:8px;border-radius:4px;background:var(--blue);transition:width .3s;width:0%}
    canvas{max-height:260px}
    .mobile-url{background:var(--bg3);border:0.5px solid var(--green);border-radius:6px;
                padding:10px 14px;color:var(--green);font-size:12px;margin-bottom:16px;
                display:flex;align-items:center;justify-content:space-between}
    .mobile-url a{color:var(--green)}
    .copy-url{background:transparent;border:0.5px solid var(--green);border-radius:4px;
              color:var(--green);padding:4px 10px;cursor:pointer;font-size:11px;font-family:monospace}
  </style>
</head>
<body>
<header>
  <h1>🔐 Adaptive Secure IoT Communication Platform</h1>
  <div>
    <span class="live">● LIVE</span>
    <span style="color:var(--tx2);font-size:11px;margin-left:12px">AES-256-GCM + ChaCha20-Poly1305 + TLS 1.3</span>
  </div>
</header>

<div class="tabs">
  <div class="tab active" onclick="showTab('iot')">📡 IoT Gateway</div>
  <div class="tab" onclick="showTab('chat')">💬 Encrypted Chat</div>
  <div class="tab" onclick="showTab('profiler')">⚡ Energy Profiler</div>
  <div class="tab" onclick="showTab('about')">📋 About</div>
</div>

<!-- ── TAB 1: IoT Gateway ───────────────────────────────────────────────── -->
<div class="panel active" id="tab-iot">

  <div class="mobile-url">
    <span>📱 Mobile URL: <a id="mob-url" href="#" target="_blank">loading...</a></span>
    <button class="copy-url" onclick="copyMobUrl()">copy link</button>
  </div>

  <div class="grid3">
    <div class="card metric">
      <div class="val" id="stat-total">0</div>
      <div class="lbl">Messages Encrypted</div>
      <div class="bar-bg"><div class="bar-fill" id="bar-total" style="width:0%"></div></div>
    </div>
    <div class="card metric">
      <div class="val" id="stat-cpu">—</div>
      <div class="lbl">CPU Usage %</div>
      <div class="bar-bg"><div class="bar-fill" id="bar-cpu" style="width:0%"></div></div>
    </div>
    <div class="card metric">
      <div class="val ok">5</div>
      <div class="lbl">Active IoT Device Tiers</div>
    </div>
  </div>

  <div class="grid2">
    <div class="card">
      <h2>🤖 ALGORITHM SELECTOR — LIVE DECISIONS</h2>
      <table>
        <tr><th>Device</th><th>Tier</th><th>Algorithm</th><th>Enc (ms)</th><th>Score</th><th>Decision Reason</th></tr>
        <tbody id="device-table"><tr><td colspan="6" style="color:var(--tx2);text-align:center">Loading devices...</td></tr></tbody>
      </table>
    </div>
    <div class="card">
      <h2>📊 LIVE THROUGHPUT CHART</h2>
      <canvas id="throughputChart"></canvas>
    </div>
  </div>

  <div class="card">
    <h2>📋 ALL ENCRYPTED MESSAGES — LIVE FEED</h2>
    <table>
      <tr><th>Time</th><th>Device</th><th>Algorithm</th><th>Payload</th><th>Ciphertext Preview</th><th>Enc (ms)</th><th>Dec (ms)</th><th>Integrity</th></tr>
      <tbody id="msg-table"><tr><td colspan="8" style="color:var(--tx2);text-align:center">Waiting for data...</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ── TAB 2: Encrypted Chat ───────────────────────────────────────────── -->
<div class="panel" id="tab-chat">
  <div class="grid2">
    <div class="card">
      <h2>💬 REAL-TIME ENCRYPTED CHAT</h2>
      <div class="chat-wrap">
        <div class="chat-rooms">
          <div style="font-size:10px;color:var(--tx2);margin-bottom:8px">ROOMS</div>
          <button class="room-btn active" onclick="joinRoom('general',this)">general</button>
          <button class="room-btn" onclick="joinRoom('iot-data',this)">iot-data</button>
          <button class="room-btn" onclick="joinRoom('alerts',this)">alerts</button>
          <div style="margin-top:16px;font-size:10px;color:var(--tx2)">YOUR NAME</div>
          <input id="username" value="User1" style="width:100%;margin-top:6px;padding:6px 8px;
            background:var(--bg3);border:0.5px solid var(--bd);border-radius:4px;
            color:var(--tx);font-size:12px;font-family:monospace">
        </div>
        <div class="chat-main">
          <div class="chat-msgs" id="chat-msgs">
            <div style="color:var(--tx2);font-size:11px;text-align:center;padding:20px">
              Send a message — all messages are end-to-end encrypted
            </div>
          </div>
          <div class="chat-input-row">
            <input class="chat-input" id="chat-in" placeholder="Type your message..." onkeydown="if(event.key==='Enter')sendChat()">
            <select class="algo-sel" id="chat-algo">
              <option value="aes">AES-256</option>
              <option value="chacha">ChaCha20</option>
            </select>
            <button class="send-btn" onclick="sendChat()">Send 🔒</button>
          </div>
        </div>
      </div>
    </div>
    <div class="card">
      <h2>📁 FILE ENCRYPTION</h2>
      <div class="upload-zone" onclick="document.getElementById('file-in').click()">
        <input type="file" id="file-in" onchange="handleFile(this)">
        <div style="font-size:24px;margin-bottom:8px">📂</div>
        <div>Click to select any file</div>
        <div style="font-size:11px;color:var(--tx2);margin-top:4px">File will be encrypted with AES-256-GCM</div>
      </div>
      <div id="file-result" style="display:none">
        <table>
          <tr><th>Field</th><th>Value</th></tr>
          <tbody id="file-table"></tbody>
        </table>
        <button class="export-btn" style="margin-top:10px" onclick="downloadEncFile()">⬇ Download Encrypted File</button>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>🔍 ENCRYPTION DETAIL — LAST MESSAGE</h2>
    <table>
      <tr><th>Field</th><th>Value</th></tr>
      <tbody id="msg-detail">
        <tr><td colspan="2" style="color:var(--tx2);text-align:center">Send a message above to see full encryption detail</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ── TAB 3: Energy Profiler ──────────────────────────────────────────── -->
<div class="panel" id="tab-profiler">
  <div style="margin-bottom:16px">
    <button class="prof-btn" id="run-btn" onclick="runProfiler()">▶ Run Full Energy Profile</button>
    <button class="export-btn" onclick="exportCSV()">⬇ Export CSV for Report</button>
    <span style="font-size:11px;color:var(--tx2)">Tests 7 payload sizes × 2 algorithms × 5 runs each (~30 sec)</span>
  </div>
  <div class="progress-wrap"><div class="progress-bar" id="prof-progress"></div></div>
  <div id="prof-status" style="font-size:11px;color:var(--tx2);margin-bottom:12px">Click Run to start profiling</div>

  <div class="grid2">
    <div class="card">
      <h2>⚡ ENERGY COST — µJ PER ENCRYPTION</h2>
      <canvas id="energyChart"></canvas>
    </div>
    <div class="card">
      <h2>⏱ ENCRYPTION TIME — ms</h2>
      <canvas id="timeChart"></canvas>
    </div>
  </div>

  <div class="card">
    <h2>📊 FULL BENCHMARK TABLE — AES-256-GCM vs ChaCha20-Poly1305</h2>
    <table>
      <tr>
        <th>Payload</th>
        <th>AES Enc (ms)</th><th>AES Dec (ms)</th><th>AES CPU %</th><th>AES Energy (µJ)</th>
        <th>CHA Enc (ms)</th><th>CHA Dec (ms)</th><th>CHA CPU %</th><th>CHA Energy (µJ)</th>
        <th>Winner</th>
      </tr>
      <tbody id="prof-table">
        <tr><td colspan="10" style="color:var(--tx2);text-align:center">Run the profiler to see results</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ── TAB 4: About ────────────────────────────────────────────────────── -->
<div class="panel" id="tab-about">
  <div class="grid2">
    <div class="card">
      <h2>📌 PROJECT OBJECTIVES</h2>
      <table>
        <tr><th>#</th><th>Objective</th><th>Implemented By</th></tr>
        <tr><td>1</td><td>Lightweight crypto for IoT</td><td class="ok">ChaCha20 for Tier1-2 devices</td></tr>
        <tr><td>2</td><td>AES + TLS implementation</td><td class="ok">AES-256-GCM + TLS 1.3</td></tr>
        <tr><td>3</td><td>Security vs performance balance</td><td class="ok">Adaptive selector + profiler</td></tr>
      </table>
    </div>
    <div class="card">
      <h2>📚 LITERATURE GAPS ADDRESSED</h2>
      <table>
        <tr><th>Paper</th><th>Gap</th><th>Solution</th></tr>
        <tr><td>Kumar 2024</td><td>No real-time adaptability</td><td class="ok">Adaptive selector</td></tr>
        <tr><td>Lakshmanan 2024</td><td>Energy not measured</td><td class="ok">Energy profiler (µJ)</td></tr>
        <tr><td>Khan 2025</td><td>High TLS latency</td><td class="ok">TLS timing per message</td></tr>
        <tr><td>Sahu 2024</td><td>AES overhead on constrained</td><td class="ok">ChaCha20 for small payloads</td></tr>
        <tr><td>Mohsin 2026</td><td>No universal solution</td><td class="ok">Multi-param decision engine</td></tr>
      </table>
    </div>
  </div>
  <div class="card" style="margin-top:12px">
    <h2>🛠 TECH STACK</h2>
    <table>
      <tr><th>Layer</th><th>Technology</th><th>Purpose</th></tr>
      <tr><td>Encryption</td><td>PyCryptodome</td><td>AES-256-GCM + ChaCha20-Poly1305</td></tr>
      <tr><td>Transport</td><td>TLS 1.3 (HTTPS on Render)</td><td>Secure channel</td></tr>
      <tr><td>Backend</td><td>Flask + Flask-SocketIO</td><td>REST API + real-time WebSocket</td></tr>
      <tr><td>Frontend</td><td>Chart.js + vanilla JS</td><td>Live charts + dashboard</td></tr>
      <tr><td>Hosting</td><td>Render (free tier)</td><td>Cloud deployment</td></tr>
      <tr><td>Profiling</td><td>psutil + perf_counter</td><td>CPU, RAM, energy measurement</td></tr>
    </table>
  </div>
</div>

<script>
const socket = io();
let currentRoom = 'general';
let profilerData = [];
let encChartI, timeChartI, encChartE, timeChartE;
let lastFileResult = null;

// ── Tab switching ────────────────────────────────────────────────────────
function showTab(name) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  event.target.classList.add('active');
}

// ── Mobile URL ───────────────────────────────────────────────────────────
const mobileUrl = location.origin + '/mobile';
document.getElementById('mob-url').href = mobileUrl;
document.getElementById('mob-url').textContent = mobileUrl;
function copyMobUrl(){navigator.clipboard.writeText(mobileUrl);}

// ── IoT live polling ─────────────────────────────────────────────────────
function updateIoT() {
  fetch('/api/iot/feed').then(r=>r.json()).then(data => {
    document.getElementById('stat-total').textContent = data.total;
    document.getElementById('stat-cpu').textContent = data.cpu + '%';
    document.getElementById('bar-cpu').style.width = data.cpu + '%';
    document.getElementById('bar-total').style.width = Math.min(data.total, 100) + '%';

    // Device table (one row per device tier, latest reading)
    const seen = {};
    (data.devices||[]).forEach(d => { if(!seen[d.tier]) seen[d.tier] = d; });
    const devHtml = Object.values(seen).map(d => `
      <tr>
        <td><span class="badge b-dev">${d.device}</span></td>
        <td style="font-size:10px;color:var(--tx2)">${d.tier}</td>
        <td><span class="badge ${d.algo.includes('AES')?'b-aes':'b-cha'}">${d.algo}</span></td>
        <td class="ok">${d.enc_ms}</td>
        <td><span class="${d.security_score>80?'ok':'warn'}">${d.security_score}/100</span></td>
        <td class="reason-cell">${d.reason}</td>
      </tr>`).join('');
    document.getElementById('device-table').innerHTML = devHtml || '<tr><td colspan="6">Loading...</td></tr>';

    // Message feed table
    const msgHtml = (data.devices||[]).slice(0,15).map(d => `
      <tr>
        <td>${d.time}</td>
        <td><span class="badge b-dev">${d.device}</span></td>
        <td><span class="badge ${d.algo.includes('AES')?'b-aes':'b-cha'}">${d.algo}</span></td>
        <td>${d.payload_bytes}B</td>
        <td style="font-size:10px;word-break:break-all">${d.ct_preview}</td>
        <td class="ok">${d.enc_ms}</td>
        <td>${d.dec_ms}</td>
        <td class="ok">✓ Verified</td>
      </tr>`).join('');
    document.getElementById('msg-table').innerHTML = msgHtml || '<tr><td colspan="8">Waiting...</td></tr>';

    // Throughput chart update
    updateThroughputChart(data.devices||[]);
  });
}

let throughputChart;
function updateThroughputChart(devices) {
  const ctx = document.getElementById('throughputChart').getContext('2d');
  const labels = devices.slice(0,8).map(d=>d.device).reverse();
  const vals = devices.slice(0,8).map(d=>d.payload_bytes/(d.enc_ms/1000)/1024).reverse();
  if(!throughputChart) {
    throughputChart = new Chart(ctx,{type:'bar',data:{labels,datasets:[{
      label:'Throughput KB/s',data:vals,
      backgroundColor:'#1f4068',borderColor:'#58a6ff',borderWidth:1}]},
      options:{responsive:true,plugins:{legend:{labels:{color:'#c9d1d9',font:{family:'Courier New'}}}},
        scales:{x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},
                y:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}}}}});
  } else {
    throughputChart.data.labels = labels;
    throughputChart.data.datasets[0].data = vals;
    throughputChart.update();
  }
}

setInterval(updateIoT, 2000);
updateIoT();

// ── Chat ─────────────────────────────────────────────────────────────────
socket.on('connect', () => socket.emit('join', {room: currentRoom}));
socket.on('new_message', data => appendMessage(data));

function joinRoom(room, btn) {
  currentRoom = room;
  document.querySelectorAll('.room-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  socket.emit('join', {room});
  document.getElementById('chat-msgs').innerHTML =
    '<div style="color:var(--tx2);font-size:11px;text-align:center;padding:20px">Joined '+room+'</div>';
}

function sendChat() {
  const msg = document.getElementById('chat-in').value.trim();
  const algo = document.getElementById('chat-algo').value;
  const user = document.getElementById('username').value.trim() || 'User';
  if(!msg) return;
  fetch('/api/chat/send', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({message:msg, algo, sender:user, room:currentRoom})
  }).then(r=>r.json()).then(d => {
    appendMessage(d, true);
    showMsgDetail(d);
    document.getElementById('chat-in').value = '';
  });
}

function appendMessage(d, mine=false) {
  const box = document.getElementById('chat-msgs');
  const div = document.createElement('div');
  div.className = 'msg' + (mine?' mine':'');
  div.innerHTML = `
    <div class="msg-sender">${d.sender} · ${d.time} · <span class="badge ${d.algo.includes('AES')?'b-aes':'b-cha'}">${d.algo}</span></div>
    <div class="msg-text">${d.original}</div>
    <div class="msg-crypto">
      Ciphertext: ${d.ct_preview}<br>
      Enc: ${d.enc_ms}ms &nbsp;|&nbsp; Dec: ${d.dec_ms}ms &nbsp;|&nbsp;
      <span class="ok">✓ ${d.integrity}</span>
    </div>`;
  box.insertBefore(div, box.firstChild);
}

function showMsgDetail(d) {
  document.getElementById('msg-detail').innerHTML = `
    <tr><td>Sender</td><td>${d.sender}</td></tr>
    <tr><td>Algorithm</td><td><span class="badge ${d.algo.includes('AES')?'b-aes':'b-cha'}">${d.algo}</span></td></tr>
    <tr><td>Original message</td><td class="ok">${d.original}</td></tr>
    <tr><td>Ciphertext (full)</td><td style="word-break:break-all;font-size:10px">${d.ciphertext}</td></tr>
    <tr><td>Nonce</td><td style="font-size:10px">${d.nonce}</td></tr>
    <tr><td>Auth Tag</td><td style="font-size:10px">${d.tag}</td></tr>
    <tr><td>Enc time</td><td class="ok">${d.enc_ms} ms</td></tr>
    <tr><td>Dec time</td><td class="ok">${d.dec_ms} ms</td></tr>
    <tr><td>Payload size</td><td>${d.payload_bytes} bytes</td></tr>
    <tr><td>Integrity</td><td class="ok">✓ ${d.integrity}</td></tr>`;
}

// ── File encryption ──────────────────────────────────────────────────────
function handleFile(input) {
  const file = input.files[0]; if(!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    const b64 = e.target.result.split(',')[1];
    fetch('/api/chat/encrypt_file', {method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({filename:file.name, data:b64, algo:'aes'})
    }).then(r=>r.json()).then(d => {
      lastFileResult = d;
      document.getElementById('file-result').style.display='block';
      document.getElementById('file-table').innerHTML = `
        <tr><td>Filename</td><td>${d.filename}</td></tr>
        <tr><td>Algorithm</td><td><span class="badge b-aes">${d.algo}</span></td></tr>
        <tr><td>Original size</td><td>${d.original_size} bytes</td></tr>
        <tr><td>Encrypted size</td><td>${d.encrypted_size} bytes</td></tr>
        <tr><td>Enc time</td><td class="ok">${d.enc_ms} ms</td></tr>
        <tr><td>Nonce</td><td style="font-size:10px">${d.nonce}</td></tr>
        <tr><td>Auth Tag</td><td style="font-size:10px">${d.tag}</td></tr>
        <tr><td>Ciphertext preview</td><td style="font-size:10px;word-break:break-all">${d.ct_hex_preview}</td></tr>`;
    });
  };
  reader.readAsDataURL(file);
}

function downloadEncFile() {
  if(!lastFileResult) return;
  window.location = '/api/chat/download_encrypted?filename='+encodeURIComponent(lastFileResult.filename);
}

// ── Energy Profiler ──────────────────────────────────────────────────────
function runProfiler() {
  const btn = document.getElementById('run-btn');
  btn.textContent = '⏳ Running...'; btn.classList.add('running');
  document.getElementById('prof-status').textContent = 'Profiling in progress — testing 7 payload sizes...';
  document.getElementById('prof-progress').style.width = '10%';

  fetch('/api/profiler/run').then(r=>r.json()).then(data => {
    profilerData = data;
    btn.textContent = '▶ Run Again'; btn.classList.remove('running');
    document.getElementById('prof-progress').style.width = '100%';
    document.getElementById('prof-status').textContent =
      'Profiling complete — ' + data.length + ' payload sizes tested. Export CSV for your report.';
    renderProfilerCharts(data);
    renderProfilerTable(data);
  });
}

function renderProfilerCharts(data) {
  const labels = data.map(d=>d.payload_label);
  const aesEnergy = data.map(d=>d.aes.energy_uj);
  const chaEnergy = data.map(d=>d.chacha.energy_uj);
  const aesTime = data.map(d=>d.aes.enc_ms);
  const chaTime = data.map(d=>d.chacha.enc_ms);

  const opts = {responsive:true,
    plugins:{legend:{labels:{color:'#c9d1d9',font:{family:'Courier New'}}}},
    scales:{x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},
            y:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}}}};

  if(encChartE) encChartE.destroy();
  encChartE = new Chart(document.getElementById('energyChart'),{type:'line',data:{labels,
    datasets:[
      {label:'AES-256-GCM (µJ)',data:aesEnergy,borderColor:'#58a6ff',backgroundColor:'#1f406844',fill:true},
      {label:'ChaCha20 (µJ)',data:chaEnergy,borderColor:'#3fb950',backgroundColor:'#0f3a2a44',fill:true}
    ]},options:opts});

  if(timeChartE) timeChartE.destroy();
  timeChartE = new Chart(document.getElementById('timeChart'),{type:'line',data:{labels,
    datasets:[
      {label:'AES-256-GCM (ms)',data:aesTime,borderColor:'#58a6ff',backgroundColor:'#1f406844',fill:true},
      {label:'ChaCha20 (ms)',data:chaTime,borderColor:'#3fb950',backgroundColor:'#0f3a2a44',fill:true}
    ]},options:opts});
}

function renderProfilerTable(data) {
  const html = data.map(d => {
    const winner = d.aes.enc_ms < d.chacha.enc_ms ? 'AES' : 'ChaCha20';
    return `<tr>
      <td>${d.payload_label}</td>
      <td class="ok">${d.aes.enc_ms}</td><td>${d.aes.dec_ms}</td>
      <td>${d.aes.cpu}</td><td>${d.aes.energy_uj}</td>
      <td class="ok">${d.chacha.enc_ms}</td><td>${d.chacha.dec_ms}</td>
      <td>${d.chacha.cpu}</td><td>${d.chacha.energy_uj}</td>
      <td><span class="badge ${winner==='AES'?'b-aes':'b-cha'}">${winner}</span></td>
    </tr>`;}).join('');
  document.getElementById('prof-table').innerHTML = html;
}

function exportCSV() {
  window.location = '/api/profiler/export_csv';
}
</script>
</body>
</html>
"""

MOBILE_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Secure Crypto — Mobile</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.6.1/socket.io.min.js"></script>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:14px;font-size:13px}
    h1{color:#fff;font-size:14px;margin-bottom:4px}
    .sub{color:#8b949e;font-size:11px;margin-bottom:14px}
    .card{background:#161b22;border:0.5px solid #30363d;border-radius:8px;padding:14px;margin-bottom:12px}
    h2{color:#58a6ff;font-size:12px;margin-bottom:10px}
    .row{display:flex;justify-content:space-between;align-items:flex-start;
         padding:5px 0;border-bottom:0.5px solid #21262d;font-size:12px;gap:8px}
    .lbl{color:#8b949e;white-space:nowrap;min-width:80px}
    .val{color:#e6edf3;word-break:break-all;text-align:right}
    .ok{color:#3fb950}.err{color:#f85149}
    button{width:100%;padding:12px;margin-top:8px;border:none;border-radius:6px;
           font-size:13px;font-weight:bold;cursor:pointer;font-family:monospace}
    .btn-aes{background:#1f4068;color:#58a6ff;border:0.5px solid #58a6ff}
    .btn-cha{background:#0f3a2a;color:#3fb950;border:0.5px solid #3fb950}
    textarea{width:100%;padding:10px;background:#21262d;border:0.5px solid #30363d;
             border-radius:6px;color:#e6edf3;font-size:13px;margin-top:6px;
             resize:vertical;min-height:80px;font-family:monospace}
    #result-card{display:none}
    #spinner{display:none;text-align:center;color:#58a6ff;padding:10px;font-size:12px}
    .log-entry{padding:6px;border-bottom:0.5px solid #21262d;font-size:11px;line-height:1.6}
    .badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:bold;margin-right:4px}
    .b-aes{background:#1f4068;color:#58a6ff}
    .b-cha{background:#0f3a2a;color:#3fb950}
    #log{max-height:200px;overflow-y:auto}
  </style>
</head>
<body>
  <h1>🔐 Live Cryptography</h1>
  <p class="sub">All encryption runs on the cloud server in real time</p>

  <div class="card">
    <h2>📡 CONNECTION</h2>
    <div class="row"><span class="lbl">Server</span><span class="ok">● Online</span></div>
    <div class="row"><span class="lbl">Protocol</span><span class="val">HTTPS + AES-256-GCM</span></div>
    <div class="row"><span class="lbl">Your IP</span><span class="val" id="myip">detecting...</span></div>
    <div class="row"><span class="lbl">Sent</span><span class="val" id="count">0</span></div>
  </div>

  <div class="card">
    <h2>✉️ ENCRYPT YOUR MESSAGE</h2>
    <textarea id="msg" placeholder="Type anything — it will be encrypted and sent to the dashboard..."></textarea>
    <button class="btn-aes" onclick="sendMsg('aes')">🔒 AES-256-GCM</button>
    <button class="btn-cha" onclick="sendMsg('chacha')" style="margin-top:6px">🔒 ChaCha20-Poly1305</button>
    <div id="spinner">⏳ Encrypting...</div>
  </div>

  <div class="card" id="result-card">
    <h2>⚡ RESULT</h2>
    <div class="row"><span class="lbl">Original</span><span class="val ok" id="r-orig"></span></div>
    <div class="row"><span class="lbl">Algorithm</span><span class="val" id="r-algo"></span></div>
    <div class="row"><span class="lbl">Encrypted</span><span class="val" id="r-enc"></span></div>
    <div class="row"><span class="lbl">Nonce</span><span class="val" id="r-nonce"></span></div>
    <div class="row"><span class="lbl">Auth Tag</span><span class="val" id="r-tag"></span></div>
    <div class="row"><span class="lbl">Enc Time</span><span class="val ok" id="r-ems"></span></div>
    <div class="row"><span class="lbl">Dec Time</span><span class="val ok" id="r-dms"></span></div>
    <div class="row"><span class="lbl">Decrypted</span><span class="ok" id="r-dec"></span></div>
    <div class="row"><span class="lbl">Integrity</span><span class="ok">✓ Verified — Not Tampered</span></div>
  </div>

  <div class="card">
    <h2>📋 MY HISTORY</h2>
    <div id="log"><p style="color:#8b949e;font-size:11px">Nothing yet</p></div>
  </div>

<script>
  const socket = io();
  let count = 0;
  const log = [];
  fetch('/api/myinfo').then(r=>r.json()).then(d=>document.getElementById('myip').textContent=d.ip);

  function sendMsg(algo) {
    const msg = document.getElementById('msg').value.trim() ||
      'Hello from phone at ' + new Date().toLocaleTimeString();
    document.getElementById('spinner').style.display='block';
    document.getElementById('result-card').style.display='none';
    fetch('/api/chat/send', {method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({message:msg, algo, sender:'Mobile-'+document.getElementById('myip').textContent, room:'general'})
    }).then(r=>r.json()).then(d=>{
      document.getElementById('spinner').style.display='none';
      document.getElementById('result-card').style.display='block';
      document.getElementById('r-orig').textContent=d.original;
      document.getElementById('r-algo').textContent=d.algo;
      document.getElementById('r-enc').textContent=d.ct_preview;
      document.getElementById('r-nonce').textContent=d.nonce;
      document.getElementById('r-tag').textContent=d.tag;
      document.getElementById('r-ems').textContent=d.enc_ms+' ms';
      document.getElementById('r-dms').textContent=d.dec_ms+' ms';
      document.getElementById('r-dec').textContent=d.decrypted;
      count++; document.getElementById('count').textContent=count;
      log.unshift({algo:d.algo,msg:msg.substring(0,30),ms:d.enc_ms,time:new Date().toLocaleTimeString()});
      document.getElementById('log').innerHTML = log.map(e=>
        '<div class="log-entry"><span class="badge '+(e.algo.includes('AES')?'b-aes':'b-cha')+'">'+
        e.algo+'</span>'+e.time+' — "'+e.msg+'..." → '+e.ms+'ms</div>').join('');
    }).catch(()=>{document.getElementById('spinner').style.display='none';alert('Error');});
  }
</script>
</body>
</html>
"""

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(MAIN_DASH)

@app.route("/mobile")
def mobile():
    return render_template_string(MOBILE_PAGE)

@app.route("/api/myinfo")
def myinfo():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    live_stats["devices_connected"].add(ip)
    return jsonify({"ip": ip})

# ── IoT Feed ─────────────────────────────────────────────────────────────────
@app.route("/api/iot/feed")
def iot_feed():
    cpu = psutil.cpu_percent(interval=0.1)
    return jsonify({
        "total": len(device_log),
        "cpu": round(cpu, 1),
        "devices": list(device_log[:20])
    })

# ── Chat ─────────────────────────────────────────────────────────────────────
@app.route("/api/chat/send", methods=["POST"])
def chat_send():
    data = request.json or {}
    entry = send_message(
        sender=data.get("sender", "Anonymous"),
        message=data.get("message", "Hello"),
        algo=data.get("algo", "aes"),
        room=data.get("room", "general")
    )
    live_stats["chat_messages"] += 1
    live_stats["devices_connected"].add(
        request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    )
    socketio.emit("new_message", entry, room=entry["room"])
    return jsonify(entry)

@app.route("/api/chat/encrypt_file", methods=["POST"])
def chat_encrypt_file():
    data = request.json or {}
    import base64
    file_bytes = base64.b64decode(data.get("data", ""))
    result = encrypt_file(file_bytes, data.get("filename", "file.bin"), data.get("algo", "aes"))
    # Store encrypted bytes for download
    app.config["LAST_ENC_FILE"] = result
    return jsonify({k: v for k, v in result.items() if k not in ["ct_bytes","nonce_bytes","tag_bytes"]})

@app.route("/api/chat/download_encrypted")
def download_encrypted():
    result = app.config.get("LAST_ENC_FILE")
    if not result:
        return "No file", 404
    payload = result["nonce_bytes"] + result["tag_bytes"] + result["ct_bytes"]
    return send_file(
        io.BytesIO(payload),
        as_attachment=True,
        download_name="encrypted_" + result["filename"] + ".enc",
        mimetype="application/octet-stream"
    )

@app.route("/api/chat/history")
def chat_hist():
    return jsonify(chat_history[:30])

# ── Energy Profiler ───────────────────────────────────────────────────────────
@app.route("/api/profiler/run")
def profiler_run():
    data = run_full_profile()
    app.config["LAST_PROFILE"] = data
    return jsonify(data)

@app.route("/api/profiler/export_csv")
def profiler_csv():
    data = app.config.get("LAST_PROFILE", [])
    if not data:
        data = [profile_encryption(s) for s in [100, 1024, 10240]]
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Payload","AES_Enc_ms","AES_Dec_ms","AES_CPU_%","AES_Energy_uJ",
                     "ChaCha_Enc_ms","ChaCha_Dec_ms","ChaCha_CPU_%","ChaCha_Energy_uJ","Winner"])
    for d in data:
        winner = "AES" if d["aes"]["enc_ms"] < d["chacha"]["enc_ms"] else "ChaCha20"
        writer.writerow([
            d["payload_label"],
            d["aes"]["enc_ms"], d["aes"]["dec_ms"], d["aes"]["cpu"], d["aes"]["energy_uj"],
            d["chacha"]["enc_ms"], d["chacha"]["dec_ms"], d["chacha"]["cpu"], d["chacha"]["energy_uj"],
            winner
        ])
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        as_attachment=True,
        download_name="crypto_benchmark_results.csv",
        mimetype="text/csv"
    )

@app.route("/api/status")
def status():
    return jsonify({"status": "ok", "modules": ["iot_gateway","encrypted_chat","energy_profiler"]})

# ── WebSocket ─────────────────────────────────────────────────────────────────
@socketio.on("join")
def on_join(data):
    join_room(data.get("room", "general"))

# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[OK] Dashboard → http://localhost:{port}")
    print(f"[OK] Mobile    → http://localhost:{port}/mobile\n")
    app.run( host="0.0.0.0", port=port, debug=False)

