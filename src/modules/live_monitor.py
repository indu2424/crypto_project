from flask import Flask, request, jsonify, render_template_string
from flask_socketio import SocketIO, emit
import sys, time, os, threading, json, psutil
sys.path.insert(0, "src/modules")
from aes_module import load_key, encrypt, decrypt
from chacha_module import load_chacha_key, chacha_encrypt, chacha_decrypt

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Live log of all real device connections
live_events = []
connected_devices = {}

# ── HTML served to mobile browser ──────────────────────
MOBILE_HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Live Crypto Monitor</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:16px}
    h1{color:#fff;font-size:1.1em;margin-bottom:4px}
    .sub{color:#8b949e;font-size:.8em;margin-bottom:16px}
    .card{background:#161b22;border:1px solid #30363d;border-radius:8px;
          padding:14px;margin-bottom:12px}
    h2{color:#58a6ff;font-size:.9em;margin-bottom:10px}
    .row{display:flex;justify-content:space-between;padding:4px 0;
         border-bottom:1px solid #21262d;font-size:.82em}
    .lbl{color:#8b949e}.val{color:#e6edf3}
    .ok{color:#3fb950}.err{color:#f85149}.warn{color:#d29922}
    button{width:100%;padding:12px;margin-top:8px;border:none;
           border-radius:6px;font-size:.95em;font-weight:bold;cursor:pointer}
    .btn-aes{background:#1f4068;color:#58a6ff}
    .btn-cha{background:#1a3a2a;color:#3fb950}
    .btn-send{background:#5a3e1b;color:#d29922}
    input{width:100%;padding:10px;background:#21262d;border:1px solid #30363d;
          border-radius:6px;color:#e6edf3;font-size:.9em;margin-top:6px}
    #log{max-height:300px;overflow-y:auto}
    .log-entry{padding:6px;border-bottom:1px solid #21262d;font-size:.78em}
    .badge{display:inline-block;padding:2px 6px;border-radius:4px;
           font-size:.75em;font-weight:bold;margin-right:4px}
    .b-aes{background:#1f4068;color:#58a6ff}
    .b-cha{background:#1a3a2a;color:#3fb950}
    .b-dev{background:#2d1f3d;color:#a78bfa}
  </style>
</head>
<body>
  <h1>🔐 Live Cryptography Monitor</h1>
  <p class="sub">Your device is connected — all encryption is real</p>

  <!-- Device Info -->
  <div class="card">
    <h2>📱 Your Device Info</h2>
    <div class="row"><span class="lbl">IP Address</span>
      <span class="val" id="myip">detecting...</span></div>
    <div class="row"><span class="lbl">Device</span>
      <span class="val" id="mydevice">detecting...</span></div>
    <div class="row"><span class="lbl">Connection</span>
      <span class="ok" id="conn_status">● Connected</span></div>
    <div class="row"><span class="lbl">Messages Sent</span>
      <span class="val" id="msg_count">0</span></div>
  </div>

  <!-- Send Custom Message -->
  <div class="card">
    <h2>✉️ Send Your Own Message</h2>
    <input type="text" id="custom_msg" placeholder="Type anything to encrypt...">
    <button class="btn-aes" onclick="sendMessage('aes')">
      🔒 Encrypt with AES-256-GCM & Send
    </button>
    <button class="btn-cha" onclick="sendMessage('cha')" style="margin-top:6px">
      🔒 Encrypt with ChaCha20 & Send
    </button>
  </div>

  <!-- Live Result -->
  <div class="card">
    <h2>⚡ Last Encryption Result</h2>
    <div class="row"><span class="lbl">Original</span>
      <span class="val" id="r_orig">—</span></div>
    <div class="row"><span class="lbl">Algorithm</span>
      <span class="val" id="r_algo">—</span></div>
    <div class="row"><span class="lbl">Encrypted</span>
      <span class="val" id="r_enc" style="word-break:break-all;max-width:60%">—</span></div>
    <div class="row"><span class="lbl">Nonce</span>
      <span class="val" id="r_nonce" style="word-break:break-all;max-width:60%">—</span></div>
    <div class="row"><span class="lbl">Auth Tag</span>
      <span class="val" id="r_tag" style="word-break:break-all;max-width:60%">—</span></div>
    <div class="row"><span class="lbl">Enc Time</span>
      <span class="val" id="r_enc_ms">—</span></div>
    <div class="row"><span class="lbl">Dec Time</span>
      <span class="val" id="r_dec_ms">—</span></div>
    <div class="row"><span class="lbl">Decrypted</span>
      <span class="ok" id="r_dec">—</span></div>
    <div class="row"><span class="lbl">Integrity</span>
      <span class="ok" id="r_integrity">—</span></div>
  </div>

  <!-- Live Event Log -->
  <div class="card">
    <h2>📋 Live Event Log</h2>
    <div id="log"><p style="color:#8b949e;font-size:.8em">Waiting for events...</p></div>
  </div>

<script>
  let msgCount = 0;

  // Detect device info
  fetch('/api/myinfo').then(r=>r.json()).then(d=>{
    document.getElementById('myip').textContent = d.ip;
    document.getElementById('mydevice').textContent = d.device;
  });

  function sendMessage(algo) {
    const msg = document.getElementById('custom_msg').value ||
                'Hello from my phone at ' + new Date().toLocaleTimeString();
    msgCount++;
    document.getElementById('msg_count').textContent = msgCount;

    fetch('/api/encrypt_live', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({message: msg, algo: algo,
                            device: navigator.userAgent.substring(0,50)})
    })
    .then(r => r.json())
    .then(d => {
      document.getElementById('r_orig').textContent = d.original;
      document.getElementById('r_algo').textContent = d.algorithm;
      document.getElementById('r_enc').textContent = d.ciphertext;
      document.getElementById('r_nonce').textContent = d.nonce;
      document.getElementById('r_tag').textContent = d.tag;
      document.getElementById('r_enc_ms').textContent = d.enc_ms + ' ms';
      document.getElementById('r_dec_ms').textContent = d.dec_ms + ' ms';
      document.getElementById('r_dec').textContent = d.decrypted;
      document.getElementById('r_integrity').textContent = '✓ Verified — Not Tampered';

      // Add to log
      const log = document.getElementById('log');
      const entry = document.createElement('div');
      entry.className = 'log-entry';
      entry.innerHTML =
        '<span class="badge b-dev">PHONE</span>' +
        '<span class="badge ' + (algo=='aes'?'b-aes':'b-cha') + '">' +
        d.algorithm + '</span>' +
        new Date().toLocaleTimeString() + ' — "' + d.original.substring(0,30) + '..." ' +
        '→ ' + d.enc_ms + 'ms enc / ' + d.dec_ms + 'ms dec';
      log.insertBefore(entry, log.firstChild);
    });
  }

  // Auto-refresh log every 3 seconds
  setInterval(() => {
    fetch('/api/live_log').then(r=>r.json()).then(events => {
      if(events.length === 0) return;
      const log = document.getElementById('log');
      log.innerHTML = events.map(e =>
        '<div class="log-entry">' +
        '<span class="badge ' + (e.source=='phone'?'b-dev':'b-aes') + '">' +
        e.source.toUpperCase() + '</span>' +
        '<span class="badge ' + (e.algo=='AES-256-GCM'?'b-aes':'b-cha') + '">' +
        e.algo + '</span>' +
        e.time + ' — ' + (e.msg||'').substring(0,35) + '... ' +
        '→ ' + e.enc_ms + 'ms' +
        '</div>'
      ).join('');
    });
  }, 3000);
</script>
</body>
</html>
"""

# ── Dashboard HTML (for laptop browser) ────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>Live Device Monitor — Kali Dashboard</title>
  <meta http-equiv="refresh" content="4">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:24px}
    h1{color:#fff;font-size:1.3em;margin-bottom:4px}
    .sub{color:#8b949e;font-size:.85em;margin-bottom:20px}
    h2{color:#58a6ff;font-size:.95em;margin-bottom:12px}
    .grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:16px}
    .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px}
    .full{grid-column:1/-1}
    table{width:100%;border-collapse:collapse;font-size:.82em}
    td,th{padding:7px 10px;border:1px solid #21262d}
    th{background:#21262d;color:#fff}
    .ok{color:#3fb950}.err{color:#f85149}.warn{color:#d29922}
    .metric .val{font-size:1.5em;font-weight:bold;color:#58a6ff}
    .metric .lbl{font-size:.78em;color:#8b949e;margin-top:4px}
    .qr{text-align:center;padding:10px}
    .qr img{width:180px;height:180px}
    .url{font-size:1.1em;color:#3fb950;font-weight:bold;text-align:center;
         margin-top:8px;word-break:break-all}
    .badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.75em;
           font-weight:bold;margin-right:4px}
    .b-aes{background:#1f4068;color:#58a6ff}
    .b-cha{background:#1a3a2a;color:#3fb950}
    .b-dev{background:#2d1f3d;color:#a78bfa}
  </style>
</head>
<body>
  <h1>🔐 Live Device Encryption Monitor</h1>
  <p class="sub">Real messages from real devices — encrypted live on this server</p>

  <div class="grid">
    <!-- QR Code to connect mobile -->
    <div class="card qr">
      <h2>📱 Connect Your Phone</h2>
      <img src="/api/qrcode" alt="QR Code">
      <div class="url">http://{{ ip }}:5000/mobile</div>
      <p style="color:#8b949e;font-size:.78em;margin-top:8px;text-align:center">
        Scan with phone camera<br>Must be on same WiFi
      </p>
    </div>

    <!-- Live stats -->
    <div class="card metric" style="text-align:center">
      <div class="val">{{ stats.total_msgs }}</div>
      <div class="lbl">Total Messages Encrypted</div>
      <div style="margin-top:16px" class="val" style="font-size:1em">
        {{ stats.connected_devices }}</div>
      <div class="lbl">Devices Connected</div>
      <div style="margin-top:16px">
        <span style="color:#3fb950;font-size:.85em">
          CPU: {{ res.cpu_percent }}% &nbsp;|&nbsp; RAM: {{ res.ram_used_mb }} MB
        </span>
      </div>
    </div>

    <!-- Last message -->
    <div class="card">
      <h2>⚡ Last Encrypted Message</h2>
      {% if last %}
      <table>
        <tr><td style="color:#8b949e">From</td>
            <td><span class="badge b-dev">{{ last.device[:30] }}</span></td></tr>
        <tr><td style="color:#8b949e">Message</td>
            <td class="ok">{{ last.original[:40] }}</td></tr>
        <tr><td style="color:#8b949e">Algorithm</td>
            <td><span class="badge {{ 'b-aes' if 'AES' in last.algo else 'b-cha' }}">
            {{ last.algo }}</span></td></tr>
        <tr><td style="color:#8b949e">Encrypted</td>
            <td style="word-break:break-all;font-size:.75em">{{ last.ct[:40] }}...</td></tr>
        <tr><td style="color:#8b949e">Enc Time</td>
            <td class="ok">{{ last.enc_ms }} ms</td></tr>
        <tr><td style="color:#8b949e">Integrity</td>
            <td class="ok">✓ Verified</td></tr>
      </table>
      {% else %}
      <p style="color:#8b949e">Waiting for first message...</p>
      {% endif %}
    </div>
  </div>

  <!-- Full live log -->
  <div class="card full">
    <h2>📋 All Live Encrypted Messages</h2>
    <table>
      <tr>
        <th>Time</th><th>Source</th><th>Algorithm</th>
        <th>Original Message</th><th>Ciphertext (preview)</th>
        <th>Enc (ms)</th><th>Dec (ms)</th><th>Integrity</th>
      </tr>
      {% for e in events %}
      <tr>
        <td>{{ e.time }}</td>
        <td><span class="badge b-dev">{{ e.source[:15] }}</span></td>
        <td><span class="badge {{ 'b-aes' if 'AES' in e.algo else 'b-cha' }}">
            {{ e.algo }}</span></td>
        <td class="ok">{{ e.msg[:40] }}</td>
        <td style="font-size:.75em">{{ e.ct[:30] }}...</td>
        <td>{{ e.enc_ms }}</td>
        <td>{{ e.dec_ms }}</td>
        <td class="ok">✓ Verified</td>
      </tr>
      {% endfor %}
      {% if not events %}
      <tr><td colspan="8" style="text-align:center;color:#8b949e">
        No messages yet — scan QR code with your phone</td></tr>
      {% endif %}
    </table>
  </div>
</body>
</html>
"""

# ── Helpers ─────────────────────────────────────────────
def get_resources():
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "ram_used_mb": round(psutil.virtual_memory().used/(1024*1024), 1),
        "ram_total_mb": round(psutil.virtual_memory().total/(1024*1024), 1)
    }

def get_local_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "localhost"

stats = {"total_msgs": 0, "connected_devices": set()}

# ── Routes ──────────────────────────────────────────────
@app.route("/")
def dashboard():
    ip = get_local_ip()
    last = live_events[0] if live_events else None
    return render_template_string(DASHBOARD_HTML,
        ip=ip, stats={
            "total_msgs": stats["total_msgs"],
            "connected_devices": len(stats["connected_devices"])
        },
        res=get_resources(), last=last, events=live_events[:20])

@app.route("/mobile")
def mobile():
    return render_template_string(MOBILE_HTML)

@app.route("/api/myinfo")
def myinfo():
    ip = request.remote_addr
    device = request.user_agent.string[:80]
    stats["connected_devices"].add(ip)
    return jsonify({"ip": ip, "device": device})

@app.route("/api/encrypt_live", methods=["POST"])
def encrypt_live():
    data = request.json
    message = data.get("message", "Hello")
    algo = data.get("algo", "aes")
    device = data.get("device", "unknown")[:60]

    if algo == "aes":
        key = load_key()
        ct, nonce, tag, enc_ms = encrypt(key, message)
        dec, dec_ms = decrypt(key, ct, nonce, tag)
        algo_name = "AES-256-GCM"
    else:
        key = load_chacha_key()
        ct, nonce, tag, enc_ms = chacha_encrypt(key, message)
        dec, dec_ms = chacha_decrypt(key, ct, nonce, tag)
        algo_name = "ChaCha20-Poly1305"

    stats["total_msgs"] += 1
    stats["connected_devices"].add(request.remote_addr)

    entry = {
        "time": time.strftime("%H:%M:%S"),
        "source": request.remote_addr,
        "device": device,
        "algo": algo_name,
        "msg": message,
        "ct": ct.hex(),
        "original": message,
        "enc_ms": round(enc_ms, 4),
        "dec_ms": round(dec_ms, 4)
    }
    live_events.insert(0, entry)
    if len(live_events) > 50:
        live_events.pop()

    return jsonify({
        "original": message,
        "algorithm": algo_name,
        "ciphertext": ct.hex()[:48] + "...",
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "enc_ms": round(enc_ms, 4),
        "dec_ms": round(dec_ms, 4),
        "decrypted": dec,
        "integrity": "verified"
    })

@app.route("/api/live_log")
def live_log():
    return jsonify(live_events[:20])

@app.route("/api/qrcode")
def qrcode_img():
    try:
        import qrcode, io
        ip = get_local_ip()
        url = f"http://{ip}:5000/mobile"
        qr = qrcode.make(url)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        buf.seek(0)
        from flask import send_file
        return send_file(buf, mimetype="image/png")
    except:
        from flask import Response
        return Response("QR library not installed", mimetype="text/plain")

if __name__ == "__main__":
    ip = get_local_ip()
    print(f"\n[OK] Dashboard  → http://localhost:5000")
    print(f"[OK] Mobile URL → http://{ip}:5000/mobile")
    print(f"[OK] Share this URL with your phone (must be on same WiFi)\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
