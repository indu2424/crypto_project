from flask import Flask, request, jsonify, render_template_string
import time, os, psutil

app = Flask(__name__)

# ── Key Management ──────────────────────────────────────
def get_aes_key():
    from Crypto.Cipher import AES
    key = os.environ.get("AES_KEY")
    if key:
        return bytes.fromhex(key)
    return os.urandom(32)

def get_chacha_key():
    from Crypto.Cipher import ChaCha20_Poly1305
    key = os.environ.get("CHACHA_KEY")
    if key:
        return bytes.fromhex(key)
    return os.urandom(32)

AES_KEY    = get_aes_key()
CHACHA_KEY = get_chacha_key()

# ── Encryption Functions ────────────────────────────────
def do_aes_encrypt(message):
    from Crypto.Cipher import AES as _AES
    start = time.perf_counter()
    cipher = _AES.new(AES_KEY, _AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(message.encode())
    enc_ms = (time.perf_counter() - start) * 1000
    start2 = time.perf_counter()
    cipher2 = _AES.new(AES_KEY, _AES.MODE_GCM, nonce=cipher.nonce)
    dec = cipher2.decrypt_and_verify(ct, tag).decode()
    dec_ms = (time.perf_counter() - start2) * 1000
    return ct, cipher.nonce, tag, enc_ms, dec_ms, dec

def do_chacha_encrypt(message):
    from Crypto.Cipher import ChaCha20_Poly1305
    start = time.perf_counter()
    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY)
    ct, tag = cipher.encrypt_and_digest(message.encode())
    enc_ms = (time.perf_counter() - start) * 1000
    start2 = time.perf_counter()
    cipher2 = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=cipher.nonce)
    dec = cipher2.decrypt_and_verify(ct, tag).decode()
    dec_ms = (time.perf_counter() - start2) * 1000
    return ct, cipher.nonce, tag, enc_ms, dec_ms, dec

# ── Live Event Log ──────────────────────────────────────
live_events = []
stats = {"total": 0, "devices": set()}

# ── Mobile Page ─────────────────────────────────────────
MOBILE_HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Live Crypto</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:16px}
    h1{color:#fff;font-size:1.1em;margin-bottom:4px}
    .sub{color:#8b949e;font-size:.8em;margin-bottom:14px}
    .card{background:#161b22;border:1px solid #30363d;border-radius:8px;
          padding:14px;margin-bottom:12px}
    h2{color:#58a6ff;font-size:.9em;margin-bottom:10px}
    .row{display:flex;justify-content:space-between;align-items:flex-start;
         padding:5px 0;border-bottom:1px solid #21262d;font-size:.82em;gap:8px}
    .lbl{color:#8b949e;white-space:nowrap;min-width:80px}
    .val{color:#e6edf3;word-break:break-all;text-align:right}
    .ok{color:#3fb950}.err{color:#f85149}
    button{width:100%;padding:13px;margin-top:8px;border:none;border-radius:6px;
           font-size:.95em;font-weight:bold;cursor:pointer;transition:.2s}
    .btn-aes{background:#1f4068;color:#58a6ff}
    .btn-cha{background:#1a3a2a;color:#3fb950}
    .btn-aes:active,.btn-cha:active{opacity:.7}
    textarea{width:100%;padding:10px;background:#21262d;border:1px solid #30363d;
             border-radius:6px;color:#e6edf3;font-size:.9em;margin-top:6px;
             resize:vertical;min-height:70px}
    .spinner{display:none;text-align:center;color:#58a6ff;padding:10px}
    .log-entry{padding:6px;border-bottom:1px solid #21262d;font-size:.78em;
               line-height:1.5}
    .badge{display:inline-block;padding:2px 6px;border-radius:4px;
           font-size:.72em;font-weight:bold;margin-right:4px}
    .b-aes{background:#1f4068;color:#58a6ff}
    .b-cha{background:#1a3a2a;color:#3fb950}
    #log{max-height:250px;overflow-y:auto}
    .meter{background:#21262d;border-radius:4px;height:8px;margin-top:4px}
    .meter-fill{height:8px;border-radius:4px;background:#58a6ff;transition:.5s}
  </style>
</head>
<body>
  <h1>🔐 Live Cryptography</h1>
  <p class="sub">Real encryption running on cloud server</p>

  <!-- Status -->
  <div class="card">
    <h2>📡 Connection Status</h2>
    <div class="row">
      <span class="lbl">Server</span>
      <span class="ok">● Online (Render Cloud)</span>
    </div>
    <div class="row">
      <span class="lbl">Protocol</span>
      <span class="val">HTTPS + AES-256-GCM</span>
    </div>
    <div class="row">
      <span class="lbl">Your IP</span>
      <span class="val" id="myip">detecting...</span>
    </div>
    <div class="row">
      <span class="lbl">Total Sent</span>
      <span class="val" id="msg_count">0</span>
    </div>
  </div>

  <!-- Send Message -->
  <div class="card">
    <h2>✉️ Encrypt Your Own Message</h2>
    <textarea id="custom_msg"
      placeholder="Type anything — your name, a sentence, anything..."></textarea>
    <button class="btn-aes" onclick="sendMsg('aes')">
      🔒 Encrypt with AES-256-GCM
    </button>
    <button class="btn-cha" onclick="sendMsg('cha')" style="margin-top:6px">
      🔒 Encrypt with ChaCha20-Poly1305
    </button>
    <div class="spinner" id="spinner">⏳ Encrypting...</div>
  </div>

  <!-- Result -->
  <div class="card" id="result_card" style="display:none">
    <h2>⚡ Encryption Result</h2>
    <div class="row"><span class="lbl">Original</span>
      <span class="val ok" id="r_orig"></span></div>
    <div class="row"><span class="lbl">Algorithm</span>
      <span class="val" id="r_algo"></span></div>
    <div class="row"><span class="lbl">Encrypted</span>
      <span class="val" id="r_enc"></span></div>
    <div class="row"><span class="lbl">Nonce</span>
      <span class="val" id="r_nonce"></span></div>
    <div class="row"><span class="lbl">Auth Tag</span>
      <span class="val" id="r_tag"></span></div>
    <div class="row"><span class="lbl">Enc Time</span>
      <span class="val ok" id="r_enc_ms"></span></div>
    <div class="row"><span class="lbl">Dec Time</span>
      <span class="val ok" id="r_dec_ms"></span></div>
    <div class="row"><span class="lbl">Decrypted</span>
      <span class="val ok" id="r_dec"></span></div>
    <div class="row"><span class="lbl">Integrity</span>
      <span class="ok">✓ Verified — Not Tampered</span></div>
  </div>

  <!-- Benchmark -->
  <div class="card">
    <h2>📊 Quick Benchmark</h2>
    <button class="btn-aes" onclick="runBench()">▶ Run Live Benchmark</button>
    <div id="bench_result" style="margin-top:10px;font-size:.82em"></div>
  </div>

  <!-- Log -->
  <div class="card">
    <h2>📋 My Encryption History</h2>
    <div id="log"><p style="color:#8b949e;font-size:.8em">
      Nothing yet — encrypt something above</p></div>
  </div>

<script>
  let count = 0;
  const log = [];

  fetch('/api/myinfo').then(r=>r.json()).then(d=>{
    document.getElementById('myip').textContent = d.ip;
  });

  function sendMsg(algo) {
    const msg = document.getElementById('custom_msg').value.trim() ||
      'Hello from my phone at ' + new Date().toLocaleTimeString();
    document.getElementById('spinner').style.display = 'block';
    document.getElementById('result_card').style.display = 'none';

    fetch('/api/encrypt_live', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        message: msg, algo: algo,
        device: navigator.userAgent.substring(0,80)
      })
    })
    .then(r => r.json())
    .then(d => {
      document.getElementById('spinner').style.display = 'none';
      document.getElementById('result_card').style.display = 'block';
      document.getElementById('r_orig').textContent   = d.original;
      document.getElementById('r_algo').textContent   = d.algorithm;
      document.getElementById('r_enc').textContent    = d.ciphertext;
      document.getElementById('r_nonce').textContent  = d.nonce;
      document.getElementById('r_tag').textContent    = d.tag;
      document.getElementById('r_enc_ms').textContent = d.enc_ms + ' ms';
      document.getElementById('r_dec_ms').textContent = d.dec_ms + ' ms';
      document.getElementById('r_dec').textContent    = d.decrypted;
      count++;
      document.getElementById('msg_count').textContent = count;

      log.unshift({
        time: new Date().toLocaleTimeString(),
        algo: d.algorithm, msg: msg.substring(0,30),
        enc_ms: d.enc_ms
      });
      renderLog();
    })
    .catch(()=>{
      document.getElementById('spinner').style.display='none';
      alert('Error — check connection');
    });
  }

  function renderLog() {
    document.getElementById('log').innerHTML = log.map(e =>
      '<div class="log-entry">' +
      '<span class="badge ' + (e.algo.includes('AES')?'b-aes':'b-cha') + '">' +
      e.algo + '</span>' +
      e.time + ' — "' + e.msg + '..." → ' + e.enc_ms + 'ms' +
      '</div>'
    ).join('') || '<p style="color:#8b949e;font-size:.8em">Nothing yet</p>';
  }

  function runBench() {
    document.getElementById('bench_result').innerHTML =
      '<span style="color:#58a6ff">Running benchmark...</span>';
    fetch('/api/benchmark').then(r=>r.json()).then(rows => {
      document.getElementById('bench_result').innerHTML =
        '<table style="width:100%;border-collapse:collapse">' +
        '<tr style="color:#fff">' +
        '<th style="padding:4px;border:1px solid #30363d">Size</th>' +
        '<th style="padding:4px;border:1px solid #30363d">AES (ms)</th>' +
        '<th style="padding:4px;border:1px solid #30363d">ChaCha (ms)</th>' +
        '<th style="padding:4px;border:1px solid #30363d">Winner</th></tr>' +
        rows.map(r =>
          '<tr><td style="padding:4px;border:1px solid #30363d">' + r.label + '</td>' +
          '<td style="padding:4px;border:1px solid #30363d;color:#58a6ff">' + r.aes_enc + '</td>' +
          '<td style="padding:4px;border:1px solid #30363d;color:#3fb950">' + r.cha_enc + '</td>' +
          '<td style="padding:4px;border:1px solid #30363d;color:#d29922">' + r.winner + '</td></tr>'
        ).join('') + '</table>';
    });
  }
</script>
</body>
</html>
"""

# ── Dashboard for laptop ────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="refresh" content="5">
  <title>Crypto Dashboard</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:24px}
    h1{color:#fff;font-size:1.3em;margin-bottom:4px}
    .sub{color:#8b949e;font-size:.85em;margin-bottom:20px}
    h2{color:#58a6ff;font-size:.95em;margin-bottom:12px}
    .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:16px}
    .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px}
    table{width:100%;border-collapse:collapse;font-size:.82em}
    td,th{padding:7px 10px;border:1px solid #21262d}
    th{background:#21262d;color:#fff}
    .ok{color:#3fb950}.err{color:#f85149}
    .big{font-size:1.8em;font-weight:bold;color:#58a6ff}
    .lbl{font-size:.78em;color:#8b949e;margin-top:4px}
    .badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.75em;font-weight:bold}
    .b-aes{background:#1f4068;color:#58a6ff}
    .b-cha{background:#1a3a2a;color:#3fb950}
    .b-dev{background:#2d1f3d;color:#a78bfa}
    .url{background:#161b22;border:1px solid #3fb950;border-radius:6px;
         padding:12px;color:#3fb950;font-size:1em;text-align:center;
         margin-bottom:16px;word-break:break-all}
  </style>
</head>
<body>
  <h1>🔐 Efficient Secure Communication — Live Monitor</h1>
  <p class="sub">Cloud-hosted | AES-256-GCM + ChaCha20-Poly1305 + TLS 1.3</p>

  <div class="url">📱 Mobile URL: {{ mobile_url }} &nbsp;|&nbsp; Share this link with your phone</div>

  <div class="grid">
    <div class="card" style="text-align:center">
      <div class="big">{{ stats.total }}</div>
      <div class="lbl">Messages Encrypted</div>
    </div>
    <div class="card" style="text-align:center">
      <div class="big">{{ stats.devices }}</div>
      <div class="lbl">Unique Devices</div>
    </div>
    <div class="card" style="text-align:center">
      <div class="big ok">Live</div>
      <div class="lbl">Server Status — Render Cloud</div>
    </div>
  </div>

  <div class="card" style="margin-bottom:16px">
    <h2>📋 Live Encrypted Messages from All Devices</h2>
    <table>
      <tr>
        <th>Time</th><th>Device IP</th><th>Algorithm</th>
        <th>Original Message</th><th>Ciphertext Preview</th>
        <th>Enc (ms)</th><th>Dec (ms)</th><th>Integrity</th>
      </tr>
      {% for e in events %}
      <tr>
        <td>{{ e.time }}</td>
        <td><span class="badge b-dev">{{ e.ip }}</span></td>
        <td><span class="badge {{ 'b-aes' if 'AES' in e.algo else 'b-cha' }}">
            {{ e.algo }}</span></td>
        <td class="ok">{{ e.msg[:45] }}</td>
        <td style="font-size:.75em">{{ e.ct[:32] }}...</td>
        <td>{{ e.enc_ms }}</td>
        <td>{{ e.dec_ms }}</td>
        <td class="ok">✓ Verified</td>
      </tr>
      {% endfor %}
      {% if not events %}
      <tr><td colspan="8" style="text-align:center;color:#8b949e">
        Open mobile URL on your phone and send a message</td></tr>
      {% endif %}
    </table>
  </div>
</body>
</html>
"""

# ── Flask Routes ────────────────────────────────────────
@app.route("/")
def dashboard():
    host = request.host_url.rstrip("/")
    return render_template_string(DASHBOARD_HTML,
        mobile_url=f"{host}/mobile",
        stats={"total": stats["total"], "devices": len(stats["devices"])},
        events=live_events[:30])

@app.route("/mobile")
def mobile():
    return render_template_string(MOBILE_HTML)

@app.route("/api/myinfo")
def myinfo():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    stats["devices"].add(ip)
    return jsonify({"ip": ip})

@app.route("/api/encrypt_live", methods=["POST"])
def encrypt_live():
    data    = request.json or {}
    message = data.get("message", "Hello")[:500]
    algo    = data.get("algo", "aes")
    device  = data.get("device", "unknown")[:80]
    ip      = request.headers.get("X-Forwarded-For",
                                   request.remote_addr).split(",")[0].strip()

    if algo == "aes":
        ct, nonce, tag, enc_ms, dec_ms, dec = do_aes_encrypt(message)
        algo_name = "AES-256-GCM"
    else:
        ct, nonce, tag, enc_ms, dec_ms, dec = do_chacha_encrypt(message)
        algo_name = "ChaCha20-Poly1305"

    stats["total"] += 1
    stats["devices"].add(ip)

    live_events.insert(0, {
        "time":    time.strftime("%H:%M:%S"),
        "ip":      ip,
        "device":  device,
        "algo":    algo_name,
        "msg":     message,
        "ct":      ct.hex(),
        "enc_ms":  round(enc_ms, 4),
        "dec_ms":  round(dec_ms, 4)
    })
    if len(live_events) > 100:
        live_events.pop()

    return jsonify({
        "original":   message,
        "algorithm":  algo_name,
        "ciphertext": ct.hex()[:48] + "...",
        "nonce":      nonce.hex(),
        "tag":        tag.hex(),
        "enc_ms":     round(enc_ms, 4),
        "dec_ms":     round(dec_ms, 4),
        "decrypted":  dec,
        "integrity":  "verified"
    })

@app.route("/api/benchmark")
def benchmark():
    sizes = [("100B",100),("1KB",1024),("10KB",10240),("100KB",102400)]
    rows  = []
    for label, size in sizes:
        msg = "A" * size
        ae, ce = [], []
        for _ in range(3):
            _,_,_,et,_,_ = do_aes_encrypt(msg); ae.append(et)
            _,_,_,et,_,_ = do_chacha_encrypt(msg); ce.append(et)
        a = round(sum(ae)/3, 4)
        c = round(sum(ce)/3, 4)
        rows.append({"label": label, "aes_enc": a,
                     "cha_enc": c, "winner": "AES" if a < c else "ChaCha20"})
    return jsonify(rows)

@app.route("/api/live_log")
def live_log():
    return jsonify(live_events[:20])

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
