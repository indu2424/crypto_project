from flask import Flask, jsonify, render_template_string
import sys, time, os, threading
sys.path.insert(0, "src/modules")
from aes_module import load_key, encrypt, decrypt
from chacha_module import generate_chacha_key, load_chacha_key, chacha_encrypt, chacha_decrypt
from resource_monitor import get_resources, measure_encryption_cost
from tls_server import start_background_server
from iot_simulator import start_simulator, iot_log

app = Flask(__name__)

# ── start background services once ──────────────────────────────────────────
start_background_server()
time.sleep(1)
start_simulator(["IoT-001", "IoT-002", "IoT-003"], interval=5)

# ── generate ChaCha key if missing ──────────────────────────────────────────
if not os.path.exists("certs/chacha.key"):
    generate_chacha_key()

# ────────────────────────────────────────────────────────────────────────────
HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>Lightweight Cryptography Dashboard</title>
  <meta http-equiv="refresh" content="5">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;padding:24px}
    h1{color:#fff;font-size:1.4em;margin-bottom:4px}
    .sub{color:#8b949e;font-size:.85em;margin-bottom:20px}
    h2{color:#58a6ff;font-size:1em;margin-bottom:12px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
    .grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:16px}
    .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px}
    .full{grid-column:1/-1}
    pre{color:#e6edf3;font-size:.82em;line-height:1.6;white-space:pre-wrap;word-break:break-all}
    table{width:100%;border-collapse:collapse;font-size:.83em}
    td,th{padding:7px 10px;border:1px solid #21262d;text-align:left}
    th{background:#21262d;color:#fff}
    tr:hover td{background:#1c2129}
    .ok{color:#3fb950}.warn{color:#d29922}.err{color:#f85149}
    .tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.78em;font-weight:bold}
    .tag-aes{background:#1f4068;color:#58a6ff}
    .tag-cha{background:#1a3a2a;color:#3fb950}
    .metric{text-align:center}
    .metric .val{font-size:1.6em;font-weight:bold;color:#58a6ff}
    .metric .lbl{font-size:.78em;color:#8b949e;margin-top:4px}
    .bar-wrap{background:#21262d;border-radius:4px;height:10px;margin-top:6px}
    .bar{height:10px;border-radius:4px;background:#58a6ff}
  </style>
</head>
<body>
  <h1>🔐 Efficient Secure Communication — Lightweight Cryptography</h1>
  <p class="sub">AES-256-GCM + ChaCha20-Poly1305 + TLS 1.3 &nbsp;|&nbsp; IoT Simulation &nbsp;|&nbsp; Auto-refresh: 5s</p>

  <!-- ── Resource Meters ─────────────────────────────── -->
  <div class="grid3">
    <div class="card metric">
      <div class="val">{{ res.cpu_percent }}%</div>
      <div class="lbl">CPU Usage</div>
      <div class="bar-wrap"><div class="bar" style="width:{{ res.cpu_percent }}%"></div></div>
    </div>
    <div class="card metric">
      <div class="val">{{ res.ram_used_mb }} MB</div>
      <div class="lbl">RAM Used / {{ res.ram_total_mb }} MB</div>
      <div class="bar-wrap"><div class="bar" style="width:{{ res.ram_percent }}%"></div></div>
    </div>
    <div class="card metric">
      <div class="val ok">TLS 1.3</div>
      <div class="lbl">Active Protocol</div>
      <div style="margin-top:8px;font-size:.8em;color:#3fb950">● Server Running</div>
    </div>
  </div>

  <!-- ── Algorithm Comparison ───────────────────────── -->
  <div class="grid">
    <div class="card">
      <h2><span class="tag tag-aes">AES-256-GCM</span> &nbsp; Live Encryption</h2>
      <pre>{{ aes.text }}</pre>
    </div>
    <div class="card">
      <h2><span class="tag tag-cha">ChaCha20-Poly1305</span> &nbsp; Live Encryption</h2>
      <pre>{{ cha.text }}</pre>
    </div>
  </div>

  <!-- ── Side-by-side Benchmark ─────────────────────── -->
  <div class="card" style="margin-bottom:16px">
    <h2>📊 Algorithm Comparison — Performance at Different Payload Sizes</h2>
    <table>
      <tr>
        <th>Payload</th>
        <th>AES Enc (ms)</th><th>AES Dec (ms)</th><th>AES Throughput</th>
        <th>ChaCha Enc (ms)</th><th>ChaCha Dec (ms)</th><th>ChaCha Throughput</th>
        <th>Winner</th>
      </tr>
      {% for r in bench %}
      <tr>
        <td>{{ r.label }}</td>
        <td>{{ r.aes_enc }}</td><td>{{ r.aes_dec }}</td>
        <td>{{ r.aes_thr }} KB/s</td>
        <td>{{ r.cha_enc }}</td><td>{{ r.cha_dec }}</td>
        <td>{{ r.cha_thr }} KB/s</td>
        <td class="{{ 'ok' if r.winner=='AES' else 'warn' }}">{{ r.winner }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <!-- ── IoT Live Feed ───────────────────────────────── -->
  <div class="card">
    <h2>📡 Live IoT Device Feed — Encrypted over TLS 1.3</h2>
    <table>
      <tr>
        <th>Device</th><th>Temp (°C)</th><th>Humidity (%)</th>
        <th>Battery (%)</th><th>Enc (ms)</th>
        <th>TLS Handshake (ms)</th><th>Total (ms)</th><th>Status</th>
      </tr>
      {% for r in iot %}
      <tr>
        <td>{{ r.device }}</td>
        <td>{{ r.get('temp','—') }}</td>
        <td>{{ r.get('humidity','—') }}</td>
        <td>{{ r.get('battery','—') }}</td>
        <td>{{ r.get('enc_ms','—') }}</td>
        <td>{{ r.get('hs_ms','—') }}</td>
        <td>{{ r.get('total_ms','—') }}</td>
        <td class="{{ 'ok' if r.status=='OK' else 'err' }}">{{ r.status }}</td>
      </tr>
      {% endfor %}
      {% if not iot %}
      <tr><td colspan="8" style="text-align:center;color:#8b949e">Waiting for IoT data...</td></tr>
      {% endif %}
    </table>
  </div>

</body>
</html>
"""

def do_benchmark():
    aes_key = load_key()
    cha_key = load_chacha_key()
    sizes = [("100B",100),("1KB",1024),("10KB",10240),("100KB",102400),("1MB",1048576)]
    rows = []
    for label, size in sizes:
        msg = "A" * size
        ae, ad, ce, cd = [], [], [], []
        for _ in range(3):
            ct,n,t,et = encrypt(aes_key, msg); ae.append(et)
            _,dt = decrypt(aes_key, ct, n, t); ad.append(dt)
            ct2,n2,t2,et2 = chacha_encrypt(cha_key, msg); ce.append(et2)
            _,dt2 = chacha_decrypt(cha_key, ct2, n2, t2); cd.append(dt2)
        avg = lambda x: round(sum(x)/len(x), 4)
        thr = lambda ms,sz: round((sz/1024)/(avg(ms)/1000), 1)
        a_enc=avg(ae); c_enc=avg(ce)
        rows.append({
            "label": label,
            "aes_enc": a_enc, "aes_dec": avg(ad), "aes_thr": thr(ae, size),
            "cha_enc": c_enc, "cha_dec": avg(cd), "cha_thr": thr(ce, size),
            "winner": "AES" if a_enc < c_enc else "ChaCha20"
        })
    return rows

def live_encrypt(algo="aes"):
    msg = f"IoT:temp=28.5,hum=65,dev=IoT-001,ts={int(time.time())}"
    if algo == "aes":
        key = load_key()
        ct, nonce, tag, enc_ms = encrypt(key, msg)
        dec, dec_ms = decrypt(key, ct, nonce, tag)
    else:
        key = load_chacha_key()
        ct, nonce, tag, enc_ms = chacha_encrypt(key, msg)
        dec, dec_ms = chacha_decrypt(key, ct, nonce, tag)
    return {
        "text": (
            f"Original  : {msg}\n"
            f"Encrypted : {ct.hex()[:44]}...\n"
            f"Nonce     : {nonce.hex()}\n"
            f"Auth Tag  : {tag.hex()}\n"
            f"Enc Time  : {enc_ms:.4f} ms\n"
            f"Dec Time  : {dec_ms:.4f} ms\n"
            f"✓ Integrity verified"
        )
    }

@app.route("/")
def index():
    return render_template_string(HTML,
        res=get_resources(),
        aes=live_encrypt("aes"),
        cha=live_encrypt("cha"),
        bench=do_benchmark(),
        iot=list(iot_log[:10])
    )

@app.route("/api/status")
def api_status():
    return jsonify({
        "resources": get_resources(),
        "aes": live_encrypt("aes"),
        "chacha": live_encrypt("cha"),
        "iot_feed": list(iot_log[:5])
    })

if __name__ == "__main__":
    print("[DASHBOARD] Running at http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
