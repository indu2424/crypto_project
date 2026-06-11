import os, time, json, secrets, csv, io
from flask import Flask, request, jsonify, send_file
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

app = Flask(__name__, static_folder='../frontend', static_url_path='')
app.config['SECRET_KEY'] = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*")

DEVICE_TIERS = {
    "sensor":          {"ram_kb": 64,   "algo": "ChaCha20-Poly1305", "score": 62},
    "microcontroller": {"ram_kb": 128,  "algo": "ChaCha20-Poly1305", "score": 71},
    "edge_lite":       {"ram_kb": 256,  "algo": "AES-256-GCM",       "score": 84},
    "edge_gateway":    {"ram_kb": 512,  "algo": "AES-256-GCM",       "score": 91},
    "gateway":         {"ram_kb": 2048, "algo": "AES-256-GCM",       "score": 97},
}

REASON_MAP = {
    "sensor":          "64 KB RAM — ChaCha20 is software-efficient, no AES hardware",
    "microcontroller": "128 KB RAM — ChaCha20 optimal for constrained MCU",
    "edge_lite":       "256 KB RAM — AES-NI acceleration available",
    "edge_gateway":    "512 KB RAM — full AES pipeline with hardware support",
    "gateway":         "2 MB RAM — maximum security, AES-256-GCM preferred",
}

benchmark_results = []

def estimate_energy(time_ms, algo):
    power_mw = 85 if algo == "AES" else 72
    return {
        "energy_mj": round((power_mw * time_ms) / 1000, 6),
        "power_mw": power_mw,
        "cpu_cycles": int(time_ms * 400000)
    }

def encrypt_aes(plaintext: bytes):
    key = AESGCM.generate_key(256)
    nonce = secrets.token_bytes(12)
    t0 = time.perf_counter()
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    elapsed = (time.perf_counter() - t0) * 1000
    return {
        "ciphertext": ct.hex(),
        "nonce": nonce.hex(),
        "tag": ct[-16:].hex(),
        "time_ms": round(elapsed, 4),
        "energy": estimate_energy(elapsed, "AES"),
        "key": key.hex()
    }

def encrypt_chacha(plaintext: bytes):
    key = ChaCha20Poly1305.generate_key()
    nonce = secrets.token_bytes(12)
    t0 = time.perf_counter()
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    elapsed = (time.perf_counter() - t0) * 1000
    return {
        "ciphertext": ct.hex(),
        "nonce": nonce.hex(),
        "tag": ct[-16:].hex(),
        "time_ms": round(elapsed, 4),
        "energy": estimate_energy(elapsed, "ChaCha20"),
        "key": key.hex()
    }

# ── Module 1: Adaptive Gateway ────────────────────────────────────────────────

@app.route('/api/adaptive/encrypt', methods=['POST'])
def adaptive_encrypt():
    data = request.json
    message = data.get('message', 'test').encode()
    tier = data.get('device_tier', 'edge_lite')
    config = DEVICE_TIERS.get(tier, DEVICE_TIERS['edge_lite'])
    algo = config['algo']
    if 'AES' in algo:
        result = encrypt_aes(message)
    else:
        result = encrypt_chacha(message)
    return jsonify({
        "selected_algorithm": algo,
        "reason": REASON_MAP.get(tier, ""),
        "security_score": config['score'],
        "time_ms": result['time_ms'],
        "energy": result['energy'],
        "ciphertext": result['ciphertext'],
        "nonce": result['nonce'],
        "tag": result['tag']
    })

@app.route('/api/adaptive/simulate', methods=['POST'])
def simulate_all():
    tiers_result = []
    message = b"IoT Sensor Payload: Temperature=24.5C Humidity=60%"
    for tier, config in DEVICE_TIERS.items():
        if 'AES' in config['algo']:
            r = encrypt_aes(message)
        else:
            r = encrypt_chacha(message)
        tiers_result.append({
            "tier": tier,
            "algorithm": config['algo'],
            "security_score": config['score'],
            "time_ms": r['time_ms'],
            "energy_mj": r['energy']['energy_mj']
        })
    socketio.emit('simulation_complete', {"tiers": tiers_result})
    return jsonify({"status": "ok", "tiers": tiers_result})

# ── Module 2: Encrypted Chat ──────────────────────────────────────────────────

@socketio.on('send_message')
def handle_message(data):
    message = data.get('message', '').encode()
    algo = data.get('algorithm', 'AES-256-GCM')
    sender = data.get('sender', 'Device')
    if 'AES' in algo:
        result = encrypt_aes(message)
    else:
        result = encrypt_chacha(message)
    emit('new_message', {
        "plaintext": data.get('message', ''),
        "algorithm": algo,
        "sender": sender,
        "timestamp": time.strftime("%H:%M:%S"),
        "time_ms": result['time_ms'],
        "energy_mj": result['energy']['energy_mj'],
        "nonce": result['nonce'],
        "tag": result['tag'],
        "ciphertext": result['ciphertext'][:64] + "..."
    }, broadcast=True)

# ── Module 3: Energy Profiler ─────────────────────────────────────────────────

@app.route('/api/profile/compare', methods=['POST'])
def compare():
    size = int(request.json.get('payload_size', 1024))
    payload = secrets.token_bytes(size)
    aes = encrypt_aes(payload)
    chacha = encrypt_chacha(payload)
    return jsonify({
        "payload_size": size,
        "aes": {
            "enc_time_ms": aes['time_ms'],
            "energy_mj": aes['energy']['energy_mj'],
            "cpu_cycles": aes['energy']['cpu_cycles']
        },
        "chacha": {
            "enc_time_ms": chacha['time_ms'],
            "energy_mj": chacha['energy']['energy_mj'],
            "cpu_cycles": chacha['energy']['cpu_cycles']
        },
        "winner_speed": "AES-256-GCM" if aes['time_ms'] < chacha['time_ms'] else "ChaCha20-Poly1305",
        "winner_energy": "AES-256-GCM" if aes['energy']['energy_mj'] < chacha['energy']['energy_mj'] else "ChaCha20-Poly1305"
    })

@app.route('/api/profile/benchmark', methods=['POST'])
def benchmark():
    global benchmark_results
    benchmark_results = []
    sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384]
    results = []
    for size in sizes:
        payload = secrets.token_bytes(size)
        aes = encrypt_aes(payload)
        chacha = encrypt_chacha(payload)
        row = {
            "payload_size": size,
            "aes": {"enc_time_ms": aes['time_ms'], "energy_mj": aes['energy']['energy_mj'], "cpu_cycles": aes['energy']['cpu_cycles']},
            "chacha": {"enc_time_ms": chacha['time_ms'], "energy_mj": chacha['energy']['energy_mj'], "cpu_cycles": chacha['energy']['cpu_cycles']}
        }
        results.append(row)
        benchmark_results.append(row)
    socketio.emit('benchmark_complete', {"results": results})
    return jsonify({"status": "ok", "results": results})

@app.route('/api/profile/export-csv')
def export_csv():
    global benchmark_results
    if not benchmark_results:
        sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384]
        benchmark_results = []
        for size in sizes:
            payload = secrets.token_bytes(size)
            aes = encrypt_aes(payload)
            chacha = encrypt_chacha(payload)
            benchmark_results.append({
                "payload_size": size,
                "aes": {"enc_time_ms": aes['time_ms'], "energy_mj": aes['energy']['energy_mj'], "cpu_cycles": aes['energy']['cpu_cycles']},
                "chacha": {"enc_time_ms": chacha['time_ms'], "energy_mj": chacha['energy']['energy_mj'], "cpu_cycles": chacha['energy']['cpu_cycles']}
            })
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["payload_size_bytes","aes_time_ms","aes_energy_mj","aes_cpu_cycles","chacha_time_ms","chacha_energy_mj","chacha_cpu_cycles"])
    for r in benchmark_results:
        writer.writerow([r['payload_size'], r['aes']['enc_time_ms'], r['aes']['energy_mj'], r['aes']['cpu_cycles'],
                         r['chacha']['enc_time_ms'], r['chacha']['energy_mj'], r['chacha']['cpu_cycles']])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv',
                     as_attachment=True, download_name='benchmark_results.csv')

@app.route('/')
def index():
    return send_file('../frontend/index.html')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
