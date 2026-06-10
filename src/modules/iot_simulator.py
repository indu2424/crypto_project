import ssl
import socket
import time
import json
import random
import threading
import sys
sys.path.insert(0, "src/modules")
from aes_module import load_key, encrypt

HOST = "localhost"
PORT = 8443

# Shared log visible to dashboard
iot_log = []
log_lock = threading.Lock()

def generate_sensor_data(device_id):
    return {
        "device_id": device_id,
        "temperature": round(random.uniform(22.0, 35.0), 2),
        "humidity": round(random.uniform(40.0, 80.0), 2),
        "pressure": round(random.uniform(1000.0, 1020.0), 2),
        "battery": round(random.uniform(60.0, 100.0), 1),
        "timestamp": int(time.time())
    }

def send_iot_packet(device_id):
    key = load_key()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("certs/server.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    data = generate_sensor_data(device_id)
    message = json.dumps(data)

    try:
        start = time.perf_counter()
        with socket.create_connection((HOST, PORT), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as tls_sock:
                hs_ms = (time.perf_counter() - start) * 1000
                ct, nonce, tag, enc_ms = encrypt(key, message)
                tls_sock.sendall(nonce + tag + ct)
                tls_sock.recv(1024)
                total_ms = (time.perf_counter() - start) * 1000

                entry = {
                    "device": device_id,
                    "temp": data["temperature"],
                    "humidity": data["humidity"],
                    "battery": data["battery"],
                    "enc_ms": round(enc_ms, 4),
                    "hs_ms": round(hs_ms, 4),
                    "total_ms": round(total_ms, 4),
                    "status": "OK"
                }
                with log_lock:
                    iot_log.insert(0, entry)
                    if len(iot_log) > 20:
                        iot_log.pop()
    except Exception as e:
        with log_lock:
            iot_log.insert(0, {"device": device_id, "status": f"ERR: {e}"})

def start_simulator(devices=["IoT-001", "IoT-002", "IoT-003"], interval=4):
    """Continuously send data from multiple simulated IoT devices."""
    def loop():
        while True:
            for dev in devices:
                threading.Thread(target=send_iot_packet, args=(dev,), daemon=True).start()
                time.sleep(0.5)
            time.sleep(interval)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
