import random, time, threading, sys
sys.path.insert(0,"src/modules")
from aes_module import load_key, encrypt, decrypt
from chacha_module import load_chacha_key, chacha_encrypt, chacha_decrypt
from adaptive_selector import DEVICE_PROFILES, select_algorithm

device_log = []
log_lock = threading.Lock()

def make_payload(device_name, tier):
    sizes = {"Tier1-Sensor":80,"Tier2-Node":512,"Tier3-RPi":2048,
             "Tier4-Gateway":8192,"Tier5-Server":51200}
    size = sizes.get(tier, 256)
    data = f"dev={device_name},temp={round(random.uniform(22,36),2)}," \
           f"hum={round(random.uniform(40,80),2)},bat={round(random.uniform(60,100),1)}," \
           f"ts={int(time.time())},pad={'X'*(size-80)}"
    return data[:size]

def simulate_device(device_name, tier):
    aes_key = load_key()
    cha_key = load_chacha_key()
    profile = DEVICE_PROFILES[tier]
    payload = make_payload(device_name, tier)
    algo, reason = select_algorithm(len(payload))

    if algo == "aes":
        ct, nonce, tag, enc_ms = encrypt(aes_key, payload)
        _, dec_ms = decrypt(aes_key, ct, nonce, tag)
    else:
        ct, nonce, tag, enc_ms = chacha_encrypt(cha_key, payload)
        _, dec_ms = chacha_decrypt(cha_key, ct, nonce, tag)

    cpu = random.uniform(5, profile["cpu_limit"])
    security_score = min(100, int(90 + (enc_ms < 1)*5 + (dec_ms < 1)*5))

    entry = {
        "device": device_name, "tier": tier,
        "desc": profile["desc"], "algo": "AES-256-GCM" if algo=="aes" else "ChaCha20-Poly1305",
        "reason": reason, "payload_bytes": len(payload),
        "enc_ms": round(enc_ms,4), "dec_ms": round(dec_ms,4),
        "cpu": round(cpu,1), "ram_mb": profile["ram_mb"],
        "ct_preview": ct.hex()[:24]+"...",
        "security_score": security_score,
        "time": time.strftime("%H:%M:%S"), "status": "OK"
    }
    with log_lock:
        device_log.insert(0, entry)
        if len(device_log) > 50: device_log.pop()

DEVICES = [
    ("Sensor-A1","Tier1-Sensor"),("Node-B2","Tier2-Node"),
    ("RPi-C3","Tier3-RPi"),("Gateway-D4","Tier4-Gateway"),("Server-E5","Tier5-Server")
]

def start_device_simulator(interval=3):
    def loop():
        while True:
            for dev, tier in DEVICES:
                threading.Thread(target=simulate_device,args=(dev,tier),daemon=True).start()
                time.sleep(0.4)
            time.sleep(interval)
    threading.Thread(target=loop, daemon=True).start()
