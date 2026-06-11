import psutil

def select_algorithm(payload_size_bytes, override=None):
    """
    Decision rules (from literature review gaps):
    - Khan 2025: high latency in TLS → use ChaCha20 for small payloads
    - Lakshmanan 2024: energy cost → ChaCha20 cheaper on constrained devices
    - Sahu 2024: AES overhead → AES wins for large payloads (hardware acceleration)
    """
    if override and override in ["aes","chacha"]: 
        reason = f"Manual override: {override.upper()}"
        return override, reason

    cpu = psutil.cpu_percent(interval=0.05)

    if payload_size_bytes < 1024:
        algo, reason = "chacha", f"Payload {payload_size_bytes}B < 1KB → ChaCha20 faster for small data"
    elif payload_size_bytes < 10240:
        if cpu > 70:
            algo, reason = "chacha", f"CPU {cpu}% high + payload {payload_size_bytes//1024}KB → ChaCha20 (lower overhead)"
        else:
            algo, reason = "aes", f"Payload {payload_size_bytes//1024}KB mid-range + CPU {cpu}% normal → AES-256"
    else:
        algo, reason = "aes", f"Payload {payload_size_bytes//1024}KB large → AES-256 (hardware acceleration wins)"

    return algo, reason

DEVICE_PROFILES = {
    "Tier1-Sensor":   {"cpu_limit": 20,  "ram_mb": 64,   "algo": "chacha", "desc": "Ultra-low power sensor"},
    "Tier2-Node":     {"cpu_limit": 40,  "ram_mb": 128,  "algo": "chacha", "desc": "IoT edge node"},
    "Tier3-RPi":      {"cpu_limit": 60,  "ram_mb": 512,  "algo": "aes",    "desc": "Raspberry Pi class"},
    "Tier4-Gateway":  {"cpu_limit": 80,  "ram_mb": 1024, "algo": "aes",    "desc": "IoT gateway"},
    "Tier5-Server":   {"cpu_limit": 100, "ram_mb": 4096, "algo": "aes",    "desc": "Cloud/edge server"},
}
