import time
import psutil
import math

# Simulated energy constants (based on ARM Cortex-M benchmarks from literature)
ENERGY_CONSTANTS = {
    "AES-256-GCM": {
        "cycles_per_byte": 12.4,
        "mw_active": 45.0,
        "ram_bytes": 512
    },
    "ChaCha20-Poly1305": {
        "cycles_per_byte": 8.2,
        "mw_active": 38.0,
        "ram_bytes": 320
    }
}

CPU_FREQ_MHZ = 80  # Simulated IoT CPU (e.g., ESP32)

def profile_encryption(algorithm: str, payload_size_bytes: int, enc_time_ms: float) -> dict:
    """Calculate energy cost for one encryption operation."""
    constants = ENERGY_CONSTANTS.get(algorithm, ENERGY_CONSTANTS["AES-256-GCM"])
    
    # CPU cycles
    cpu_cycles = int(constants["cycles_per_byte"] * payload_size_bytes)
    
    # Time in seconds
    time_s = enc_time_ms / 1000.0
    
    # Energy in mJ = Power(mW) × Time(s)
    energy_mj = constants["mw_active"] * time_s
    
    # Battery drain over 1000 messages (mAh estimate at 3.3V)
    # E = P×t, I = P/V
    current_ma = constants["mw_active"] / 3.3
    time_per_1000_h = (enc_time_ms * 1000) / (1000 * 3600 * 1000)
    battery_drain_mah = current_ma * time_per_1000_h
    
    return {
        "algorithm": algorithm,
        "payload_size_bytes": payload_size_bytes,
        "enc_time_ms": round(enc_time_ms, 4),
        "cpu_cycles": cpu_cycles,
        "energy_mj": round(energy_mj, 6),
        "ram_bytes": constants["ram_bytes"],
        "battery_drain_1000msg_mah": round(battery_drain_mah, 6),
        "mw_active": constants["mw_active"]
    }

def compare_algorithms(payload_size_bytes: int) -> dict:
    """Run both algorithms and return side-by-side comparison."""
    from crypto_utils import encrypt_aes_gcm, encrypt_chacha20
    
    data = b"X" * payload_size_bytes
    
    aes_result = encrypt_aes_gcm(data)
    chacha_result = encrypt_chacha20(data)
    
    aes_profile = profile_encryption("AES-256-GCM", payload_size_bytes, aes_result["time_ms"])
    chacha_profile = profile_encryption("ChaCha20-Poly1305", payload_size_bytes, chacha_result["time_ms"])
    
    return {
        "payload_size": payload_size_bytes,
        "aes": aes_profile,
        "chacha": chacha_profile,
        "winner_speed": "AES-256-GCM" if aes_result["time_ms"] < chacha_result["time_ms"] else "ChaCha20-Poly1305",
        "winner_energy": "AES-256-GCM" if aes_profile["energy_mj"] < chacha_profile["energy_mj"] else "ChaCha20-Poly1305"
    }
