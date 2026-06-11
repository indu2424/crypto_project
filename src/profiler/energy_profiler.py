import psutil, time, sys
sys.path.insert(0,"src/modules")
from aes_module import load_key, encrypt, decrypt
from chacha_module import load_chacha_key, chacha_encrypt, chacha_decrypt

# Energy estimation constants (from Lakshmanan 2024 paper)
CPU_POWER_W = 0.5      # typical IoT SoC at full load (Watts)
IDLE_POWER_W = 0.05    # idle power

def estimate_energy_uj(cpu_percent, duration_ms):
    """Estimate energy in microjoules"""
    active_power = IDLE_POWER_W + (CPU_POWER_W * cpu_percent / 100)
    return round(active_power * (duration_ms / 1000) * 1_000_000, 4)

def profile_encryption(payload_size, runs=5):
    aes_key = load_key()
    cha_key = load_chacha_key()
    msg = "A" * payload_size

    results = {"aes": [], "chacha": []}

    for _ in range(runs):
        # AES
        cpu_before = psutil.cpu_percent(interval=0.02)
        ram_before = psutil.virtual_memory().used / (1024*1024)
        ct, n, t, enc_ms = encrypt(aes_key, msg)
        _, dec_ms = decrypt(aes_key, ct, n, t)
        cpu_after = psutil.cpu_percent(interval=0.02)
        ram_after = psutil.virtual_memory().used / (1024*1024)
        results["aes"].append({
            "enc_ms": enc_ms, "dec_ms": dec_ms,
            "cpu": (cpu_before+cpu_after)/2,
            "ram_delta": ram_after-ram_before,
            "energy_uj": estimate_energy_uj((cpu_before+cpu_after)/2, enc_ms+dec_ms)
        })

        # ChaCha20
        cpu_before = psutil.cpu_percent(interval=0.02)
        ram_before = psutil.virtual_memory().used / (1024*1024)
        ct, n, t, enc_ms = chacha_encrypt(cha_key, msg)
        _, dec_ms = chacha_decrypt(cha_key, ct, n, t)
        cpu_after = psutil.cpu_percent(interval=0.02)
        ram_after = psutil.virtual_memory().used / (1024*1024)
        results["chacha"].append({
            "enc_ms": enc_ms, "dec_ms": dec_ms,
            "cpu": (cpu_before+cpu_after)/2,
            "ram_delta": ram_after-ram_before,
            "energy_uj": estimate_energy_uj((cpu_before+cpu_after)/2, enc_ms+dec_ms)
        })

    def avg(lst, key): return round(sum(x[key] for x in lst)/len(lst), 4)

    return {
        "payload_bytes": payload_size,
        "payload_label": f"{payload_size}B" if payload_size<1024 else f"{payload_size//1024}KB",
        "aes": {k: avg(results["aes"],k) for k in ["enc_ms","dec_ms","cpu","ram_delta","energy_uj"]},
        "chacha": {k: avg(results["chacha"],k) for k in ["enc_ms","dec_ms","cpu","ram_delta","energy_uj"]},
    }

PAYLOAD_SIZES = [100, 512, 1024, 4096, 10240, 102400, 1048576]

def run_full_profile():
    return [profile_encryption(s) for s in PAYLOAD_SIZES]
