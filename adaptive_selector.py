import psutil
import time

# Device tier definitions (simulating IoT tiers)
DEVICE_TIERS = {
    "sensor":       {"max_cpu": 20,  "max_ram_mb": 64,   "label": "Tier 1 - Sensor Node"},
    "microcontroller": {"max_cpu": 40, "max_ram_mb": 128, "label": "Tier 2 - Microcontroller"},
    "edge_lite":    {"max_cpu": 60,  "max_ram_mb": 256,  "label": "Tier 3 - Edge Lite"},
    "edge_gateway": {"max_cpu": 80,  "max_ram_mb": 512,  "label": "Tier 4 - Edge Gateway"},
    "gateway":      {"max_cpu": 100, "max_ram_mb": 2048, "label": "Tier 5 - Full Gateway"},
}

def select_algorithm(payload_size_bytes: int, device_tier: str = "edge_lite") -> dict:
    """
    Rule-based adaptive selector (mimics ML decision logic).
    Rules derived from benchmark data:
    - Small payload (<1KB) + high CPU → ChaCha20 (lower overhead)
    - Large payload or hardware AES support → AES-256-GCM
    """
    cpu_percent = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory()
    ram_used_mb = ram.used / (1024 * 1024)
    
    tier_config = DEVICE_TIERS.get(device_tier, DEVICE_TIERS["edge_lite"])
    
    # Decision logic
    reasons = []
    
    if payload_size_bytes < 1024 and cpu_percent > 60:
        algorithm = "ChaCha20-Poly1305"
        reasons.append(f"payload < 1KB ({payload_size_bytes}B)")
        reasons.append(f"CPU load high ({cpu_percent:.1f}%)")
    elif device_tier in ["sensor", "microcontroller"]:
        algorithm = "ChaCha20-Poly1305"
        reasons.append(f"constrained device tier ({tier_config['label']})")
        reasons.append("ChaCha20 has lower memory overhead")
    elif payload_size_bytes > 10240:
        algorithm = "AES-256-GCM"
        reasons.append(f"large payload ({payload_size_bytes/1024:.1f}KB)")
        reasons.append("AES-GCM faster for bulk data (hardware acceleration)")
    else:
        algorithm = "AES-256-GCM"
        reasons.append("default — balanced load")
        reasons.append(f"CPU: {cpu_percent:.1f}%, payload: {payload_size_bytes}B")
    
    # Security score (0-100)
    security_score = 95 if algorithm == "AES-256-GCM" else 93
    if cpu_percent > 80:
        security_score -= 5  # penalise overloaded device
    
    return {
        "selected_algorithm": algorithm,
        "reason": " → ".join(reasons),
        "cpu_percent": cpu_percent,
        "ram_used_mb": round(ram_used_mb, 1),
        "device_tier": tier_config["label"],
        "security_score": security_score,
        "payload_size": payload_size_bytes
    }
