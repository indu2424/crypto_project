import psutil
import time
import os

def get_resources():
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "ram_used_mb": round(psutil.virtual_memory().used / (1024 * 1024), 2),
        "ram_percent": psutil.virtual_memory().percent,
        "ram_total_mb": round(psutil.virtual_memory().total / (1024 * 1024), 2)
    }

def measure_encryption_cost(fn, *args):
    """Measure CPU + RAM before and during an encryption call."""
    cpu_before = psutil.cpu_percent(interval=0.05)
    ram_before = psutil.virtual_memory().used / (1024 * 1024)

    result = fn(*args)

    cpu_after = psutil.cpu_percent(interval=0.05)
    ram_after = psutil.virtual_memory().used / (1024 * 1024)

    return result, {
        "cpu_delta": round(cpu_after - cpu_before, 2),
        "ram_delta_mb": round(ram_after - ram_before, 4),
        "cpu_after": round(cpu_after, 2),
        "ram_after_mb": round(ram_after, 2)
    }
