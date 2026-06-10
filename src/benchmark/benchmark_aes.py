import os
import sys
import time
import csv
sys.path.insert(0, "src/modules")
from aes_module import generate_key, encrypt, decrypt

SIZES = [100, 1024, 10240, 102400, 1048576]
RUNS  = 10

def run():
    key = generate_key()
    results = []

    print("=== AES-256-GCM Benchmark ===\n")
    print(f"{'Size':<12} {'Enc Avg(ms)':<16} {'Dec Avg(ms)':<16} {'Throughput KB/s'}")
    print("-" * 60)

    for size in SIZES:
        plaintext = "A" * size
        enc_times = []
        dec_times = []

        for _ in range(RUNS):
            ct, nonce, tag, et = encrypt(key, plaintext)
            enc_times.append(et)
            _, dt = decrypt(key, ct, nonce, tag)
            dec_times.append(dt)

        avg_enc = sum(enc_times) / RUNS
        avg_dec = sum(dec_times) / RUNS
        throughput = (size / 1024) / (avg_enc / 1000)

        label = f"{size}B" if size < 1024 else f"{size//1024}KB" if size < 1048576 else "1MB"
        print(f"{label:<12} {avg_enc:<16.4f} {avg_dec:<16.4f} {throughput:.2f}")

        results.append({
            "size_label": label,
            "size_bytes": size,
            "avg_enc_ms": round(avg_enc, 4),
            "avg_dec_ms": round(avg_dec, 4),
            "throughput_kbps": round(throughput, 2)
        })

    with open("results/aes_benchmark.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print("\n[OK] Results saved to results/aes_benchmark.csv")

if __name__ == "__main__":
    run()
