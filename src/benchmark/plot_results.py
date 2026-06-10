import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use("Agg")

# --- Graph 1: AES Latency vs Payload Size ---
df = pd.read_csv("results/aes_benchmark.csv")

fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(df["size_label"], df["avg_enc_ms"], marker="o", label="Encryption", color="#185FA5", linewidth=2)
ax.plot(df["size_label"], df["avg_dec_ms"], marker="s", label="Decryption", color="#0F6E56", linewidth=2)
ax.set_title("AES-256-GCM: Encryption & Decryption Latency vs Payload Size", fontsize=13)
ax.set_xlabel("Payload Size")
ax.set_ylabel("Time (ms)")
ax.legend()
ax.grid(True, linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig("results/aes_latency_graph.png", dpi=150)
print("[OK] Saved results/aes_latency_graph.png")
plt.close()

# --- Graph 2: TLS Handshake Times ---
df2 = pd.read_csv("results/tls_benchmark.csv")

fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(df2["run"], df2["handshake_ms"], marker="o", color="#534AB7", linewidth=1.5, markersize=5)
ax.axhline(df2["handshake_ms"].mean(), color="#993C1D", linestyle="--", linewidth=1.5, label=f"Average: {df2['handshake_ms'].mean():.2f} ms")
ax.set_title("TLS 1.3 Handshake Latency over 20 Connections", fontsize=13)
ax.set_xlabel("Connection Number")
ax.set_ylabel("Handshake Time (ms)")
ax.legend()
ax.grid(True, linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig("results/tls_handshake_graph.png", dpi=150)
print("[OK] Saved results/tls_handshake_graph.png")
plt.close()

# --- Graph 3: Throughput Bar Chart ---
fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar(df["size_label"], df["throughput_kbps"], color="#185FA5", edgecolor="white", linewidth=0.5)
ax.set_title("AES-256-GCM Throughput by Payload Size", fontsize=13)
ax.set_xlabel("Payload Size")
ax.set_ylabel("Throughput (KB/s)")
for bar, val in zip(bars, df["throughput_kbps"]):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
            f"{val:.0f}", ha="center", va="bottom", fontsize=10)
ax.grid(True, axis="y", linestyle="--", alpha=0.5)
plt.tight_layout()
plt.savefig("results/throughput_graph.png", dpi=150)
print("[OK] Saved results/throughput_graph.png")
plt.close()

print("\n[OK] All 3 graphs saved to results/")
