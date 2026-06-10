import ssl
import socket
import time
import threading
import csv
import sys
sys.path.insert(0, "src/modules")
from aes_module import load_key, encrypt, decrypt

HOST = "localhost"
PORT = 8444
RUNS = 20

def server_thread():
    key = load_key()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("certs/server.crt", "certs/server.key")
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(RUNS * 2)
        with context.wrap_socket(s, server_side=True) as tls_s:
            for _ in range(RUNS * 2):
                try:
                    conn, _ = tls_s.accept()
                    with conn:
                        data = conn.recv(4096)
                        conn.sendall(b"ACK")
                except:
                    pass

def measure_handshake():
    key = load_key()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("certs/server.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    times = []
    for _ in range(RUNS):
        start = time.perf_counter()
        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as tls_sock:
                hs = (time.perf_counter() - start) * 1000
                times.append(hs)
                ct, nonce, tag, _ = encrypt(key, "benchmark payload")
                tls_sock.sendall(nonce + tag + ct)
                tls_sock.recv(1024)
        time.sleep(0.05)
    return times

def run():
    print("=== TLS 1.3 Handshake Benchmark ===\n")

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()
    time.sleep(1)

    print(f"Running {RUNS} handshake measurements...")
    times = measure_handshake()

    avg = sum(times) / len(times)
    mn  = min(times)
    mx  = max(times)

    print(f"\n{'Metric':<20} {'Time (ms)'}")
    print("-" * 35)
    print(f"{'Average':<20} {avg:.4f}")
    print(f"{'Minimum':<20} {mn:.4f}")
    print(f"{'Maximum':<20} {mx:.4f}")

    results = [{"run": i+1, "handshake_ms": round(t, 4)} for i, t in enumerate(times)]
    with open("results/tls_benchmark.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["run", "handshake_ms"])
        writer.writeheader()
        writer.writerows(results)

    print("\n[OK] Results saved to results/tls_benchmark.csv")

if __name__ == "__main__":
    run()
