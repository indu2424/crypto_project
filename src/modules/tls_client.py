import ssl
import socket
import time
import json
import sys
sys.path.insert(0, "src/modules")
from aes_module import load_key, encrypt

HOST = "localhost"
PORT = 8443

def send_message(payload):
    key = load_key()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("certs/server.crt")
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    start = time.perf_counter()

    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as tls_sock:
            hs_time = (time.perf_counter() - start) * 1000
            print(f"[CLIENT] Connected — TLS handshake : {hs_time:.4f} ms")
            print(f"[CLIENT] TLS version : {tls_sock.version()}")
            print(f"[CLIENT] Cipher      : {tls_sock.cipher()[0]}")

            message = json.dumps(payload)
            ciphertext, nonce, tag, enc_time = encrypt(key, message)
            print(f"[CLIENT] Encrypting  : {message}")
            print(f"[CLIENT] Encrypt time: {enc_time:.4f} ms")

            tls_sock.sendall(nonce + tag + ciphertext)

            response = tls_sock.recv(1024)
            total = (time.perf_counter() - start) * 1000
            print(f"[CLIENT] Server says : {response.decode()}")
            print(f"[CLIENT] Total time  : {total:.4f} ms")

if __name__ == "__main__":
    payload = {
        "device_id": "IoT-001",
        "temperature": 28.5,
        "humidity": 65,
        "status": "active"
    }
    send_message(payload)
