import ssl
import socket
import time
import sys
sys.path.insert(0, "src/modules")
from aes_module import load_key, decrypt

HOST = "localhost"
PORT = 8443

def start_server():
    key = load_key()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("certs/server.crt", "certs/server.key")
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(10)
        print(f"[SERVER] Listening on {HOST}:{PORT} with TLS 1.3...")

        with context.wrap_socket(server, server_side=True) as tls_server:
            while True:
                conn, addr = tls_server.accept()
                hs_time = time.perf_counter()
                with conn:
                    print(f"\n[SERVER] Connection from {addr}")
                    print(f"[SERVER] TLS version : {conn.version()}")
                    print(f"[SERVER] Cipher      : {conn.cipher()[0]}")

                    data = b""
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk

                    nonce      = data[:16]
                    tag        = data[16:32]
                    ciphertext = data[32:]

                    decrypted, dec_time = decrypt(key, ciphertext, nonce, tag)
                    elapsed = (time.perf_counter() - hs_time) * 1000

                    print(f"[SERVER] Decrypted   : {decrypted}")
                    print(f"[SERVER] Decrypt time: {dec_time:.4f} ms")
                    print(f"[SERVER] Total time  : {elapsed:.4f} ms")

                    conn.sendall(b"ACK: message received and decrypted")

if __name__ == "__main__":
    start_server()
