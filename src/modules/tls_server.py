import ssl
import socket
import time
import threading
import sys
sys.path.insert(0, "src/modules")
from aes_module import load_key, decrypt

HOST = "localhost"
PORT = 8443
server_running = False

def handle_client(conn, key):
    try:
        with conn:
            data = b""
            conn.settimeout(2)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except:
                pass
            if len(data) > 32:
                nonce      = data[:16]
                tag        = data[16:32]
                ciphertext = data[32:]
                decrypted, _ = decrypt(key, ciphertext, nonce, tag)
                conn.sendall(b"ACK: received")
    except:
        pass

def start_background_server():
    global server_running
    if server_running:
        return
    server_running = True

    def run():
        key = load_key()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("certs/server.crt", "certs/server.key")
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(50)
            with context.wrap_socket(s, server_side=True) as tls_s:
                while True:
                    try:
                        conn, _ = tls_s.accept()
                        threading.Thread(
                            target=handle_client,
                            args=(conn, key),
                            daemon=True
                        ).start()
                    except:
                        pass
    threading.Thread(target=run, daemon=True).start()

if __name__ == "__main__":
    print("[SERVER] TLS 1.3 server running on localhost:8443 ...")
    start_background_server()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[SERVER] Stopped.")
