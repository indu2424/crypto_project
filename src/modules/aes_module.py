import os
import time
from Crypto.Cipher import AES


def generate_key():
    key = os.urandom(32)
    with open("certs/aes.key", "wb") as f:
        f.write(key)
    print("[OK] AES-256 key generated and saved to certs/aes.key")
    return key


def load_key():
    with open("certs/aes.key", "rb") as f:
        return f.read()


def encrypt(key, plaintext):
    start = time.perf_counter()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    end = time.perf_counter()
    elapsed_ms = (end - start) * 1000
    return ciphertext, cipher.nonce, tag, elapsed_ms


def decrypt(key, ciphertext, nonce, tag):
    start = time.perf_counter()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    end = time.perf_counter()
    elapsed_ms = (end - start) * 1000
    return plaintext.decode(), elapsed_ms


if __name__ == "__main__":
    print("=== AES-256-GCM Module Test ===\n")

    key = generate_key()

    message = "IoT Sensor Data: temperature=28.5, humidity=65, device=IoT-001"
    print(f"Original message : {message}")

    ciphertext, nonce, tag, enc_time = encrypt(key, message)
    print(f"Encrypted        : {ciphertext.hex()}")
    print(f"Nonce            : {nonce.hex()}")
    print(f"Auth Tag         : {tag.hex()}")
    print(f"Encryption time  : {enc_time:.4f} ms")

    decrypted, dec_time = decrypt(key, ciphertext, nonce, tag)
    print(f"\nDecrypted message: {decrypted}")
    print(f"Decryption time  : {dec_time:.4f} ms")

    if decrypted == message:
        print("\n[PASS] Encrypt → Decrypt successful")
    else:
        print("\n[FAIL] Mismatch!")
