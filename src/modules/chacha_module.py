import os
import time
from Crypto.Cipher import ChaCha20_Poly1305

def generate_chacha_key():
    key = os.urandom(32)
    with open("certs/chacha.key", "wb") as f:
        f.write(key)
    return key

def load_chacha_key():
    with open("certs/chacha.key", "rb") as f:
        return f.read()

def chacha_encrypt(key, plaintext):
    start = time.perf_counter()
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    elapsed = (time.perf_counter() - start) * 1000
    return ciphertext, cipher.nonce, tag, elapsed

def chacha_decrypt(key, ciphertext, nonce, tag):
    start = time.perf_counter()
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    elapsed = (time.perf_counter() - start) * 1000
    return plaintext.decode(), elapsed
