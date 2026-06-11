import time
import os
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import base64

def encrypt_aes_gcm(plaintext: bytes, key: bytes = None):
    """AES-256-GCM encryption. Returns ciphertext, nonce, tag, key, time_ms."""
    if key is None:
        key = get_random_bytes(32)  # 256-bit key
    
    start = time.perf_counter()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    elapsed = (time.perf_counter() - start) * 1000  # ms
    
    return {
        "algorithm": "AES-256-GCM",
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "key": base64.b64encode(key).decode(),
        "time_ms": round(elapsed, 4),
        "payload_size": len(plaintext)
    }

def decrypt_aes_gcm(ciphertext_b64: str, nonce_b64: str, tag_b64: str, key_b64: str):
    key = base64.b64decode(key_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

def encrypt_chacha20(plaintext: bytes, key: bytes = None):
    """ChaCha20-Poly1305 encryption."""
    if key is None:
        key = get_random_bytes(32)
    
    start = time.perf_counter()
    cipher = ChaCha20_Poly1305.new(key=key)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    elapsed = (time.perf_counter() - start) * 1000
    
    return {
        "algorithm": "ChaCha20-Poly1305",
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "key": base64.b64encode(key).decode(),
        "time_ms": round(elapsed, 4),
        "payload_size": len(plaintext)
    }

def decrypt_chacha20(ciphertext_b64: str, nonce_b64: str, tag_b64: str, key_b64: str):
    key = base64.b64decode(key_b64)
    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()
