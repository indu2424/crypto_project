import os, time
from Crypto.Cipher import ChaCha20_Poly1305

def generate_chacha_key():
    key = os.urandom(32)
    with open("certs/chacha.key","wb") as f: f.write(key)
    return key

def load_chacha_key():
    if not os.path.exists("certs/chacha.key"): generate_chacha_key()
    with open("certs/chacha.key","rb") as f: return f.read()

def chacha_encrypt(key, plaintext):
    start = time.perf_counter()
    cipher = ChaCha20_Poly1305.new(key=key)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return ct, cipher.nonce, tag, (time.perf_counter()-start)*1000

def chacha_decrypt(key, ct, nonce, tag):
    start = time.perf_counter()
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag).decode()
    return pt, (time.perf_counter()-start)*1000
