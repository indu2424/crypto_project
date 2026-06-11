import sys, time, os
sys.path.insert(0,"src/modules")
from aes_module import load_key, encrypt, decrypt
from chacha_module import load_chacha_key, chacha_encrypt, chacha_decrypt

chat_history = []

def send_message(sender, message, algo="aes", room="general"):
    aes_key = load_key()
    cha_key = load_chacha_key()

    if algo == "aes":
        ct, nonce, tag, enc_ms = encrypt(aes_key, message)
        dec, dec_ms = decrypt(aes_key, ct, nonce, tag)
        algo_name = "AES-256-GCM"
    else:
        ct, nonce, tag, enc_ms = chacha_encrypt(cha_key, message)
        dec, dec_ms = chacha_decrypt(cha_key, ct, nonce, tag)
        algo_name = "ChaCha20-Poly1305"

    entry = {
        "id": len(chat_history)+1,
        "sender": sender, "room": room,
        "original": message,
        "algo": algo_name,
        "ciphertext": ct.hex(),
        "ct_preview": ct.hex()[:32]+"...",
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "enc_ms": round(enc_ms,4),
        "dec_ms": round(dec_ms,4),
        "decrypted": dec,
        "integrity": "✓ Verified",
        "time": time.strftime("%H:%M:%S"),
        "payload_bytes": len(message.encode())
    }
    chat_history.insert(0, entry)
    if len(chat_history) > 100: chat_history.pop()
    return entry

def encrypt_file(file_bytes, filename, algo="aes"):
    aes_key = load_key()
    cha_key = load_chacha_key()
    content = file_bytes.decode("latin-1")

    if algo == "aes":
        ct, nonce, tag, enc_ms = encrypt(aes_key, content)
        algo_name = "AES-256-GCM"
    else:
        ct, nonce, tag, enc_ms = chacha_encrypt(cha_key, content)
        algo_name = "ChaCha20-Poly1305"

    return {
        "filename": filename,
        "original_size": len(file_bytes),
        "encrypted_size": len(ct),
        "algo": algo_name,
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "enc_ms": round(enc_ms,4),
        "ct_hex_preview": ct.hex()[:64]+"...",
        "ct_bytes": ct, "nonce_bytes": nonce, "tag_bytes": tag
    }
