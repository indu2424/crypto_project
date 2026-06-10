import sys
sys.path.insert(0, "src/modules")
from aes_module import generate_key, encrypt, decrypt
from Crypto.Cipher import AES

print("=== AES-256-GCM Unit Tests ===\n")
passed = 0
failed = 0

def test(name, result):
    global passed, failed
    if result:
        print(f"[PASS] {name}")
        passed += 1
    else:
        print(f"[FAIL] {name}")
        failed += 1

key = generate_key()

# Test 1 — basic encrypt and decrypt
ciphertext, nonce, tag, _ = encrypt(key, "hello world")
decrypted, _ = decrypt(key, ciphertext, nonce, tag)
test("Basic encrypt and decrypt", decrypted == "hello world")

# Test 2 — decrypted matches original exactly
message = "IoT Sensor Data: temperature=28.5, humidity=65"
ciphertext, nonce, tag, _ = encrypt(key, message)
decrypted, _ = decrypt(key, ciphertext, nonce, tag)
test("Decrypted text matches original", decrypted == message)

# Test 3 — ciphertext is different from plaintext
ciphertext, nonce, tag, _ = encrypt(key, "secret data")
test("Ciphertext differs from plaintext", ciphertext != b"secret data")

# Test 4 — two encryptions of same message give different ciphertext (random nonce)
c1, n1, t1, _ = encrypt(key, "same message")
c2, n2, t2, _ = encrypt(key, "same message")
test("Random nonce makes each encryption unique", c1 != c2)

# Test 5 — tampered ciphertext is rejected
ciphertext, nonce, tag, _ = encrypt(key, "original message")
tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
try:
    decrypt(key, tampered, nonce, tag)
    test("Tampered ciphertext rejected", False)
except Exception:
    test("Tampered ciphertext rejected", True)

# Test 6 — tampered tag is rejected
ciphertext, nonce, tag, _ = encrypt(key, "original message")
bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
try:
    decrypt(key, ciphertext, nonce, bad_tag)
    test("Tampered auth tag rejected", False)
except Exception:
    test("Tampered auth tag rejected", True)

# Test 7 — wrong key fails
ciphertext, nonce, tag, _ = encrypt(key, "secret")
wrong_key = generate_key()
try:
    decrypt(wrong_key, ciphertext, nonce, tag)
    test("Wrong key rejected", False)
except Exception:
    test("Wrong key rejected", True)

# Test 8 — empty string encrypts and decrypts
ciphertext, nonce, tag, _ = encrypt(key, " ")
decrypt
