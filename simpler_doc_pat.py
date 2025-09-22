from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

# ---------- Key Generation ----------
patient_key = RSA.generate(2048)
doctor_key = RSA.generate(2048)

patient_pub = patient_key.publickey()
doctor_pub = doctor_key.publickey()

# ---------- Patient side ----------
print("\n--- Patient Side ---")
message = b"Patient Alice: Blood test result - all normal."

# AES encrypt
aes_key = get_random_bytes(32)  # AES-256
cipher_aes = AES.new(aes_key, AES.MODE_GCM)
ciphertext, tag = cipher_aes.encrypt_and_digest(message)

# Encrypt AES key with doctor’s RSA public key
cipher_rsa = PKCS1_OAEP.new(doctor_pub)
enc_aes_key = cipher_rsa.encrypt(aes_key)

# Sign the plaintext
h = SHA256.new(message)
patient_signature = pkcs1_15.new(patient_key).sign(h)

package = (enc_aes_key, ciphertext, cipher_aes.nonce, tag, patient_signature)
print("Package prepared and sent.")

# ---------- Doctor side ----------
print("\n--- Doctor Side ---")
(enc_aes_key, ciphertext, nonce, tag, patient_signature) = package

# Decrypt AES key
cipher_rsa = PKCS1_OAEP.new(doctor_key)
aes_key_dec = cipher_rsa.decrypt(enc_aes_key)

# Decrypt message
cipher_aes = AES.new(aes_key_dec, AES.MODE_GCM, nonce=nonce)
plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
print("Decrypted message:", plaintext.decode())

# Verify patient’s signature
h = SHA256.new(plaintext)
try:
    pkcs1_15.new(patient_pub).verify(h, patient_signature)
    print("Patient signature verified ✅")
except:
    print("Patient signature invalid ❌")

# Doctor signs confirmation
confirm_hash = SHA256.new(plaintext)
doctor_signature = pkcs1_15.new(doctor_key).sign(confirm_hash)
print("Doctor signed confirmation.")

# ---------- Moderator side ----------
print("\n--- Moderator Side ---")
# Moderator cannot decrypt, but can check signatures
try:
    pkcs1_15.new(patient_pub).verify(SHA256.new(plaintext), patient_signature)
    print("Moderator: Patient signature valid ✅")
except:
    print("Moderator: Patient signature invalid ❌")

try:
    pkcs1_15.new(doctor_pub).verify(SHA256.new(plaintext), doctor_signature)
    print("Moderator: Doctor confirmation valid ✅")
except:
    print("Moderator: Doctor confirmation invalid ❌")
