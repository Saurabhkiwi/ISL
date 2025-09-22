#!/usr/bin/env python3
"""
EHR hybrid crypto demo:
- Patient encrypts an EHR message with AES-GCM (symmetric).
- AES key is encrypted with Doctor's RSA public key (RSA-OAEP).
- Patient hashes the plaintext (SHA-256) and signs the hash with Patient's RSA private key (PKCS#1 v1.5).
- Doctor decrypts AES key, decrypts message, verifies patient signature, then signs a confirmation and stores confirmation.
- Moderator stores logs (cannot decrypt AES key) and can verify signatures.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import json, time, base64, pprint

# ---------- Utilities ----------
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode())

# ---------- Role classes ----------
class Participant:
    def __init__(self, name: str, rsa_bits: int = 2048):
        self.name = name
        self.key = RSA.generate(rsa_bits)
        self.pub_pem = self.key.publickey().export_key()
        self.priv_pem = self.key.export_key()

    def sign(self, data: bytes) -> bytes:
        h = SHA256.new(data)
        sig = pkcs1_15.new(self.key).sign(h)
        return sig

    def verify(self, pub_pem: bytes, data: bytes, signature: bytes) -> bool:
        pub = RSA.import_key(pub_pem)
        h = SHA256.new(data)
        try:
            pkcs1_15.new(pub).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False


class Patient(Participant):
    def __init__(self, name="Patient"):
        super().__init__(name)

    def prepare_message(self, plaintext: bytes, doctor_pub_pem: bytes):
        """
        - Generate AES key (256-bit)
        - Encrypt plaintext with AES-GCM
        - Encrypt AES key with Doctor's RSA public key (OAEP)
        - Hash plaintext and sign hash with patient's RSA private key
        Returns a package dict.
        """
        # 1) AES-GCM
        aes_key = get_random_bytes(32)  # 256-bit AES key
        nonce = get_random_bytes(12)    # recommended 12 bytes for GCM
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(plaintext)

        # 2) RSA-OAEP encrypt the AES key for doctor
        doctor_pub = RSA.import_key(doctor_pub_pem)
        rsa_cipher = PKCS1_OAEP.new(doctor_pub, hashAlgo=SHA256)
        enc_aes_key = rsa_cipher.encrypt(aes_key)

        # 3) Hash and sign the plaintext
        h = SHA256.new(plaintext)
        sig = pkcs1_15.new(self.key).sign(h)

        package = {
            "sender": self.name,
            "aes_ciphertext": b64(ct),
            "aes_nonce": b64(nonce),
            "aes_tag": b64(tag),
            "enc_aes_key": b64(enc_aes_key),
            "patient_signature": b64(sig),
            "hash_plain": b64(h.digest()),
            "timestamp": time.time()
        }
        return package


class Doctor(Participant):
    def __init__(self, name="Doctor"):
        super().__init__(name)

    def process_package(self, package: dict, patient_pub_pem: bytes):
        """
        - Decrypt AES key with own RSA private key
        - Decrypt ciphertext with AES-GCM
        - Verify patient's signature on plaintext hash
        - If valid, sign a confirmation (message id/hash/timestamp)
        - Return dictionary with plaintext and confirmation metadata
        """
        # decode fields
        enc_aes_key = ub64(package["enc_aes_key"])
        nonce = ub64(package["aes_nonce"])
        ct = ub64(package["aes_ciphertext"])
        tag = ub64(package["aes_tag"])
        patient_sig = ub64(package["patient_signature"])
        # 1) decrypt AES key
        rsa_cipher = PKCS1_OAEP.new(self.key, hashAlgo=SHA256)
        aes_key = rsa_cipher.decrypt(enc_aes_key)

        # 2) decrypt message
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        try:
            pt = cipher.decrypt_and_verify(ct, tag)
        except Exception as e:
            raise ValueError("AES decryption or tag verification failed") from e

        # 3) verify patient's signature
        h = SHA256.new(pt)
        patient_ok = False
        try:
            pub = RSA.import_key(patient_pub_pem)
            pkcs1_15.new(pub).verify(h, patient_sig)
            patient_ok = True
        except (ValueError, TypeError):
            patient_ok = False

        # 4) create doctor confirmation (sign the hash + timestamp)
        confirm_payload = {
            "doctor": self.name,
            "message_hash": b64(h.digest()),
            "received_timestamp": time.time(),
            "patient_signature_valid": patient_ok
        }
        # sign the confirmation payload bytes (deterministic serialization)
        confirm_bytes = json.dumps(confirm_payload, sort_keys=True).encode()
        confirm_sig = pkcs1_15.new(self.key).sign(SHA256.new(confirm_bytes))
        confirm_payload["doctor_signature"] = b64(confirm_sig)

        return {
            "plaintext": pt,
            "patient_signature_valid": patient_ok,
            "confirmation": confirm_payload
        }


class Moderator:
    def __init__(self, name="Moderator"):
        self.name = name
        self.log = []  # append-only list of entries

    def store_log_entry(self, package: dict, doctor_confirmation: dict):
        entry = {
            "package": package,
            "doctor_confirmation": doctor_confirmation,
            "logged_at": time.time()
        }
        self.log.append(entry)

    def verify_log_entry(self, idx: int, patient_pub_pem: bytes, doctor_pub_pem: bytes):
        if idx < 0 or idx >= len(self.log):
            raise IndexError("no such log entry")
        entry = self.log[idx]
        package = entry["package"]
        confirmation = entry["doctor_confirmation"]

        # verify patient signature on hash: we only have hash from package
        patient_sig = ub64(package["patient_signature"])
        hash_plain = ub64(package["hash_plain"])
        patient_ok = False
        try:
            pkcs1_15.new(RSA.import_key(patient_pub_pem)).verify(SHA256.new(hash_plain), patient_sig)
            patient_ok = True
        except Exception:
            patient_ok = False

        # verify doctor's signature on confirmation
        doctor_sig = ub64(confirmation["doctor_signature"])
        # reconstruct bytes signed (the serialized confirm_payload used above)
        # Note: we must reconstruct same JSON order
        confirm_payload = {
            "doctor": confirmation["doctor"],
            "message_hash": confirmation["message_hash"],
            "received_timestamp": confirmation["received_timestamp"],
            "patient_signature_valid": confirmation["patient_signature_valid"]
        }
        confirm_bytes = json.dumps(confirm_payload, sort_keys=True).encode()
        doctor_ok = False
        try:
            pkcs1_15.new(RSA.import_key(doctor_pub_pem)).verify(SHA256.new(confirm_bytes), doctor_sig)
            doctor_ok = True
        except Exception:
            doctor_ok = False

        return {
            "patient_signature_ok": patient_ok,
            "doctor_confirmation_ok": doctor_ok,
            "entry_logged_at": entry["logged_at"],
            "package_timestamp": package.get("timestamp")
        }

# ---------- Demo flow ----------
def demo():
    # create participants
    patient = Patient("Alice_Patient")
    doctor = Doctor("Dr_Bob")
    moderator = Moderator("Mod_Char")

    print("\n=== Keys generated ===")
    print(f"Patient pubkey len = {len(patient.pub_pem)} bytes")
    print(f"Doctor pubkey len = {len(doctor.pub_pem)} bytes")

    # Patient encrypts a secret medical note
    secret = b"Patient Alice: Blood test result - all normal. Prescribed medication X."
    print("\n[Patient] Preparing package...")
    package = patient.prepare_message(secret, doctor.pub_pem)

    print("\n[Moderator] Storing received package in log (cannot decrypt).")
    # Moderator stores raw package (ciphertext + metadata)
    moderator.store_log_entry(package, {"doctor": None, "doctor_signature": None})

    # Doctor retrieves package (in a real system would be delivered)
    print("\n[Doctor] Processing package...")
    result = doctor.process_package(package, patient.pub_pem)
    plaintext = result["plaintext"]
    print("[Doctor] Recovered plaintext:", plaintext.decode())
    print("[Doctor] Patient signature valid?:", result["patient_signature_valid"])

    # Doctor creates confirmation which we store in the log (update last log entry)
    print("\n[Doctor] Storing confirmation in moderator log...")
    moderator.log[-1]["doctor_confirmation"] = result["confirmation"]

    # Moderator verifying the last entry using known public keys
    print("\n[Moderator] Verifying log entry integrity and signatures...")
    verify_res = moderator.verify_log_entry(len(moderator.log)-1, patient.pub_pem, doctor.pub_pem)
    pprint.pprint(verify_res)

    print("\n=== Full log (redacted) ===")
    # print a compact summary of log (do not print raw keys/sigs fully)
    for i, e in enumerate(moderator.log):
        pkg = e["package"]
        conf = e["doctor_confirmation"]
        print(f"\nLog entry #{i}:")
        print("  package_timestamp:", pkg.get("timestamp"))
        print("  cipher_len:", len(ub64(pkg["aes_ciphertext"])))
        print("  enc_key_len:", len(ub64(pkg["enc_aes_key"])))
        print("  patient_signature_len:", len(ub64(pkg["patient_signature"])))
        print("  doctor_confirmation_signed_by:", conf.get("doctor"))

if __name__ == "__main__":
    demo()
