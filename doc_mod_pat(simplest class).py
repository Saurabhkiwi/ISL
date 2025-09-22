# exam_demo.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import time, json


# === Utility functions ===
def rsa_keypair(name):
    key = RSA.generate(2048)
    return {"name": name, "priv": key, "pub": key.publickey()}

def rsa_encrypt(pub, data):
    return PKCS1_OAEP.new(pub).encrypt(data)

def rsa_decrypt(priv, data):
    return PKCS1_OAEP.new(priv).decrypt(data)

def aes_encrypt(key, plaintext):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag

def aes_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def sign(priv, data):
    h = SHA256.new(data)
    return pkcs1_15.new(priv).sign(h)

def verify(pub, data, sig):
    try:
        pkcs1_15.new(pub).verify(SHA256.new(data), sig)
        return True
    except:
        return False


# === Roles ===
class Patient:
    def __init__(self, name):
        self.keys = rsa_keypair(name)

    def prepare_package(self, msg, doctor_pub):
        print(f"[{self.keys['name']}] Preparing package...")
        # AES encrypt the message
        aes_key = get_random_bytes(16)
        nonce, ct, tag = aes_encrypt(aes_key, msg.encode())
        # Encrypt AES key with Doctor’s RSA
        enc_aes = rsa_encrypt(doctor_pub, aes_key)
        # Sign the plaintext
        sig = sign(self.keys["priv"], msg.encode())
        ts = time.time()
        return {
            "ciphertext": ct,
            "nonce": nonce,
            "tag": tag,
            "enc_aes": enc_aes,
            "patient_signature": sig,
            "timestamp": ts,
            "patient_name": self.keys["name"],
        }


class Doctor:
    def __init__(self, name):
        self.keys = rsa_keypair(name)

    def process_package(self, package, patient_pub):
        print(f"[{self.keys['name']}] Processing package...")
        # Decrypt AES key
        aes_key = rsa_decrypt(self.keys["priv"], package["enc_aes"])
        # Recover plaintext
        pt = aes_decrypt(aes_key, package["nonce"], package["ciphertext"], package["tag"])
        print(f"[{self.keys['name']}] Recovered plaintext: {pt.decode()}")
        # Verify patient signature
        ok = verify(patient_pub, pt, package["patient_signature"])
        print(f"[{self.keys['name']}] Patient signature valid?: {ok}")
        # Sign confirmation
        conf = sign(self.keys["priv"], pt)
        return {
            "doctor_confirmation": conf,
            "doctor_name": self.keys["name"],
            "entry_logged_at": time.time(),
            "package_timestamp": package["timestamp"],
            "patient_signature_ok": ok,
        }


class Moderator:
    def __init__(self):
        self.log = []

    def store(self, package):
        print("[Moderator] Storing received package in log (cannot decrypt).")
        self.log.append({"package": package})

    def add_doctor_confirmation(self, package_idx, conf):
        self.log[package_idx]["doctor_confirmation"] = conf

    def verify_log(self, patient_pub, doctor_pub):
        print("[Moderator] Verifying log entry integrity and signatures...")
        results = []
        for i, entry in enumerate(self.log):
            package = entry["package"]
            pt = b""  # moderator cannot decrypt
            res = {
                "entry_logged_at": entry.get("doctor_confirmation", {}).get("entry_logged_at"),
                "package_timestamp": package["timestamp"],
                "patient_signature_ok": entry.get("doctor_confirmation", {}).get("patient_signature_ok"),
                "doctor_confirmation_ok": verify(
                    doctor_pub,
                    pt,  # doctor confirmation is over plaintext (not accessible here)
                    entry["doctor_confirmation"]["doctor_confirmation"],
                ) if "doctor_confirmation" in entry else False
            }
            results.append(res)
        return results


# === Demo run ===
if __name__ == "__main__":
    patient = Patient("Alice")
    doctor = Doctor("Dr_Bob")
    moderator = Moderator()

    msg = "Patient Alice: Blood test result - all normal. Prescribed medication X."

    # Patient prepares package
    package = patient.prepare_package(msg, doctor.keys["pub"])

    # Moderator stores
    moderator.store(package)

    # Doctor processes
    conf = doctor.process_package(package, patient.keys["pub"])

    # Moderator stores doctor confirmation
    moderator.add_doctor_confirmation(0, conf)

    # Verify log
    results = moderator.verify_log(patient.keys["pub"], doctor.keys["pub"])
    print(json.dumps(results, indent=2))
