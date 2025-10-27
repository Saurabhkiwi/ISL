import sys
import json
from datetime import datetime
from Crypto.PublicKey import ECC, DSA
from Crypto.Cipher import AES
from Crypto.Signature import DSS
from Crypto.Hash import MD5, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF

# --------------- ECIES Encryption (for Merchant) ---------------
# Based on Lab 3 
# ECIES = Elliptic Curve Integrated Encryption Scheme
# (ECDH + KDF + AES)

def generate_ecc_keys(curve='P-256'):
    key = ECC.generate(curve=curve)
    return {"public_key": key.publickey(), "private_key": key}

def ecies_encrypt(msg_bytes, pub_key_ecc):
    """Encrypts a message using ECIES."""
    # 1. Generate ephemeral key for ECDH
    ephemeral_key = ECC.generate(curve=pub_key_ecc.curve)
    
    # 2. Derive shared secret
    shared_secret = ephemeral_key.exchange_key(pub_key_ecc)
    
    # 3. Derive symmetric key using HKDF
    sym_key = HKDF(shared_secret, 16, b'', SHA256)
    
    # 4. Encrypt with AES-GCM
    aes_cipher = AES.new(sym_key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(msg_bytes)
    
    # 5. Return public part of ephemeral key + crypto payload
    return {
        "ephemeral_pub_hex": ephemeral_key.publickey().export_key(format='PEM'),
        "nonce": aes_cipher.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }

def ecies_decrypt(payload_dict, priv_key_ecc):
    """Decrypts an ECIES message."""
    try:
        # 1. Load all parts
        ephemeral_pub_key = ECC.import_key(payload_dict["ephemeral_pub_hex"])
        nonce = bytes.fromhex(payload_dict["nonce"])
        tag = bytes.fromhex(payload_dict["tag"])
        ciphertext = bytes.fromhex(payload_dict["ciphertext"])
        
        # 2. Derive shared secret
        shared_secret = priv_key_ecc.exchange_key(ephemeral_pub_key)
        
        # 3. Derive symmetric key (must be identical)
        sym_key = HKDF(shared_secret, 16, b'', SHA256)
        
        # 4. Decrypt with AES-GCM
        aes_cipher = AES.new(sym_key, AES.MODE_GCM, nonce=nonce)
        plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError, TypeError):
        return None

# --------------- DSA Signatures (for Customer) ---------------
# Based on Lab 6 

def generate_dsa_signing_keys(bits=2048):
    key = DSA.generate(bits)
    return {"public_key": key.publickey(), "private_key": key}

def dsa_sign(hash_obj, private_key):
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature

def dsa_verify(hash_obj, sig_bytes, public_key):
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, sig_bytes)
        return True
    except (ValueError, TypeError):
        return False

# --------------- In-Memory Store and Utilities ---------------

class Store:
    def __init__(self):
        self.keys = {
            "merchant_ecc_enc": None, # ECC key pair
            "customer_dsa_sig": None, # DSA key pair
        }
        self.customer_history = []
        self.merchant_inbox = []
        self.merchant_processed = []
        self.next_tx_id = 1

store = Store()

def now_ts():
    return datetime.now().isoformat(timespec="seconds")

# --------------- Role Actions (MD5) ---------------

def customer_create_and_send():
    if store.keys["merchant_ecc_enc"] is None or store.keys["customer_dsa_sig"] is None:
        print("Keys not ready.")
        return

    try:
        details = input("Enter payment details: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if not details:
        print("Empty details. Aborting.")
        return

    msg_bytes = details.encode("utf-8")
    ts = now_ts()
    
    # Hash (MD5) of plaintext 
    digest_bytes = MD5.new(msg_bytes).digest()
    digest_hex = digest_bytes.hex()
    
    # Sign the hash-of-hash
    hash_to_sign_obj = MD5.new(digest_bytes)
    cust_key = store.keys["customer_dsa_sig"]["private_key"]
    signature = dsa_sign(hash_to_sign_obj, cust_key)

    # Encrypt payment details using Merchant's ECC public key
    merch_key = store.keys["merchant_ecc_enc"]["public_key"]
    try:
        c_payload_dict = ecies_encrypt(msg_bytes, merch_key)
    except Exception as e:
        print("Encryption error:", str(e))
        return

    tx = {
        "id": store.next_tx_id,
        "timestamp": ts,
        "plaintext": details,
        # Store the payload as a JSON string
        "cipher_payload_json": json.dumps(c_payload_dict), 
        "hash_hex": digest_hex,
        "signature_hex": signature.hex(),
        "processed": False,
    }
    store.next_tx_id += 1
    store.customer_history.append(tx)
    store.merchant_inbox.append(dict(tx))

    print("Transaction created and sent.")
    print("ID:", tx["id"])
    print("MD5 digest (hex):", tx["hash_hex"])
    print("DSA signature (hex):", tx["signature_hex"][:64] + "...")

def merchant_process_all():
    if store.keys["merchant_ecc_enc"] is None or store.keys["customer_dsa_sig"] is None:
        print("Keys not ready.")
        return
    if not store.merchant_inbox:
        print("No pending transactions.")
        return

    merch_priv_key = store.keys["merchant_ecc_enc"]["private_key"]
    cust_pub_key = store.keys["customer_dsa_sig"]["public_key"]

    for tx in store.merchant_inbox:
        ts = now_ts()
        c_payload_json = tx["cipher_payload_json"]
        
        # Decrypt payload with Merchant's ECC private key
        payload_dict = json.loads(c_payload_json)
        decrypted_msg_bytes = ecies_decrypt(payload_dict, merch_priv_key)
        
        decrypt_ok = decrypted_msg_bytes is not None
        decrypted_msg_str = decrypted_msg_bytes.decode("utf-8") if decrypt_ok else ""

        # Compute hash of decrypted plaintext
        computed_hash_hex = "DECRYPT_FAIL"
        if decrypt_ok:
            computed_hash_hex = MD5.new(decrypted_msg_bytes).hexdigest()

        # Verify signature using received hash
        received_hash_hex = tx["hash_hex"]
        received_hash_bytes = bytes.fromhex(received_hash_hex)
        sig_bytes = bytes.fromhex(tx["signature_hex"])
        
        hash_to_verify_obj = MD5.new(received_hash_bytes)
        sig_valid = dsa_verify(hash_to_verify_obj, sig_bytes, cust_pub_key)

        hash_match = (computed_hash_hex == received_hash_hex)

        rec = {
            "id": tx["id"],
            "timestamp": ts,
            "received_hash_hex": received_hash_hex,
            "computed_hash_hex": computed_hash_hex,
            "signature_valid": bool(sig_valid),
            "hash_match": bool(hash_match),
            "decryption_ok": bool(decrypt_ok),
            "decrypted_plaintext": decrypted_msg_str,
        }
        store.merchant_processed.append(rec)
        
        for item in store.customer_history:
            if item["id"] == tx["id"]:
                item["processed"] = True
                break

        print("Processed transaction ID:", tx["id"])
        print("Signature valid (Authentication):", rec["signature_valid"])
        print("Decryption ok (Confidentiality):", rec["decryption_ok"])
        print("Hashes match (Integrity):", rec["hash_match"])
        print("-" * 40)

    store.merchant_inbox = []

# --- Menus and other functions (customer_view_history, etc.) ---
# (These are identical to your provided code and the previous example)
# (Omitting for brevity... copy them from the previous response)

def show_public_keys():
    if store.keys["merchant_ecc_enc"] is None or store.keys["customer_dsa_sig"] is None:
        print("Keys not ready.")
        return
    merch_pub = store.keys["merchant_ecc_enc"]["public_key"]
    cust_pub = store.keys["customer_dsa_sig"]["public_key"]
    
    print("Customer DSA Public Key (y):", hex(cust_pub.y)[:40] + "...")
    print("Merchant ECC Public Key (Curve):", merch_pub.curve)


def main_menu(): # Placeholder
    print("Please copy the full menu system from the previous response.")
def customer_menu(): # Placeholder
    print("Please copy the full menu system from the previous response.")
def merchant_menu(): # Placeholder
    print("Please copy the full menu system from the previous response.")
def auditor_menu(): # Placeholder
    print("Please copy the full menu system from the previous response.")
def customer_view_history(): # Placeholder
    print("Please copy the full menu system from the previous response.")
def merchant_show_processed(): # Placeholder
    print("Please copy the full menu system from the previous response.")
def auditor_view_hashed_records(): # Placeholder
    print("Please copy the full menu system from the previous response.")
def auditor_verify_signatures(): # Placeholder
    print("Please copy the full menu system from the previous response.")

def init_keys():
    print("Generating keys. This may take a moment...")
    # Merchant key for encryption
    print("Generating ECC P-256 key for Merchant...")
    store.keys["merchant_ecc_enc"] = generate_ecc_keys(curve='P-256')
    
    # Customer key for signing
    print("Generating 2048-bit DSA key for Customer...")
    store.keys["customer_dsa_sig"] = generate_dsa_signing_keys(bits=2048)
    print("Keys ready.")

if __name__ == "__main__":
    print("="*40)
    print("Combination 2: ECIES Encrypt + DSA Sign + MD5")
    print("NOTE: Menu functions are omitted for brevity.")
    print("="*40)
    try:
        init_keys()
        # To run this, copy the full menu functions from the previous response
        # main_menu() 
        print("\nDemo: Creating a transaction...")
        customer_create_and_send()
        print("\nDemo: Processing a transaction...")
        merchant_process_all()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
