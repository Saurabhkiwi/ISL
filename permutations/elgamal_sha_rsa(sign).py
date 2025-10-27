import sys
import json
from datetime import datetime
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pss
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes

# --------------- ElGamal Hybrid Encryption (for Merchant) ---------------
# Based on Lab 3 

def elgamal_hybrid_encrypt(msg_bytes, pub_key_elgamal):
    """Encrypts a message using ElGamal + AES-GCM."""
    # 1. Generate a one-time AES key
    session_key = get_random_bytes(16)
    
    # 2. Encrypt the message with AES-GCM
    aes_cipher = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(msg_bytes)
    nonce = aes_cipher.nonce
    
    # 3. Encrypt the AES session key with ElGamal
    # pycryptodome ElGamal requires a dummy 'k'
    encrypted_session_key = pub_key_elgamal.encrypt(session_key, 0)
    
    # 4. Return all parts, hex-encoded for storage
    return {
        "enc_session_key": encrypted_session_key[0].hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }

def elgamal_hybrid_decrypt(payload_dict, priv_key_elgamal):
    """Decrypts a message using ElGamal + AES-GCM."""
    try:
        # 1. Load all parts from hex
        enc_session_key_bytes = bytes.fromhex(payload_dict["enc_session_key"])
        nonce = bytes.fromhex(payload_dict["nonce"])
        tag = bytes.fromhex(payload_dict["tag"])
        ciphertext = bytes.fromhex(payload_dict["ciphertext"])

        # 2. Decrypt the AES session key with ElGamal
        session_key = priv_key_elgamal.decrypt(enc_session_key_bytes)
        
        # 3. Decrypt the message with AES-GCM
        aes_cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError):
        return None

# --------------- RSA-PSS Signatures (for Customer) ---------------
# Based on Lab 6 

def generate_rsa_signing_keys(bits=2048):
    key = RSA.generate(bits)
    return {"public_key": key.publickey(), "private_key": key}

def rsa_pss_sign(hash_obj, private_key):
    signer = pss.new(private_key)
    signature = signer.sign(hash_obj)
    return signature

def rsa_pss_verify(hash_obj, sig_bytes, public_key):
    verifier = pss.new(public_key)
    try:
        verifier.verify(hash_obj, sig_bytes)
        return True
    except (ValueError, TypeError):
        return False

# --------------- In-Memory Store and Utilities ---------------

class Store:
    def __init__(self):
        self.keys = {
            "merchant_elg_enc": None, # ElGamal key pair
            "customer_rsa_sig": None, # RSA key pair
        }
        self.customer_history = []
        self.merchant_inbox = []
        self.merchant_processed = []
        self.next_tx_id = 1

store = Store()

def now_ts():
    return datetime.now().isoformat(timespec="seconds")

# --------------- Role Actions (SHA-1) ---------------

def customer_create_and_send():
    if store.keys["merchant_elg_enc"] is None or store.keys["customer_rsa_sig"] is None:
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
    
    # Hash (SHA-1) of plaintext 
    digest_bytes = SHA1.new(msg_bytes).digest()
    digest_hex = digest_bytes.hex()
    
    # Sign the hash-of-hash
    hash_to_sign_obj = SHA1.new(digest_bytes)
    cust_key = store.keys["customer_rsa_sig"]["private_key"]
    signature = rsa_pss_sign(hash_to_sign_obj, cust_key)

    # Encrypt payment details using Merchant's ElGamal public key
    merch_key = store.keys["merchant_elg_enc"]["public_key"]
    try:
        c_payload_dict = elgamal_hybrid_encrypt(msg_bytes, merch_key)
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
    print("SHA-1 digest (hex):", tx["hash_hex"])
    print("RSA-PSS signature (hex):", tx["signature_hex"][:64] + "...")

def merchant_process_all():
    if store.keys["merchant_elg_enc"] is None or store.keys["customer_rsa_sig"] is None:
        print("Keys not ready.")
        return
    if not store.merchant_inbox:
        print("No pending transactions.")
        return

    merch_priv_key = store.keys["merchant_elg_enc"]["private_key"]
    cust_pub_key = store.keys["customer_rsa_sig"]["public_key"]

    for tx in store.merchant_inbox:
        ts = now_ts()
        c_payload_json = tx["cipher_payload_json"]
        
        # Decrypt payload with Merchant's ElGamal private key
        payload_dict = json.loads(c_payload_json)
        decrypted_msg_bytes = elgamal_hybrid_decrypt(payload_dict, merch_priv_key)
        
        decrypt_ok = decrypted_msg_bytes is not None
        decrypted_msg_str = decrypted_msg_bytes.decode("utf-8") if decrypt_ok else ""

        # Compute hash of decrypted plaintext
        computed_hash_hex = "DECRYPT_FAIL"
        if decrypt_ok:
            computed_hash_hex = SHA1.new(decrypted_msg_bytes).hexdigest()

        # Verify signature using received hash
        received_hash_hex = tx["hash_hex"]
        received_hash_bytes = bytes.fromhex(received_hash_hex)
        sig_bytes = bytes.fromhex(tx["signature_hex"])
        
        hash_to_verify_obj = SHA1.new(received_hash_bytes)
        sig_valid = rsa_pss_verify(hash_to_verify_obj, sig_bytes, cust_pub_key)

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
    if store.keys["merchant_elg_enc"] is None or store.keys["customer_rsa_sig"] is None:
        print("Keys not ready.")
        return
    merch_pub = store.keys["merchant_elg_enc"]["public_key"]
    cust_pub = store.keys["customer_rsa_sig"]["public_key"]
    
    print("Customer RSA-PSS Public Key (bits):", cust_pub.n.bit_length())
    print("Merchant ElGamal Public Key (bits):", merch_pub.p.bit_length())

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
    print("Generating 1024-bit ElGamal key for Merchant...")
    store.keys["merchant_elg_enc"] = {
        "private_key": ElGamal.generate(1024, get_random_bytes),
    }
    store.keys["merchant_elg_enc"]["public_key"] = store.keys["merchant_elg_enc"]["private_key"].publickey()
    
    # Customer key for signing
    print("Generating 2048-bit RSA key for Customer...")
    store.keys["customer_rsa_sig"] = generate_rsa_signing_keys(bits=2048)
    print("Keys ready.")

if __name__ == "__main__":
    print("="*40)
    print("Combination 1: ElGamal Encrypt + RSA-PSS Sign + SHA-1")
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
