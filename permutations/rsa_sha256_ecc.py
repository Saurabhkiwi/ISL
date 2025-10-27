import sys
from datetime import datetime
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# --------------- RSA Encryption (for Merchant) ---------------
# Based on Lab 3 & 4 

def generate_rsa_keys(bits=2048):
    """Generates an RSA key pair for encryption."""
    key = RSA.generate(bits)
    # private_key holds both public and private components
    # public_key() extracts only the public part
    return {"public_key": key.publickey(), "private_key": key}

def rsa_encrypt(msg_bytes, public_key):
    """Encrypts a message using the RSA public key with OAEP padding."""
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(msg_bytes)
    return ciphertext

def rsa_decrypt(cipher_bytes, private_key):
    """Decrypts a ciphertext using the RSA private key with OAEP padding."""
    try:
        cipher = PKCS1_OAEP.new(private_key)
        message = cipher.decrypt(cipher_bytes)
        return message
    except (ValueError, TypeError):
        return None

# --------------- ECDSA Signatures (for Customer) ---------------
# Based on Lab 3 

def generate_ecdsa_keys():
    """Generates an ECDSA key pair on the P-256 curve."""
    key = ECC.generate(curve='P-256')
    return {"public_key": key.publickey(), "private_key": key}

def ecdsa_sign(hash_obj, private_key):
    """Signs a hash object using the ECDSA private key."""
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature

def ecdsa_verify(hash_obj, sig_bytes, public_key):
    """Verifies an ECDSA signature against a hash object."""
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
            # Merchant's key for Confidentiality
            "merchant_rsa_enc": None,
            # Customer's key for Authentication
            "customer_ecdsa_sig": None,
        }
        self.customer_history = []
        self.merchant_inbox = []
        self.merchant_processed = []
        self.next_tx_id = 1

store = Store()

def now_ts():
    return datetime.now().isoformat(timespec="seconds")

def short_hex(x, length=32):
    hx = hex(x)[2:]
    if len(hx) <= length:
        return hx
    return hx[:length] + "...(" + str(len(hx)) + " hex chars)"

# --------------- Role Actions ---------------

def customer_create_and_send():
    if store.keys["merchant_rsa_enc"] is None or store.keys["customer_ecdsa_sig"] is None:
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
    
    # Hash (SHA-256) of plaintext; this is what we send for integrity 
    digest_bytes = SHA256.new(msg_bytes).digest()
    digest_hex = digest_bytes.hex()
    
    # We will sign the *hash* of the *digest* to follow your original code's
    # "hash-of-a-hash" pattern.
    hash_to_sign_obj = SHA256.new(digest_bytes)

    # Sign the hash-object using ECDSA 
    cust_key = store.keys["customer_ecdsa_sig"]["private_key"]
    signature = ecdsa_sign(hash_to_sign_obj, cust_key)

    # Encrypt payment details using Merchant's RSA public key [cite: 419]
    merch_key = store.keys["merchant_rsa_enc"]["public_key"]
    try:
        c_bytes = rsa_encrypt(msg_bytes, merch_key)
    except Exception as e:
        print("Encryption error:", str(e))
        return

    tx = {
        "id": store.next_tx_id,
        "timestamp": ts,
        "plaintext": details,
        "cipher_hex": c_bytes.hex(), # store as hex text
        "hash_hex": digest_hex,
        "signature_hex": signature.hex(), # store as hex text
        "processed": False,
    }
    store.next_tx_id += 1
    store.customer_history.append(tx)
    store.merchant_inbox.append(dict(tx))

    print("Transaction created and sent to merchant.")
    print("ID:", tx["id"])
    print("Timestamp:", tx["timestamp"])
    print("Before encryption (plaintext):", tx["plaintext"])
    print("After encryption (cipher hex):", tx["cipher_hex"][:64] + "...")
    print("SHA-256 digest (hex):", tx["hash_hex"])
    print("ECDSA signature (hex):", tx["signature_hex"][:64] + "...")

def customer_view_history():
    if not store.customer_history:
        print("No past transactions.")
        return
    for tx in store.customer_history:
        print("ID:", tx["id"])
        print("Timestamp:", tx["timestamp"])
        print("Plaintext:", tx["plaintext"])
        print("Cipher (hex):", tx["cipher_hex"])
        print("SHA-256 digest (hex):", tx["hash_hex"])
        print("Signature (hex):", tx["signature_hex"])
        print("Processed by merchant:", tx["processed"])
        print("-" * 40)

def merchant_process_all():
    if store.keys["merchant_rsa_enc"] is None or store.keys["customer_ecdsa_sig"] is None:
        print("Keys not ready.")
        return
    if not store.merchant_inbox:
        print("No pending transactions.")
        return

    merch_priv_key = store.keys["merchant_rsa_enc"]["private_key"]
    cust_pub_key = store.keys["customer_ecdsa_sig"]["public_key"]

    processed_any = False
    for tx in store.merchant_inbox:
        processed_any = True
        ts = now_ts()
        c_hex = tx["cipher_hex"]
        
        # Decrypt payload with Merchant's RSA private key
        decrypted_msg_bytes = rsa_decrypt(bytes.fromhex(c_hex), merch_priv_key)
        decrypt_ok = decrypted_msg_bytes is not None
        decrypted_msg_str = decrypted_msg_bytes.decode("utf-8") if decrypt_ok else ""

        # Compute hash of decrypted plaintext
        computed_hash_hex = "DECRYPT_FAIL"
        if decrypt_ok:
            computed_hash_hex = SHA256.new(decrypted_msg_bytes).hexdigest()

        # Verify signature using received hash
        received_hash_hex = tx["hash_hex"]
        received_hash_bytes = bytes.fromhex(received_hash_hex)
        sig_bytes = bytes.fromhex(tx["signature_hex"])
        
        # Re-create the hash-of-hash object to verify
        hash_to_verify_obj = SHA256.new(received_hash_bytes)
        sig_valid = ecdsa_verify(hash_to_verify_obj, sig_bytes, cust_pub_key)

        # Check if received hash matches computed hash
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
        
        # Find and update original customer history item
        for item in store.customer_history:
            if item["id"] == tx["id"]:
                item["processed"] = True
                break

        print("Processed transaction ID:", tx["id"])
        print("Signature valid (Authentication):", rec["signature_valid"])
        print("Decryption ok (Confidentiality):", rec["decryption_ok"])
        print("Hashes match (Integrity):", rec["hash_match"])
        print("Timestamp:", rec["timestamp"])
        print("-" * 40)

    store.merchant_inbox = []
    if not processed_any:
        print("No transactions processed.")

def merchant_show_processed():
    if not store.merchant_processed:
        print("No processed records.")
        return
    for rec in store.merchant_processed:
        print("ID:", rec["id"])
        print("Timestamp:", rec["timestamp"])
        print("Signature valid:", rec["signature_valid"])
        print("Decryption ok:", rec["decryption_ok"])
        print("Received hash (hex):", rec["received_hash_hex"])
        print("Computed hash (hex):", rec["computed_hash_hex"])
        print("Hashes match:", rec["hash_match"])
        if rec["decryption_ok"]:
            print("Decrypted plaintext:", rec["decrypted_plaintext"])
        print("-" * 40)

def auditor_view_hashed_records():
    if not store.merchant_processed:
        print("No records to audit.")
        return
    for rec in store.merchant_processed:
        print("ID:", rec["id"])
        print("Timestamp:", rec["timestamp"])
        print("Received hash (hex):", rec["received_hash_hex"])
        print("Computed hash (hex):", rec["computed_hash_hex"])
        print("Hashes match:", rec["hash_match"])
        print("-" * 40)

def auditor_verify_signatures():
    """Auditor verifies non-repudiation without seeing plaintext."""
    if not store.merchant_processed:
        print("No records to verify.")
        return
        
    cust_pub_key = store.keys["customer_ecdsa_sig"]["public_key"]
    
    for rec in store.merchant_processed:
        tx_id = rec["id"]
        sig_hex = None
        hash_hex = rec["received_hash_hex"]
        
        # Auditor gets original signature from customer history
        for tx in store.customer_history:
            if tx["id"] == tx_id:
                sig_hex = tx["signature_hex"]
                break
                
        if sig_hex is None:
            print("ID:", tx_id, "Original signature not found in customer log.")
            continue
            
        try:
            sig_bytes = bytes.fromhex(sig_hex)
            hash_bytes = bytes.fromhex(hash_hex)
            hash_to_verify_obj = SHA256.new(hash_bytes)
            
            ok = ecdsa_verify(hash_to_verify_obj, sig_bytes, cust_pub_key)
            print("ID:", tx_id, "Signature valid (Non-repudiation confirmed):", bool(ok))
        except Exception as e:
            print("ID:", tx_id, "Verification error:", str(e))

def show_public_keys():
    if store.keys["merchant_rsa_enc"] is None or store.keys["customer_ecdsa_sig"] is None:
        print("Keys not ready.")
        return
        
    merch_pub_n = store.keys["merchant_rsa_enc"]["public_key"].n
    cust_pub_point = store.keys["customer_ecdsa_sig"]["public_key"].pointQ
    
    print("Customer ECDSA Public Key (P-256):")
    print("  Qx:", short_hex(cust_pub_point.x))
    print("  Qy:", short_hex(cust_pub_point.y))
    print("Merchant RSA Public Modulus n (bits):", merch_pub_n.bit_length())
    print("  n:", short_hex(merch_pub_n))

# --------------- Menus (Identical to your provided code) ---------------

def main_menu():
    while True:
        print("\n" + "=" * 20)
        print("Secure Transaction System")
        print("Algorithms: RSA-2048, ECDSA-P256, SHA-256")
        print("=" * 20)
        print("Select role:")
        print("1. Customer")
        print("2. Merchant")
        print("3. Auditor")
        print("4. Show public keys")
        print("5. Exit")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            customer_menu()
        elif choice == "2":
            merchant_menu()
        elif choice == "3":
            auditor_menu()
        elif choice == "4":
            show_public_keys()
        elif choice == "5":
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")

def customer_menu():
    while True:
        print("\n--- Customer Menu ---")
        print("1. Encrypt, sign, and send payment")
        print("2. View past transactions")
        print("3. Back")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            customer_create_and_send()
        elif choice == "2":
            customer_view_history()
        elif choice == "3":
            return
        else:
            print("Invalid choice.")

def merchant_menu():
    while True:
        print("\n--- Merchant Menu ---")
        print("1. Process all pending transactions")
        print("2. Show processed records")
        print("3. Back")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            merchant_process_all()
        elif choice == "2":
            merchant_show_processed()
        elif choice == "3":
            return
        else:
            print("Invalid choice.")

def auditor_menu():
    while True:
        print("\n--- Auditor Menu ---")
        print("1. View hashed payment records (Confidentiality check)")
        print("2. Verify ECDSA signatures on records (Non-repudiation check)")
        print("3. Back")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            auditor_view_hashed_records()
        elif choice == "2":
            auditor_verify_signatures()
        elif choice == "3":
            return
        else:
            print("Invalid choice.")

def init_keys():
    print("Generating keys. This may take a moment...")
    # Merchant key for encryption [cite: 419]
    store.keys["merchant_rsa_enc"] = generate_rsa_keys(bits=2048)
    # Customer key for signing 
    store.keys["customer_ecdsa_sig"] = generate_ecdsa_keys()
    print("Keys ready.")
    print("Customer has ECDSA signing key (keeps private, shares public).")
    print("Merchant has RSA encryption key (keeps private, shares public).")

if __name__ == "__main__":
    try:
        init_keys()
        main_menu()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
