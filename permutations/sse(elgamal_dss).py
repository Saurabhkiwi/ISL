import sys
import json
import time
import hmac
from Crypto.PublicKey import DSA, ElGamal
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import number

# =====================================================================
# 1. DSA SIGNING FUNCTIONS (from Lab 6)
# =====================================================================

def generate_dsa_keys(bits=2048):
    key = DSA.generate(bits)
    return key.publickey(), key # public_key, private_key

def dsa_sign(private_key, hash_obj):
    signer = DSS.new(private_key, 'fips-186-3')
    return signer.sign(hash_obj)

def dsa_verify(public_key, hash_obj, signature):
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

# =====================================================================
# 2. HASHING FUNCTION (from Lab 5)
# =====================================================================

def hash_sha256(data_string: str) -> SHA256.SHA256Hash:
    return SHA256.new(data_string.encode('utf-8'))

# =====================================================================
# 3. AES & SSE FUNCTIONS (from Labs 2 & 8)
# =====================================================================

def aes_gcm_encrypt(key, data_bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    return {
        "nonce": cipher.nonce.hex(),
        "tag": cipher.encrypt_and_digest(data_bytes)[1].hex(),
        "ciphertext": cipher.encrypt_and_digest(data_bytes)[0].hex() # Re-encrypt for simplicity here
    }

def aes_gcm_decrypt(key, enc_dict):
    try:
        nonce = bytes.fromhex(enc_dict["nonce"])
        tag = bytes.fromhex(enc_dict["tag"])
        ciphertext = bytes.fromhex(enc_dict["ciphertext"])
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    except (ValueError, KeyError, TypeError) as e:
        print(f"[AES Decrypt Error] {e}")
        return None

def get_sse_search_token(hmac_key, keyword):
    return hmac.new(hmac_key, keyword.lower().encode(), SHA256).hexdigest()

# =====================================================================
# 4. ELGAMAL MULTIPLICATIVE FUNCTIONS (from Lab 7 Add'l Q1a)
# =====================================================================

def generate_elgamal_keys(bits=1024):
    key = ElGamal.generate(bits, get_random_bytes)
    return key.publickey(), key # public_key, private_key

def elgamal_encrypt(pub_key, m_int):
    """Manually encrypts integer 'm_int'."""
    p, g, y = pub_key.p, pub_key.g, pub_key.y
    k = number.getRandomRange(1, p - 1)
    c1 = pow(g, k, p)
    c2 = (m_int * pow(y, k, p)) % p
    # Store as hex for transport/storage
    return (hex(c1), hex(c2))

def elgamal_decrypt(priv_key, c1_hex, c2_hex):
    """Manually decrypts ElGamal ciphertext."""
    try:
        c1 = int(c1_hex, 16)
        c2 = int(c2_hex, 16)
        p, x = priv_key.p, priv_key.x
        s = pow(c1, x, p)
        s_inv = number.inverse(s, p)
        m = (c2 * s_inv) % p
        return m
    except (ValueError, TypeError) as e:
        print(f"[ElGamal Decrypt Error] {e}")
        return None

def elgamal_homomorphic_multiply(pub_key, enc_pair1, enc_pair2):
    """Performs E(m1)*E(m2) = E(m1*m2)"""
    p = pub_key.p
    c1a, c2a = int(enc_pair1[0], 16), int(enc_pair1[1], 16)
    c1b, c2b = int(enc_pair2[0], 16), int(enc_pair2[1], 16)
    
    c1_prod = (c1a * c1b) % p
    c2_prod = (c2a * c2b) % p
    return (hex(c1_prod), hex(c2_prod))

# =====================================================================
# 5. SIMULATION CLASSES & DATA
# =====================================================================

class DocumentServer:
    """Acts as the SERVER."""
    def __init__(self):
        self.name = "Document Server"
        self.owner_public_keys = {}
        self.master_sse_index = {}
        self.document_db = {} # {doc_id: {"enc_doc": {...}, "enc_version": (c1,c2)}}
        self.upload_log = []
        print(f"[{self.name}] Initialized.")

    def register_owner(self, owner):
        self.owner_public_keys[owner.name] = owner.dsa_public_key
        print(f"[{self.name}] Registered Owner: {owner.name}")

    def submit_document(self, owner_name, summary_string, signature, sse_index, enc_doc_payload, enc_version_pair, doc_id):
        print(f"\n[{self.name}] Received document {doc_id} from {owner_name}.")
        owner_pub_key = self.owner_public_keys.get(owner_name)
        if not owner_pub_key:
            print(f"[{self.name}] ERROR: Owner '{owner_name}' not registered.")
            return

        hash_to_verify = hash_sha256(summary_string)
        is_valid_signature = dsa_verify(owner_pub_key, hash_to_verify, signature)
        
        log_entry = json.loads(summary_string)
        log_entry["Signature Verification Result"] = is_valid_signature
        
        if not is_valid_signature:
            print(f"[{self.name}] SIGNATURE FAILED for {doc_id}. Submission rejected.")
            self.upload_log.append(log_entry)
            return
            
        print(f"[{self.name}] Signature VERIFIED.")
        
        # Store data
        self.document_db[doc_id] = {
            "enc_doc": enc_doc_payload,
            "enc_version": enc_version_pair
        }
        # Merge SSE index
        for token, rec_id_list in sse_index.items():
            if token not in self.master_sse_index:
                self.master_sse_index[token] = []
            # Ensure unique IDs per token
            for rid in rec_id_list:
                if rid not in self.master_sse_index[token]:
                    self.master_sse_index[token].append(rid)
                    
        print(f"[{self.name}] Document {doc_id} stored and index merged.")
        self.upload_log.append(log_entry)

    def search_documents(self, search_token):
        print(f"\n[{self.name}] Searching index for token: {search_token[:10]}...")
        found_ids = self.master_sse_index.get(search_token, [])
        print(f"[{self.name}] Found {len(found_ids)} matching document ID(s): {found_ids}")
        return found_ids

    def get_encrypted_version(self, doc_id):
        if doc_id in self.document_db:
            return self.document_db[doc_id]["enc_version"]
        return None

    def get_encrypted_document(self, doc_id):
         if doc_id in self.document_db:
            return self.document_db[doc_id]["enc_doc"]
         return None

    def print_upload_log(self):
        print("\n" + "="*50)
        print("         SERVER UPLOAD LOG")
        print("="*50)
        print(json.dumps(self.upload_log, indent=2))
        print("="*50)

class DocumentOwner:
    """Acts as a CLIENT (Uploader)."""
    def __init__(self, name):
        self.name = name
        self.dsa_public_key, self.dsa_private_key = generate_dsa_keys()
        self.doc_counter = 0
        print(f"[{self.name} (Client)] DSA Signing Keys Generated.")
        
    def upload_document(self, doc_string, keywords, aes_key, hmac_key, elgamal_pk):
        self.doc_counter += 1
        doc_id = f"{self.name.replace(' ', '_')}_doc{self.doc_counter}"
        
        print(f"\n[{self.name}] Uploading document {doc_id}...")
        
        # 1. Encrypt Document (AES)
        enc_doc_payload = aes_gcm_encrypt(aes_key, doc_string.encode('utf-8'))
        
        # 2. Encrypt Initial Version (ElGamal)
        initial_version = 1
        enc_version_pair = elgamal_encrypt(elgamal_pk, initial_version)
        
        # 3. Create SSE Index
        sse_index = {}
        for kw in keywords:
            token = get_sse_search_token(hmac_key, kw)
            sse_index[token] = [doc_id] # First version
            
        # 4. Create and Sign Summary
        summary_data = {"owner": self.name, "doc_id": doc_id, "timestamp": time.time()}
        summary_string = json.dumps(summary_data, sort_keys=True)
        hash_obj = hash_sha256(summary_string)
        signature = dsa_sign(self.dsa_private_key, hash_obj)
        
        print(f"[{self.name}] Document {doc_id} encrypted and signed.")
        # Return all parts to "send"
        return summary_string, signature, sse_index, enc_doc_payload, enc_version_pair, doc_id

class Collaborator:
    """Acts as a CLIENT (Searcher/Updater)."""
    def __init__(self, name):
        self.name = name
        print(f"[{self.name} (Client)] Ready.")
        
    def search_and_update_version(self, server, query, update_factor, hmac_key, elgamal_pk, elgamal_sk, aes_key):
        print(f"\n[{self.name}] Searching for keyword: '{query}'")
        search_token = get_sse_search_token(hmac_key, query)
        doc_ids = server.search_documents(search_token)
        
        if not doc_ids:
            return
            
        # Let's process the first result
        target_doc_id = doc_ids[0]
        print(f"[{self.name}] Found document: {target_doc_id}")
        
        # 1. Get Encrypted Version from Server
        current_enc_version = server.get_encrypted_version(target_doc_id)
        if not current_enc_version:
            print(f"[{self.name}] Could not retrieve version for {target_doc_id}.")
            return
            
        # 2. Homomorphically Multiply Version
        print(f"[{self.name}] Homomorphically multiplying version by factor: {update_factor}")
        # Encrypt the factor
        enc_update_factor = elgamal_encrypt(elgamal_pk, update_factor)
        # Multiply
        new_enc_version = elgamal_homomorphic_multiply(elgamal_pk, current_enc_version, enc_update_factor)
        
        # 3. Decrypt the *new* version locally to verify
        decrypted_new_version = elgamal_decrypt(elgamal_sk, new_enc_version[0], new_enc_version[1])
        print(f"[{self.name}] Decrypted new version number (locally): {decrypted_new_version}")
        # (In a real system, might send new_enc_version back to server)
        
        # 4. Get and Decrypt Document
        enc_doc_payload = server.get_encrypted_document(target_doc_id)
        if enc_doc_payload:
            print(f"[{self.name}] Decrypting document {target_doc_id}...")
            decrypted_doc = aes_gcm_decrypt(aes_key, enc_doc_payload)
            if decrypted_doc:
                print(f"[{self.name}] Decrypted Document Content:\n'''\n{decrypted_doc}\n'''")
            else:
                print(f"[{self.name}] Failed to decrypt document {target_doc_id}.")
        else:
             print(f"[{self.name}] Could not retrieve document {target_doc_id}.")


# --- Global Objects & Shared Keys ---
server = DocumentServer()
owner1 = DocumentOwner("Alice")
collab1 = Collaborator("Bob")

# Keys shared between Owner and Collaborator (Server NEVER sees these)
AES_KEY = get_random_bytes(16)
HMAC_KEY = get_random_bytes(16)
ELGAMAL_PK, ELGAMAL_SK = generate_elgamal_keys() # Owner has SK, Collab needs PK

# =====================================================================
# 6. MENU-DRIVEN LOGIC
# =====================================================================

def init_registration():
    print("\n--- Initializing Owner Registration ---")
    server.register_owner(owner1)
    print("---------------------------------------")

def owner_menu():
    print("\n--- Document Owner Menu (Client) ---")
    try:
        doc_content = input("Enter document content: ")
        keywords_str = input("Enter keywords (comma-separated): ")
        keywords = [kw.strip().lower() for kw in keywords_str.split(',')]
        
        if not doc_content or not keywords:
            print("Content and keywords cannot be empty.")
            return
            
        # Upload the document
        summary, sig, index, payload, enc_ver, doc_id = owner1.upload_document(
            doc_content, keywords, AES_KEY, HMAC_KEY, ELGAMAL_PK
        )
        # "Send" to server
        server.submit_document(owner1.name, summary, sig, index, payload, enc_ver, doc_id)
        
    except Exception as e:
        print(f"An error occurred: {e}")

def collaborator_menu():
    print("\n--- Collaborator Menu (Client) ---")
    query = input("Enter search keyword: ")
    if not query: return
    
    try:
        update_factor = int(input("Enter version update factor (integer, e.g., 3): "))
    except ValueError:
        print("Invalid factor. Must be an integer.")
        return
        
    collab1.search_and_update_version(server, query, update_factor, HMAC_KEY, ELGAMAL_PK, ELGAMAL_SK, AES_KEY)

def server_menu():
    print("\n--- Document Server Menu (Server) ---")
    print("1. Display Upload Log")
    print("9. Back to Main Menu")
    choice = input("Enter choice: ").strip()
    
    if choice == "1":
        server.print_upload_log()
    elif choice == "9":
        return
    else:
        print("Invalid choice.")

def main():
    init_registration()
    while True:
        print("\n" + "="*40)
        print("   Secure Document Version System")
        print("="*40)
        print("Select Your Role:")
        print("1. Document Owner (Upload)")
        print("2. Collaborator (Search & Update)")
        print("3. Document Server (View Log)")
        print("4. Exit")
        
        choice = input("Enter choice: ").strip()
        
        if choice == "1":
            owner_menu()
        elif choice == "2":
            collaborator_menu()
        elif choice == "3":
            server_menu()
        elif choice == "4":
            print("Exiting.")
            sys.exit()
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
