import sys
import json
import time
import hmac
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# =====================================================================
# 1. RSA SIGNING FUNCTIONS (from Lab 6)
# =====================================================================

def generate_rsa_signing_keys(bits=2048):
    key = RSA.generate(bits)
    return key.publickey(), key # public_key, private_key

def rsa_pss_sign(private_key, hash_obj):
    signer = pss.new(private_key)
    return signer.sign(hash_obj)

def rsa_pss_verify(public_key, hash_obj, signature):
    verifier = pss.new(public_key)
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
# [cite_start]3. AES & SSE FUNCTIONS (from Labs 2 & 8) [cite: 1021, 1030]
# =====================================================================

def aes_gcm_encrypt(key, data_bytes):
    """Encrypts data using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    # Return as hex strings for storage
    return {
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex()
    }

def aes_gcm_decrypt(key, enc_dict):
    """Decrypts an AES-GCM payload."""
    try:
        nonce = bytes.fromhex(enc_dict["nonce"])
        tag = bytes.fromhex(enc_dict["tag"])
        ciphertext = bytes.fromhex(enc_dict["ciphertext"])
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError):
        return None # Decryption failed

def get_sse_search_token(hmac_key, keyword):
    [cite_start]"""Generates the deterministic index key (search token). [cite: 1023]"""
    return hmac.new(hmac_key, keyword.lower().encode(), SHA256).hexdigest()

# =====================================================================
# 4. SIMULATION CLASSES & DATA
# =====================================================================

class RecordsServer:
    """Acts as the SERVER."""
    def __init__(self):
        self.name = "Central Records Server"
        self.hospital_public_keys = {}
        # The server STORES the SSE index, but cannot read it
        self.master_sse_index = {} # { "token": ["record_id_1", "record_id_2"] }
        # The server STORES the records, but cannot read them
        self.encrypted_record_db = {} # { "record_id": {aes_payload} }
        self.submission_log = []
        print(f"[{self.name}] Initialized.")

    def register_hospital(self, hospital):
        self.hospital_public_keys[hospital.name] = hospital.public_key
        print(f"[{self.name}] Registered Hospital: {hospital.name}")
        
    def submit_record(self, hospital_name, summary_string, signature, sse_index, enc_record_payload, record_id):
        """Receives and processes a new record from a hospital."""
        print(f"\n[{self.name}] Received record {record_id} from {hospital_name}.")
        
        # 1. Verify Signature
        hospital_pub_key = self.hospital_public_keys.get(hospital_name)
        if not hospital_pub_key:
            print(f"[{self.name}] ERROR: Hospital '{hospital_name}' not registered.")
            return

        hash_to_verify = hash_sha256(summary_string)
        is_valid_signature = rsa_pss_verify(hospital_pub_key, hash_to_verify, signature)
        
        log_entry = json.loads(summary_string)
        log_entry["Signature Verification Result"] = is_valid_signature
        
        if not is_valid_signature:
            print(f"[{self.name}] SIGNATURE FAILED for {record_id}. Record rejected.")
            self.submission_log.append(log_entry)
            return
            
        print(f"[{self.name}] Signature VERIFIED.")
        
        # 2. Store Record and Index
        self.encrypted_record_db[record_id] = enc_record_payload
        
        # Merge the new index into the master index
        for token, rec_id_list in sse_index.items():
            if token not in self.master_sse_index:
                self.master_sse_index[token] = []
            self.master_sse_index[token].extend(rec_id_list)
            
        print(f"[{self.name}] Record {record_id} stored and index merged.")
        self.submission_log.append(log_entry)

    def search_records(self, search_token):
        [cite_start]"""Performs a search using only the received token. [cite: 1025]"""
        print(f"\n[{self.name}] Searching index for token: {search_token[:10]}...")
        # The server doesn't know what "flu" is, only the token
        found_ids = self.master_sse_index.get(search_token, [])
        
        # Server returns the ENCRYPTED records matching the IDs
        encrypted_results = []
        for rec_id in found_ids:
            if rec_id in self.encrypted_record_db:
                encrypted_results.append(self.encrypted_record_db[rec_id])
                
        print(f"[{self.name}] Found {len(encrypted_results)} matching encrypted record(s).")
        return encrypted_results

    def print_submission_log(self):
        print("\n" + "="*50)
        print("         SERVER SUBMISSION LOG")
        print("="*50)
        print(json.dumps(self.submission_log, indent=2))
        print("="*50)

class Hospital:
    """Acts as a CLIENT (data submitter)."""
    def __init__(self, name):
        self.name = name
        self.public_key, self.private_key = generate_rsa_signing_keys()
        self.record_counter = 0
        print(f"[{self.name} (Client)] RSA Signing Keys Generated.")
        
    def create_record(self, record_string, keywords, aes_key, hmac_key):
        """Creates a fully encrypted and signed record package."""
        self.record_counter += 1
        record_id = f"{self.name.replace(' ', '_')}_{self.record_counter}"
        
        print(f"\n[{self.name}] Creating record {record_id}...")
        
        # [cite_start]1. Encrypt the full record [cite: 1021]
        enc_record_payload = aes_gcm_encrypt(aes_key, record_string.encode('utf-8'))
        
        # [cite_start]2. Create the SSE Index [cite: 1023]
        sse_index = {}
        for kw in keywords:
            token = get_sse_search_token(hmac_key, kw)
            if token not in sse_index:
                sse_index[token] = []
            sse_index[token].append(record_id)
            
        # 3. Create and sign the summary
        summary_data = {
            "hospital_name": self.name,
            "record_id": record_id,
            "timestamp": time.time()
        }
        summary_string = json.dumps(summary_data, sort_keys=True)
        hash_obj = hash_sha256(summary_string)
        signature = rsa_pss_sign(self.private_key, hash_obj)
        
        print(f"[{self.name}] Record {record_id} encrypted and signed.")
        return summary_string, signature, sse_index, enc_record_payload, record_id

class Doctor:
    """Acts as a CLIENT (data searcher)."""
    def __init__(self, name):
        self.name = name
        print(f"[{self.name} (Client)] Ready to search.")
        
    def search(self, server, query, aes_key, hmac_key):
        """Generates a token, searches, and decrypts results."""
        print(f"\n[{self.name}] Searching for keyword: '{query}'")
        
        # [cite_start]1. Generate the search token [cite: 1025]
        search_token = get_sse_search_token(hmac_key, query)
        
        # 2. Send *only* the token to the server
        encrypted_results = server.search_records(search_token)
        
        # 3. Decrypt the results locally
        decrypted_records = []
        for payload in encrypted_results:
            dec_record = aes_gcm_decrypt(aes_key, payload)
            if dec_record:
                decrypted_records.append(dec_record)
                
        print(f"[{self.name}] Successfully decrypted {len(decrypted_records)} record(s):")
        for rec in decrypted_records:
            print(f"  -> {rec}")
        return decrypted_records

# --- Global Objects ---
server = RecordsServer()
hospital1 = Hospital("City General Hospital")
doctor1 = Doctor("Dr. Alice")

# --- SHARED SECRET KEYS (Server NEVER sees these) ---
AES_KEY = get_random_bytes(16) # For AES-128
HMAC_KEY = get_random_bytes(16) # For SSE tokens

# =====================================================================
# 5. MENU-DRIVEN LOGIC
# =====================================================================

def init_registration():
    print("\n--- Initializing Hospital Registration ---")
    server.register_hospital(hospital1)
    print("------------------------------------------")

def hospital_menu():
    print("\n--- Hospital Menu (Client) ---")
    try:
        patient_name = input("Enter Patient Name (e.g., John Doe): ")
        condition = input("Enter Condition (e.g., Flu): ")
        record_string = f"Patient: {patient_name}, Condition: {condition}"
        
        # Generate keywords from the data
        keywords = [patient_name, condition] + patient_name.split() + condition.split()
        
        # Create and "send" the record
        summary, sig, index, payload, rec_id = hospital1.create_record(record_string, keywords, AES_KEY, HMAC_KEY)
        server.submit_record(hospital1.name, summary, sig, index, payload, rec_id)
        
    except Exception as e:
        print(f"An error occurred: {e}")

def doctor_menu():
    print("\n--- Doctor Menu (Client) ---")
    query = input("Enter search keyword (e.g., Flu, 'John Doe'): ")
    if not query:
        print("No query entered.")
        return
    doctor1.search(server, query, AES_KEY, HMAC_KEY)

def server_menu():
    print("\n--- Records Server Menu (Server) ---")
    print("1. Display Submission Log")
    print("9. Back to Main Menu")
    choice = input("Enter choice: ").strip()
    
    if choice == "1":
        server.print_submission_log()
    elif choice == "9":
        return
    else:
        print("Invalid choice.")

def main():
    init_registration()
    while True:
        print("\n" + "="*40)
        print("   Secure Medical Records Simulation")
        print("="*40)
        print("Select Your Role:")
        print("1. Hospital (Upload Record)")
        print("2. Doctor (Search Records)")
        print("3. Records Server (View Log)")
        print("4. Exit")
        
        choice = input("Enter choice: ").strip()
        
        if choice == "1":
            hospital_menu()
        elif choice == "2":
            doctor_menu()
        elif choice == "3":
            server_menu()
        elif choice == "4":
            print("Exiting.")
            sys.exit()
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
