import sys
import json
import time
import hashlib
from phe import paillier
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA1 # Using SHA1 for this combo
from Crypto.Random import get_random_bytes

# --- Paillier PKSE Functions (from previous block) ---
# (generate_paillier_keys, word_to_int, doc_id_to_int, int_to_doc_id)
# (PublicKeySearchableIndex_Paillier class: __init__, build_index, generate_search_trapdoor, search, decrypt_results)
# --- Note: Copy the Paillier PKSE code block here ---
def word_to_int(word: str) -> int: hash_bytes = hashlib.sha256(word.lower().encode('utf-8')).digest(); return int.from_bytes(hash_bytes, 'big')
DOC_ID_BYTE_SIZE = 16
def doc_id_to_int(doc_id: str) -> int: padded_bytes = doc_id.encode('utf-8').ljust(DOC_ID_BYTE_SIZE, b'\x00'); return int.from_bytes(padded_bytes, 'big')
def int_to_doc_id(doc_int: int) -> str:
    try: padded_bytes = doc_int.to_bytes(DOC_ID_BYTE_SIZE, 'big'); return padded_bytes.rstrip(b'\x00').decode('utf-8')
    except (OverflowError, UnicodeDecodeError): return "[Decryption Error]"
def generate_paillier_keys(bits=1024): pk, sk = paillier.generate_paillier_keypair(n_length=bits); return pk, sk

class PublicKeySearchableIndex_Paillier:
    def __init__(self, key_size=1024):
        print(f"Generating {key_size}-bit Paillier key pair..."); self.public_key, self.private_key = generate_paillier_keys(key_size); self.encrypted_index = []; print("PKSE Index (Paillier Homomorphic) initialized.")
    def build_index(self, documents: dict):
        print("Building plaintext inverted index..."); plaintext_index = {};
        for doc_id, content in documents.items(): words = set(content.lower().split());
        for word in words:
            if word not in plaintext_index: plaintext_index[word] = []
            plaintext_index[word].append(doc_id)
        print("Encrypting index with Paillier..."); self.encrypted_index = []
        for word, doc_ids in plaintext_index.items(): enc_word = self.public_key.encrypt(word_to_int(word)); enc_doc_id_list = [self.public_key.encrypt(doc_id_to_int(doc_id)) for doc_id in doc_ids]; self.encrypted_index.append( (enc_word, enc_doc_id_list) )
        print(f"Encrypted index created with {len(self.encrypted_index)} entries.")
    def generate_search_trapdoor(self, query: str): query_int = word_to_int(query); return self.public_key.encrypt(query_int)
    def search(self, encrypted_query_trapdoor) -> list:
        print("Iterating encrypted index and homomorphically checking for '0'..."); potential_matches = []
        for encrypted_word, encrypted_doc_id_list in self.encrypted_index: encrypted_difference = encrypted_query_trapdoor - encrypted_word; potential_matches.append( (encrypted_difference, encrypted_doc_id_list) )
        print(f"Returning {len(potential_matches)} potential matches for client decryption."); return potential_matches
    def decrypt_results(self, potential_matches: list) -> list:
        print("Client decrypting potential matches...");
        for enc_diff, enc_doc_ids in potential_matches: difference = self.private_key.decrypt(enc_diff)
        if difference == 0: print("Match found!"); decrypted_ids = [int_to_doc_id(self.private_key.decrypt(enc_id)) for enc_id in enc_doc_ids]; return decrypted_ids
        print("No match found after decryption."); return []


# --- DSA Signing Functions ---
def generate_dsa_keys(bits=2048):
    key = DSA.generate(bits)
    return key.publickey(), key

def dsa_sign(private_key, hash_obj):
    signer = DSS.new(private_key, 'fips-186-3')
    return signer.sign(hash_obj)

def dsa_verify(public_key, hash_obj, signature):
    verifier = DSS.new(public_key, 'fips-186-3')
    try: verifier.verify(hash_obj, signature); return True
    except (ValueError, TypeError): return False

# --- Hashing Function (SHA1) ---
def hash_sha1(data_string: str) -> SHA1.SHA1Hash:
    return SHA1.new(data_string.encode('utf-8'))


# --- Simulation Classes ---
class Server_Combo:
    def __init__(self, pkse_index: PublicKeySearchableIndex_Paillier):
        self.name = "Combined Server"
        self.pkse_index = pkse_index # Holds the Paillier keys and index
        self.client_dsa_keys = {}
        self.submission_log = []
        print(f"[{self.name}] Initialized.")

    def register_client(self, client):
        self.client_dsa_keys[client.name] = client.dsa_public_key
        print(f"[{self.name}] Registered Client: {client.name}")

    def submit_data(self, client_name, summary_string, signature):
        print(f"\n[{self.name}] Received submission from {client_name}.")
        client_pub_key = self.client_dsa_keys.get(client_name)
        if not client_pub_key: print(f"ERROR: Client {client_name} not registered."); return

        hash_to_verify = hash_sha1(summary_string) # Using SHA1
        is_valid = dsa_verify(client_pub_key, hash_to_verify, signature)

        log_entry = json.loads(summary_string)
        log_entry["Signature Verification (DSA+SHA1)"] = is_valid
        self.submission_log.append(log_entry)

        if is_valid: print(f"Signature VERIFIED for {client_name}.")
        else: print(f"Signature FAILED for {client_name}.")

    def perform_pkse_search(self, encrypted_trapdoor):
        # Delegate search to the PKSE index object
        return self.pkse_index.search(encrypted_trapdoor)

    def print_log(self):
        print("\n--- Server Submission Log ---"); print(json.dumps(self.submission_log, indent=2))

class Client_Combo:
    def __init__(self, name, pkse_index: PublicKeySearchableIndex_Paillier):
        self.name = name
        self.dsa_public_key, self.dsa_private_key = generate_dsa_keys()
        self.pkse_index = pkse_index # Client needs access to encrypt/decrypt
        print(f"[{self.name} (Client)] DSA Keys Generated.")

    def create_submission(self, data_dict):
        print(f"\n[{self.name}] Creating submission...")
        summary_string = json.dumps(data_dict, sort_keys=True)
        hash_obj = hash_sha1(summary_string) # Using SHA1
        signature = dsa_sign(self.dsa_private_key, hash_obj)
        print("Data summary hashed (SHA1) and signed (DSA).")
        return summary_string, signature

    def search_and_decrypt(self, query):
        print(f"\n[{self.name}] Searching for '{query}'...")
        trapdoor = self.pkse_index.generate_search_trapdoor(query)
        # Assume trapdoor is sent to server...
        potential_results = server.perform_pkse_search(trapdoor) # Call server method
        # ...Server returns results, client decrypts
        decrypted_ids = self.pkse_index.decrypt_results(potential_results)
        print(f"Decrypted search results for '{query}': {decrypted_ids}")
        return decrypted_ids

# --- Main Simulation ---
if __name__ == "__main__":
    print("\n--- Combination: PKSE (Paillier) + DSA Signature + SHA1 Hash ---")

    # 1. Setup Server with PKSE Index
    pkse_index_global = PublicKeySearchableIndex_Paillier(key_size=1024)
    server = Server_Combo(pkse_index_global)

    # 2. Setup Clients (need access to PKSE object for demo)
    client1 = Client_Combo("Client_Alpha", pkse_index_global)
    client2 = Client_Combo("Client_Beta", pkse_index_global)

    # 3. Register Clients
    server.register_client(client1)
    server.register_client(client2)

    # 4. Build PKSE Index (can be done by server or clients)
    docs = {"id1": "confidential report alpha", "id2": "beta project details", "id3": "alpha team status"}
    pkse_index_global.build_index(docs) # Build the index

    # 5. Client 1 Submits Data
    data1 = {"user": client1.name, "action": "submit", "doc_id": "id1"}
    summary1, sig1 = client1.create_submission(data1)
    server.submit_data(client1.name, summary1, sig1)

    # 6. Client 2 Submits Data
    data2 = {"user": client2.name, "action": "update", "doc_id": "id2"}
    summary2, sig2 = client2.create_submission(data2)
    server.submit_data(client2.name, summary2, sig2)

    # 7. Client 1 Searches
    client1.search_and_decrypt("alpha")
    client1.search_and_decrypt("beta")
    client1.search_and_decrypt("gamma") # Not found

    # 8. Server Log
    server.print_log()
