import sys
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# --- RSA Encryption/Decryption Functions ---
def generate_rsa_keys(bits=2048):
    key = RSA.generate(bits)
    return key.publickey(), key # public_key, private_key

def rsa_encrypt(public_key, msg_bytes):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(msg_bytes)

def rsa_decrypt(private_key, ciphertext):
    try:
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(ciphertext)
    except (ValueError, TypeError):
        return None

# --- Deterministic "Encryption" for Index Keys (Insecure Simulation) ---
def get_deterministic_index_key(keyword: str) -> str:
    """
    Simulates a deterministic encryption using a hash of the keyword hash.
    WARNING: Not cryptographically secure for real PKSE index keys.
    """
    keyword_hash = SHA256.new(keyword.lower().encode()).digest()
    # Use another hash to make it look "encrypted" deterministically
    index_key = SHA256.new(keyword_hash).hexdigest()
    return index_key

# --- PKSE Index Class ---
class PublicKeySearchableIndex_RSA_Deterministic:
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key
        # Index format: { deterministic_keyword_token: rsa_oaep_encrypted(json([doc_id1, ...])) }
        self.encrypted_index = {}
        print("PKSE Index (RSA Deterministic Simulation) initialized.")

    def build_index(self, documents):
        """Builds the encrypted index."""
        temp_index = {}
        for doc_id, doc_text in documents.items():
            words = set(doc_text.lower().split())
            for word in words:
                if word not in temp_index:
                    temp_index[word] = []
                temp_index[word].append(doc_id)

        print("Encrypting index...")
        for keyword, doc_id_list in temp_index.items():
            # Key: Deterministic token derived from keyword
            index_key_token = get_deterministic_index_key(keyword)

            # Value: Securely encrypted list of document IDs
            data_to_encrypt = json.dumps(doc_id_list).encode()
            encrypted_value = rsa_encrypt(self.public_key, data_to_encrypt)

            # Store as hex for readability
            self.encrypted_index[index_key_token] = encrypted_value.hex()

        print(f"Encrypted index built with {len(self.encrypted_index)} entries.")

    def generate_search_token(self, query: str) -> str:
        """Generates the token needed to search the index."""
        return get_deterministic_index_key(query)

    def search(self, search_token: str) -> list:
        """
        Server-side search: Finds matching encrypted value for the token.
        Returns the *encrypted* list of doc IDs.
        """
        print(f"Searching index for token: {search_token[:10]}...")
        encrypted_value_hex = self.encrypted_index.get(search_token)
        if encrypted_value_hex:
            print("Match found (returning encrypted doc ID list).")
            return bytes.fromhex(encrypted_value_hex) # Return bytes
        else:
            print("No match found for this token.")
            return None

    def decrypt_results(self, encrypted_result_bytes: bytes) -> list:
        """Client-side decryption of search results."""
        if not encrypted_result_bytes:
            return []
        decrypted_data = rsa_decrypt(self.private_key, encrypted_result_bytes)
        if decrypted_data:
            try:
                doc_id_list = json.loads(decrypted_data.decode())
                return doc_id_list
            except (json.JSONDecodeError, UnicodeDecodeError):
                print("Error decoding decrypted results.")
                return []
        else:
            print("Failed to decrypt search results.")
            return []

# --- Main Demonstration ---
if __name__ == "__main__":
    print("--- PKSE Simulation (RSA Deterministic Hashing) ---")

    # 1. Generate keys (user holds these)
    pk, sk = generate_rsa_keys()

    # 2. Initialize Index (pass keys)
    pkse_index = PublicKeySearchableIndex_RSA_Deterministic(pk, sk)

    # 3. Documents
    documents = {
        "doc1": "patient record flu symptoms",
        "doc2": "research paper cryptography security",
        "doc3": "medical history high fever flu",
        "doc4": "notes on searchable encryption security"
    }

    # 4. Build Index
    pkse_index.build_index(documents)

    # 5. Search (Client generates token, Server searches, Client decrypts)
    query = "flu"
    print(f"\n--- Searching for: '{query}' ---")

    # Client generates token
    search_token = pkse_index.generate_search_token(query)
    print(f"Client generated search token: {search_token[:10]}...")

    # Server performs search (doesn't know 'flu')
    encrypted_results = pkse_index.search(search_token)

    # Client decrypts results
    if encrypted_results:
        decrypted_ids = pkse_index.decrypt_results(encrypted_results)
        print(f"Client decrypted results: {decrypted_ids}")
    else:
        print("Client received no results.")

    # Search for something not present
    query2 = "headache"
    print(f"\n--- Searching for: '{query2}' ---")
    search_token2 = pkse_index.generate_search_token(query2)
    encrypted_results2 = pkse_index.search(search_token2)
    decrypted_ids2 = pkse_index.decrypt_results(encrypted_results2)
    print(f"Client decrypted results: {decrypted_ids2}")
