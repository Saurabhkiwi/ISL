import sys
import json
import hashlib
from phe import paillier

# --- Helper functions (from Lab 8, Ex 2 solution) ---
def word_to_int(word: str) -> int:
    hash_bytes = hashlib.sha256(word.lower().encode('utf-8')).digest()
    return int.from_bytes(hash_bytes, 'big')

DOC_ID_BYTE_SIZE = 16
def doc_id_to_int(doc_id: str) -> int:
    padded_bytes = doc_id.encode('utf-8').ljust(DOC_ID_BYTE_SIZE, b'\x00')
    return int.from_bytes(padded_bytes, 'big')

def int_to_doc_id(doc_int: int) -> str:
    try:
        padded_bytes = doc_int.to_bytes(DOC_ID_BYTE_SIZE, 'big')
        return padded_bytes.rstrip(b'\x00').decode('utf-8')
    except (OverflowError, UnicodeDecodeError):
        return "[Decryption Error]"

# --- PKSE Index Class (Paillier Homomorphic) ---
class PublicKeySearchableIndex_Paillier:
    def __init__(self, key_size=1024):
        print(f"Generating {key_size}-bit Paillier key pair...")
        self.public_key, self.private_key = paillier.generate_paillier_keypair(n_length=key_size)
        # Index Format: List of tuples [ (E(word_int), [E(doc_id_int1), E(doc_id_int2), ...]), ... ]
        self.encrypted_index = []
        print("PKSE Index (Paillier Homomorphic) initialized.")

    def build_index(self, documents: dict):
        """Builds the encrypted index using Paillier."""
        print("Building plaintext inverted index...")
        plaintext_index = {}
        for doc_id, content in documents.items():
            words = set(content.lower().split())
            for word in words:
                if word not in plaintext_index:
                    plaintext_index[word] = []
                plaintext_index[word].append(doc_id)

        print("Encrypting index with Paillier...")
        self.encrypted_index = []
        for word, doc_ids in plaintext_index.items():
            enc_word = self.public_key.encrypt(word_to_int(word))
            enc_doc_id_list = [self.public_key.encrypt(doc_id_to_int(doc_id)) for doc_id in doc_ids]
            self.encrypted_index.append( (enc_word, enc_doc_id_list) )
        print(f"Encrypted index created with {len(self.encrypted_index)} entries.")

    def generate_search_trapdoor(self, query: str):
        """Generates the encrypted query (trapdoor) for searching."""
        query_int = word_to_int(query)
        return self.public_key.encrypt(query_int)

    def search(self, encrypted_query_trapdoor) -> list:
        """
        Server-side search using homomorphic subtraction.
        Returns a list of *encrypted* document ID lists for potential matches.
        """
        print("Iterating encrypted index and homomorphically checking for '0'...")
        potential_matches = []
        for encrypted_word, encrypted_doc_id_list in self.encrypted_index:
            # Homomorphic check: E(query) - E(word) = E(query - word)
            encrypted_difference = encrypted_query_trapdoor - encrypted_word
            potential_matches.append( (encrypted_difference, encrypted_doc_id_list) )
        
        # Server returns ALL potential matches (difference + encrypted IDs)
        # The client must decrypt the difference to find the real match.
        print(f"Returning {len(potential_matches)} potential matches for client decryption.")
        return potential_matches

    def decrypt_results(self, potential_matches: list) -> list:
        """Client-side decryption to find the actual match and decrypt doc IDs."""
        print("Client decrypting potential matches...")
        for enc_diff, enc_doc_ids in potential_matches:
            difference = self.private_key.decrypt(enc_diff)
            if difference == 0:
                print("Match found!")
                decrypted_ids = [int_to_doc_id(self.private_key.decrypt(enc_id))
                                 for enc_id in enc_doc_ids]
                return decrypted_ids
        print("No match found after decryption.")
        return []

# --- Main Demonstration ---
if __name__ == "__main__":
    print("\n--- PKSE Simulation (Paillier Homomorphic Search) ---")

    # 1. Initialize Index (generates keys)
    pkse_index = PublicKeySearchableIndex_Paillier(key_size=1024)

    # 2. Documents
    documents = {
        "docA": "report status critical system alert",
        "docB": "log file analysis system error",
        "docC": "security alert critical vulnerability found",
        "docD": "system performance analysis report"
    }

    # 3. Build Index
    pkse_index.build_index(documents)

    # 4. Search
    query = "critical"
    print(f"\n--- Searching for: '{query}' ---")

    # Client generates trapdoor
    trapdoor = pkse_index.generate_search_trapdoor(query)
    print("Client generated encrypted search trapdoor.")

    # Server performs search (doesn't know 'critical')
    potential_results = pkse_index.search(trapdoor)

    # Client decrypts results
    decrypted_ids = pkse_index.decrypt_results(potential_results)
    print(f"Client decrypted results: {decrypted_ids}")
