from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
import json

class SymmetricSearchableIndex:
    """Implements a simple, secure SSE index. [cite: 1030]"""
    def __init__(self, key):
        if len(key) < 32:
            raise ValueError("Key must be at least 32 bytes.")
        # Split key for different purposes
        self.hmac_key = key[:16]
        self.aes_key = key[16:]
        self.encrypted_index = {}
        print("SSE Index initialized.")

    def _get_deterministic_key(self, keyword):
        """Creates a deterministic, unguessable index key for a keyword."""
        return HMAC.new(self.hmac_key, keyword.lower().encode(), SHA256).hexdigest()

    def build_index(self, documents):
        """Builds an inverted index from a dict of documents."""
        # 1. Create a local, plaintext inverted index
        temp_index = {}
        for doc_id, doc_text in documents.items():
            words = set(doc_text.lower().split()) # Use set for unique words
            for word in words:
                if word not in temp_index:
                    temp_index[word] = []
                temp_index[word].append(doc_id)
        
        # 2. Encrypt the index
        for keyword, doc_id_list in temp_index.items():
            # Key: Deterministic hash of the keyword
            index_key = self._get_deterministic_key(keyword)
            
            # Value: Encrypted list of document IDs
            aes_cipher = AES.new(self.aes_key, AES.MODE_GCM)
            nonce = aes_cipher.nonce
            # We must serialize the list (e.g., to JSON)
            data_to_encrypt = json.dumps(doc_id_list).encode()
            ciphertext, tag = aes_cipher.encrypt_and_digest(data_to_encrypt)
            
            # Store the encrypted value
            self.encrypted_index[index_key] = (nonce.hex(), tag.hex(), ciphertext.hex())
        
        print(f"Index built. {len(temp_index)} keywords, {len(self.encrypted_index)} encrypted entries.")

    def search(self, query):
        """Searches the encrypted index for a query. [cite: 1078, 1153]"""
        # 1. Generate the same deterministic key for the query
        query_key = self._get_deterministic_key(query)
        
        # 2. Check if the key exists in the index
        if query_key not in self.encrypted_index:
            return [] # No results
            
        # 3. Decrypt the value
        try:
            nonce, tag, ciphertext = self.encrypted_index[query_key]
            aes_cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=bytes.fromhex(nonce))
            decrypted_data = aes_cipher.decrypt_and_verify(bytes.fromhex(ciphertext), bytes.fromhex(tag))
            
            # 4. De-serialize the list
            doc_id_list = json.loads(decrypted_data.decode())
            return doc_id_list
        except (ValueError, KeyError):
            print(f"Error decrypting index for query '{query}'! (Tampered?)")
            return []

if __name__ == "__main__":
    # Lab 8, Q1 data [cite: 1148]
    documents = {
        "doc1": "this is a document with some words",
        "doc2": "another document with different words",
        "doc3": "yet another document with some common words",
        "doc4": "python is a great programming language",
        "doc5": "this lab is about searchable encryption",
        "doc6": "a test document for python and aes",
    }
    
    # 1. Generate a master key
    master_key = get_random_bytes(32) # 256-bit key
    
    # 2. Create and build the index
    sse = SymmetricSearchableIndex(master_key)
    sse.build_index(documents)
    
    # 3. Search for "document"
    query1 = "document"
    results1 = sse.search(query1)
    print(f"\nSearch results for '{query1}': {results1}")
    
    # 4. Search for "python"
    query2 = "python"
    results2 = sse.search(query2)
    print(f"Search results for '{query2}': {results2}")
    
    # 5. Search for "secret" (no results)
    query3 = "secret"
    results3 = sse.search(query3)
    print(f"Search results for '{query3}': {results3}")
