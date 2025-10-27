import hashlib
from phe import paillier  # pip install phe

# --- Helper functions to convert strings to/from integers for Paillier ---

def word_to_int(word: str) -> int:
    """
    Deterministically converts a keyword to a large integer
    using a cryptographic hash.
    """
    # Use SHA-256 and convert the 32-byte hash to a single integer
    hash_bytes = hashlib.sha256(word.lower().encode('utf-8')).digest()
    return int.from_bytes(hash_bytes, 'big')

# We need a fixed-size byte representation for doc IDs
DOC_ID_BYTE_SIZE = 16 

def doc_id_to_int(doc_id: str) -> int:
    """
    Deterministically converts a document ID string (like 'doc1')
    to a fixed-size integer.
    """
    # Pad with null bytes to ensure all ints have the same byte length
    padded_bytes = doc_id.encode('utf-8').ljust(DOC_ID_BYTE_SIZE, b'\x00')
    return int.from_bytes(padded_bytes, 'big')

def int_to_doc_id(doc_int: int) -> str:
    """Converts an integer back to a document ID string."""
    try:
        padded_bytes = doc_int.to_bytes(DOC_ID_BYTE_SIZE, 'big')
        # Remove the null-byte padding
        return padded_bytes.rstrip(b'\x00').decode('utf-8')
    except OverflowError:
        return "[Decryption Error: Bad Integer]"
    except UnicodeDecodeError:
        return "[Decryption Error: Bad Bytes]"

# --- 2b. Implement encryption and decryption functions ---
# 
def generate_keys(key_size=1024):
    """Generates Paillier public and private keys."""
    print(f"[KeyGen] Generating {key_size}-bit Paillier key pair...")
    public_key, private_key = paillier.generate_paillier_keypair(n_length=key_size)
    print("[KeyGen] Keys generated.")
    return public_key, private_key

# --- 2c. Create an encrypted index ---
# [cite: 1162]
def create_encrypted_index(documents: dict, public_key: paillier.PaillierPublicKey) -> list:
    """
    Builds an inverted index and encrypts both the keywords (keys)
    and the document IDs (values) using Paillier.
    [cite: 1165]
    """
    print("[Index] Building plaintext inverted index...")
    plaintext_index = {}
    for doc_id, content in documents.items():
        words = set(content.lower().split()) # Use a set for unique words
        for word in words:
            if word not in plaintext_index:
                plaintext_index[word] = []
            plaintext_index[word].append(doc_id)
            
    print("[Index] Encrypting index with Paillier...")
    encrypted_index = []
    # Since keys are encrypted (non-searchable), we use a list of tuples:
    # [ (E(word_hash), [E(doc_id1), E(doc_id2), ...]), ... ]
    for word, doc_ids in plaintext_index.items():
        # Encrypt the keyword (as an int)
        enc_word = public_key.encrypt(word_to_int(word))
        
        # Encrypt the list of document IDs (as ints)
        enc_doc_id_list = [public_key.encrypt(doc_id_to_int(doc_id)) for doc_id in doc_ids]
        
        encrypted_index.append( (enc_word, enc_doc_id_list) )
        
    print(f"[Index] Encrypted index created with {len(encrypted_index)} entries.")
    return encrypted_index

# --- 2d. Implement the search function ---
# [cite: 1166]
def search_encrypted_index(encrypted_index: list, query: str, 
                           public_key: paillier.PaillierPublicKey, 
                           private_key: paillier.PaillierPrivateKey) -> list:
    """
    Searches the encrypted index using homomorphic properties.
    """
    print(f"\n[Search] Searching for query: '{query}'")
    
    # 1. Encrypt the query using the public key [cite: 1168]
    query_int = word_to_int(query)
    encrypted_query = public_key.encrypt(query_int)
    
    # 2. Search the encrypted index for matching terms 
    print("[Search] Iterating encrypted index and homomorphically checking for '0'...")
    for encrypted_word, encrypted_doc_id_list in encrypted_index:
        
        # --- This is the core "search" logic ---
        # We use Paillier's homomorphic subtraction:
        # E(query) - E(word) = E(query - word)
        # If query == word, then E(query - word) = E(0)
        
        encrypted_difference = encrypted_query - encrypted_word
        
        # We must decrypt to check the result
        difference = private_key.decrypt(encrypted_difference)
        
        # If the difference is 0, we found our match!
        if difference == 0:
            print(f"[Search] Match found for '{query}'!")
            
            # 3. Decrypt the returned document IDs [cite: 1170]
            decrypted_ids = [int_to_doc_id(private_key.decrypt(enc_id)) 
                             for enc_id in encrypted_doc_id_list]
            return decrypted_ids
            
    print(f"[Search] No match found for '{query}'.")
    return []

# --- 2a. Create a dataset ---
# [cite: 1158]
def get_document_corpus():
    """Generates a text corpus of at least ten documents."""
    return {
        "doc1": "this is a document about python and programming",
        "doc2": "another document with different words about python",
        "doc3": "yet another document with some common words and encryption",
        "doc4": "python is a great programming language",
        "doc5": "this lab is about searchable encryption",
        "doc6": "a test document for python and aes",
        "doc7": "encryption keeps data secure",
        "doc8": "searching on encrypted data is tricky with paillier",
        "doc9": "this document is about python searchable encryption",
        "doc10": "final test document for the paillier lab"
    }

# --- Main execution ---
if __name__ == "__main__":
    
    # 2a. Create dataset
    documents = get_document_corpus()
    
    # 2b. Generate keys
    pub_key, priv_key = generate_keys(key_size=1024)
    
    # 2c. Create encrypted index
    enc_index = create_encrypted_index(documents, pub_key)
    
    # 2d. Perform searches
    
    # Test 1: Search for "python"
    results_python = search_encrypted_index(enc_index, "python", pub_key, priv_key)
    print(f"[Search] Results for 'python': {results_python}")
    # Verify results
    for doc_id in results_python:
        print(f"  -> {doc_id}: {documents[doc_id]}")
        
    # Test 2: Search for "encryption"
    results_encryption = search_encrypted_index(enc_index, "encryption", pub_key, priv_key)
    print(f"[Search] Results for 'encryption': {results_encryption}")
    # Verify results
    for doc_id in results_encryption:
        print(f"  -> {doc_id}: {documents[doc_id]}")
        
    # Test 3: Search for "hello" (no results)
    results_hello = search_encrypted_index(enc_index, "hello", pub_key, priv_key)
    print(f"[Search] Results for 'hello': {results_hello}")
