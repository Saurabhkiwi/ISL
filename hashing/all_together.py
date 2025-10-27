from Crypto.Hash import SHA256, SHA1, MD5

# ==================================================
# SHA-256 Functions
# ==================================================

def hash_with_sha256(msg_bytes: bytes) -> str:
    """
    Computes the SHA-256 hash of a byte string and returns the hex digest.
    
    """
    hash_obj = SHA256.new(msg_bytes)
    return hash_obj.hexdigest()

def verify_sha256_hash(original_data: bytes, expected_hash: str) -> bool:
    """
    Computes the SHA-256 hash of the data and compares it to the
    expected hash string (hex).
    """
    print(f"  Verifying SHA-256...")
    actual_hash = hash_with_sha256(original_data)
    print(f"  Expected: {expected_hash}")
    print(f"  Actual:   {actual_hash}")
    return actual_hash == expected_hash

# ==================================================
# SHA-1 Functions
# ==================================================

def hash_with_sha1(msg_bytes: bytes) -> str:
    """
    Computes the SHA-1 hash of a byte string and returns the hex digest.
    
    """
    hash_obj = SHA1.new(msg_bytes)
    return hash_obj.hexdigest()

def verify_sha1_hash(original_data: bytes, expected_hash: str) -> bool:
    """
    Computes the SHA-1 hash of the data and compares it to the
    expected hash string (hex).
    """
    print(f"  Verifying SHA-1...")
    actual_hash = hash_with_sha1(original_data)
    print(f"  Expected: {expected_hash}")
    print(f"  Actual:   {actual_hash}")
    return actual_hash == expected_hash

# ==================================================
# MD5 Functions
# ==================================================

def hash_with_md5(msg_bytes: bytes) -> str:
    """
    Computes the MD5 hash of a byte string and returns the hex digest.
    
    """
    hash_obj = MD5.new(msg_bytes)
    return hash_obj.hexdigest()

def verify_md5_hash(original_data: bytes, expected_hash: str) -> bool:
    """
    Computes the MD5 hash of the data and compares it to the
    expected hash string (hex).
    """
    print(f"  Verifying MD5...")
    actual_hash = hash_with_md5(original_data)
    print(f"  Expected: {expected_hash}")
    print(f"  Actual:   {actual_hash}")
    return actual_hash == expected_hash

# ==================================================
# Main execution for testing
# ==================================================

if __name__ == "__main__":
    
    message = b"This is a test message for all hashes."
    
    print(f"Original Message: '{message.decode()}'\n")
    
    # --- Generate all hashes ---
    
    sha256_hash = hash_with_sha256(message)
    print(f"SHA-256 Hash: {sha256_hash}")
    
    sha1_hash = hash_with_sha1(message)
    print(f"SHA-1 Hash:   {sha1_hash}")
    
    md5_hash = hash_with_md5(message)
    print(f"MD5 Hash:     {md5_hash}")
    
    print("\n" + "="*40 + "\n")
    
    # --- Verification Tests ---
    
    # --- SHA-256 Test ---
    print("--- Test 1: SHA-256 Verification (Success) ---")
    is_valid_sha256 = verify_sha256_hash(message, sha256_hash)
    print(f"Result: {is_valid_sha256}\n")
    
    # --- SHA-1 Test ---
    print("--- Test 2: SHA-1 Verification (Success) ---")
    is_valid_sha1 = verify_sha1_hash(message, sha1_hash)
    print(f"Result: {is_valid_sha1}\n")
    
    # --- MD5 Test ---
    print("--- Test 3: MD5 Verification (Success) ---")
    is_valid_md5 = verify_md5_hash(message, md5_hash)
    print(f"Result: {is_valid_md5}\n")
    
    # --- Tampering Test ---
    print("--- Test 4: Verification (Failure/Tampered) ---")
    tampered_message = b"This is a tampered message."
    print(f"Verifying tampered message: '{tampered_message.decode()}'")
    
    is_valid_tampered = verify_sha256_hash(tampered_message, sha256_hash)
    print(f"Result: {is_valid_tampered}")
