from Crypto.Hash import SHA256, SHA1, MD5

def verify_sha256_hash(original_data: bytes, expected_hash: str) -> bool:
    """
    Computes the SHA-256 hash of the data and compares it to the
    expected hash string (hex).
    """
    # 1. Compute the actual hash
    hash_obj = SHA256.new(original_data)
    actual_hash = hash_obj.hexdigest()
    
    # 2. Compare the hashes
    print(f"  SHA-256 Expected: {expected_hash}")
    print(f"  SHA-256 Actual:   {actual_hash}")
    
    # 3. Return True or False
    return actual_hash == expected_hash

def verify_sha1_hash(original_data: bytes, expected_hash: str) -> bool:
    """
    Computes the SHA-1 hash of the data and compares it to the
    expected hash string (hex).
    """
    # 1. Compute the actual hash
    hash_obj = SHA1.new(original_data)
    actual_hash = hash_obj.hexdigest()
    
    # 2. Compare the hashes
    print(f"  SHA-1 Expected: {expected_hash}")
    print(f"  SHA-1 Actual:   {actual_hash}")
    
    # 3. Return True or False
    return actual_hash == expected_hash

def verify_md5_hash(original_data: bytes, expected_hash: str) -> bool:
    """
    Computes the MD5 hash of the data and compares it to the
    expected hash string (hex).
    """
    # 1. Compute the actual hash
    hash_obj = MD5.new(original_data)
    actual_hash = hash_obj.hexdigest()
    
    # 2. Compare the hashes
    print(f"  MD5 Expected: {expected_hash}")
    print(f"  MD5 Actual:   {actual_hash}")
    
    # 3. Return True or False
    return actual_hash == expected_hash

if __name__ == "__main__":
    
    # --- Example 1: Successful Verification ---
    print("--- Test 1: Successful Verification (SHA-256) ---")
    data_to_check = b"This is the correct file content."
    known_good_hash = "a96f1338d3900a07d350f3833b3b3a38f36c50117498c56c2f9d1303866c1f6c"
    
    is_valid = verify_sha256_hash(data_to_check, known_good_hash)
    print(f"  Result: Integrity VERIFIED -> {is_valid}\n")

    
    # --- Example 2: Failed Verification (Tampered Data) ---
    print("--- Test 2: Failed Verification (SHA-256) ---")
    data_tampered = b"This is the tampered file content." # Note the change
    
    is_valid_tampered = verify_sha256_hash(data_tampered, known_good_hash)
    print(f"  Result: Integrity FAILED -> {is_valid_tampered}\n")

    
    # --- Example 3: MD5 Verification ---
    print("--- Test 3: Successful Verification (MD5) ---")
    data_md5 = b"Check this with MD5"
    known_md5_hash = "1a8f6151ac9e5d3f118ff6f125a52230"
    
    is_valid_md5 = verify_md5_hash(data_md5, known_md5_hash)
    print(f"  Result: Integrity VERIFIED -> {is_valid_md5}\n")





'''
Here are the code snippets for verifying common hashes like SHA-256, SHA-1, and MD5.

The process is always the same:

You have the original data (e.g., a file or message).

You have an "expected" hash string that you got from a trusted source.

You compute the hash of your data.

You compare your computed hash to the expected hash.
'''
