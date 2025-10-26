from Crypto.Hash import MD5, SHA1, SHA256

def hash_with_md5(msg_bytes):
    """Computes the MD5 hash of a byte string. [cite: 732]"""
    hash_obj = MD5.new(msg_bytes)
    return hash_obj.hexdigest()

def hash_with_sha1(msg_bytes):
    """Computes the SHA-1 hash of a byte string. [cite: 732]"""
    hash_obj = SHA1.new(msg_bytes)
    return hash_obj.hexdigest()

def hash_with_sha256(msg_bytes):
    """Computes the SHA-256 hash of a byte string. [cite: 732]"""
    hash_obj = SHA256.new(msg_bytes)
    return hash_obj.hexdigest()

if __name__ == "__main__":
    message = b"This is a test message for hashing."
    
    print(f"Message: {message.decode()}")
    print("-" * 20)
    
    # MD5
    md5_hash = hash_with_md5(message)
    print(f"MD5:    {md5_hash}")
    
    # SHA-1
    sha1_hash = hash_with_sha1(message)
    print(f"SHA-1:  {sha1_hash}")
    
    # SHA-256
    sha256_hash = hash_with_sha256(message)
    print(f"SHA-256:{sha256_hash}")
