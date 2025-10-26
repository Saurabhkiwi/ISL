from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def generate_dsa_keys(bits=2048):
    """Generates a DSA key pair."""
    key = DSA.generate(bits) # [cite: 496]
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

def dsa_sign(private_key, msg_bytes):
    """Signs a message using the DSA private key."""
    hash_obj = SHA256.new(msg_bytes)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature

def dsa_verify(public_key, msg_bytes, signature):
    """Verifies a DSA signature."""
    hash_obj = SHA256.new(msg_bytes)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

if __name__ == "__main__":
    message = b"This message will be signed with DSA."
    
    public_key, private_key = generate_dsa_keys(bits=2048)
    print(f"Message: {message.decode()}")
    
    signature = dsa_sign(private_key, message)
    print(f"Signature (hex): {signature.hex()[:64]}...")
    
    is_valid = dsa_verify(public_key, message, signature)
    print(f"Verification (Correct Msg): {is_valid}")
