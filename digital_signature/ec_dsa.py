from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def generate_ecdsa_keys(curve='P-256'):
    """Generates an ECDSA key pair."""
    key = ECC.generate(curve=curve) # [cite: 496]
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

def ecdsa_sign(private_key, msg_bytes):
    """Signs a message using the ECDSA private key."""
    hash_obj = SHA256.new(msg_bytes)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature

def ecdsa_verify(public_key, msg_bytes, signature):
    """Verifies an ECDSA signature."""
    hash_obj = SHA256.new(msg_bytes)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

if __name__ == "__main__":
    message = b"This message will be signed with ECDSA."
    
    public_key, private_key = generate_ecdsa_keys(curve='P-256')
    print(f"Message: {message.decode()}")
    
    signature = ecdsa_sign(private_key, message)
    print(f"Signature (hex): {signature.hex()[:64]}...")
    
    is_valid = ecdsa_verify(public_key, message, signature)
    print(f"Verification (Correct Msg): {is_valid}")
