from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

def generate_rsa_signing_keys(bits=2048):
    """Generates an RSA key pair for signing."""
    key = RSA.generate(bits) # [cite: 753]
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

def rsa_pss_sign(private_key, msg_bytes):
    """Signs a message using the RSA private key with PSS."""
    hash_obj = SHA256.new(msg_bytes)
    signer = pss.new(private_key)
    signature = signer.sign(hash_obj)
    return signature

def rsa_pss_verify(public_key, msg_bytes, signature):
    """Verifies an RSA-PSS signature."""
    hash_obj = SHA256.new(msg_bytes)
    verifier = pss.new(public_key)
    try:
        verifier.verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

if __name__ == "__main__":
    message = b"This message will be signed with RSA-PSS."
    tampered_message = b"This is a different message."
    
    public_key, private_key = generate_rsa_signing_keys(bits=2048)
    print(f"Message: {message.decode()}")
    
    signature = rsa_pss_sign(private_key, message)
    print(f"Signature (hex): {signature.hex()[:64]}...")
    
    # Test 1: Valid signature
    is_valid = rsa_pss_verify(public_key, message, signature)
    print(f"Verification (Correct Msg): {is_valid}")
    
    # Test 2: Invalid signature
    is_valid_tampered = rsa_pss_verify(public_key, tampered_message, signature)
    print(f"Verification (Tampered Msg): {is_valid_tampered}")
