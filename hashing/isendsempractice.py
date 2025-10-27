from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD5, SHA1, SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def generate_rsa_keys(bits=2048):
    """Generates an RSA key pair."""
    key = RSA.generate(bits) # [cite: 504]
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

def rsa_encrypt(public_key, msg_bytes):
    """Encrypts bytes using the RSA public key with OAEP padding."""
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(msg_bytes)
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    """Decrypts bytes using the RSA private key with OAEP padding."""
    try:
        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
    except (ValueError, TypeError):
        return None
    
def hash_with_sha256(msg_bytes):
    """Computes the SHA-256 hash of a byte string. [cite: 732]"""
    hash_obj = SHA256.new(msg_bytes)
    return hash_obj.hexdigest()

def generate_ecdsa_keys(curve='P-256'):
    """Generates an ECDSA key pair."""
    key = ECC.generate(curve=curve) # [cite: 496]
    private_key = key
    public_key = key.public_key()
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
    
class Customer :
    def __init__(self, name):
        self.name = name
        self.public_key, self.private_key = generate_rsa_keys()
        self.ecda_public_key, self.ecda_priv_key = generate_ecdsa_keys()
    
    def send_encrypted_message(self, recipient_public_key, message):
        msg_bytes = message.encode('utf-8')
        ciphertext = rsa_encrypt(recipient_public_key, msg_bytes)
        return ciphertext
    
    def hash_message(self, message):
        msg_bytes = message.encode('utf-8')
        return hash_with_sha256(msg_bytes)
    
    def sign_message(self, message):
        #ecda_public_key, ecda_priv_key = generate_ecdsa_keys()
        msg_bytes = message.encode('utf-8')
        signature = ecdsa_sign(self.ecda_priv_key, msg_bytes)
        return signature
    
class Vendor :
    def __init__(self, name):
        self.name = name
        self.public_key, self.private_key = generate_rsa_keys()
    
    def receive_encrypted_message(self, ciphertext):
        plaintext_bytes = rsa_decrypt(self.private_key, ciphertext)
        if plaintext_bytes is not None:
            return plaintext_bytes.decode('utf-8')
        else:
            return None
    
    def verify_message_signature(self, sender_public_key, message, signature):
        msg_bytes = message.encode('utf-8')
        return ecdsa_verify(sender_public_key, msg_bytes, signature)
    
class Auditor :
    def __init__(self, name):
        self.name = name
    
    def verify_hash(self, message, expected_hash):
        msg_bytes = message.encode('utf-8')
        computed_hash = hash_with_sha256(msg_bytes)
        return computed_hash == expected_hash
    
def main():
    # Create participants
    customer = Customer("Alice")
    vendor = Vendor("Bob")  
    auditor = Auditor("Charlie")

    # Customer sends encrypted message to Vendor
    message = "Order details: Item A, Quantity 2"   
    ciphertext = customer.send_encrypted_message(vendor.public_key, message)
    print(f"Ciphertext: {ciphertext}")  
    decrypted_message = vendor.receive_encrypted_message(ciphertext)
    print(f"Decrypted Message: {decrypted_message}")
    # Customer hashes the message
    message_hash = customer.hash_message(message)
    print(f"Message Hash: {message_hash}")
    # Customer signs the message
    signature = customer.sign_message(message)
    print(f"Signature: {signature}")
    # Vendor verifies the signature
    is_signature_valid = vendor.verify_message_signature(customer.ecda_public_key, message, signature)
    print(f"Is Signature Valid: {is_signature_valid}")
    # Auditor verifies the hash
    is_hash_valid = auditor.verify_hash(message, message_hash)
    print(f"Is Hash Valid: {is_hash_valid}")

if __name__ == "__main__":
    main()         