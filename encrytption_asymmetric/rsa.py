from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

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

if __name__ == "__main__":
    message = b"This is a secret message for RSA-OAEP."
    
    public_key, private_key = generate_rsa_keys(bits=2048)
    
    print(f"Message: {message.decode()}")
    
    ciphertext = rsa_encrypt(public_key, message)
    print(f"Cipher (hex): {ciphertext.hex()[:64]}...")
    
    plaintext = rsa_decrypt(private_key, ciphertext)
    if plaintext:
        print(f"Decrypted: {plaintext.decode()}")
        print(f"Success: {plaintext == message}")
    else:
        print("Decryption Failed!")
