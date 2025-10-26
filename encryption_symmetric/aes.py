from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_aes_key(bits=256):
    """Generates a random 16, 24, or 32-byte AES key."""
    return get_random_bytes(bits // 8) # [cite: 358]

def aes_gcm_encrypt(key, msg_bytes):
    """Encrypts with AES in GCM mode."""
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce # Save the random nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg_bytes) # [cite: 365]
    return nonce, tag, ciphertext

def aes_gcm_decrypt(key, nonce, tag, ciphertext):
    """Decrypts with AES in GCM mode. Verifies authenticity."""
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError):
        return None # Decryption failed (tag mismatch, key wrong, etc.)

if __name__ == "__main__":
    message = b"This is a secret message for AES-GCM."
    key = generate_aes_key(bits=256) # AES-256 [cite: 358]
    
    print(f"Message: {message.decode()}")
    print(f"Key (hex): {key.hex()}")
    
    nonce, tag, ciphertext = aes_gcm_encrypt(key, message)
    print(f"Nonce (hex): {nonce.hex()}")
    print(f"Tag (hex):   {tag.hex()}")
    print(f"Cipher (hex): {ciphertext.hex()}")
    
    plaintext = aes_gcm_decrypt(key, nonce, tag, ciphertext)
    if plaintext:
        print(f"Decrypted: {plaintext.decode()}")
        print(f"Success: {plaintext == message}")
    else:
        print("Decryption Failed! (Tag was invalid)")
