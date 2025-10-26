from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_des_key():
    """Generates a random 8-byte (64-bit) DES key."""
    return get_random_bytes(8) # [cite: 361]

def des_encrypt(key, msg_bytes):
    """Encrypts with DES in CBC mode."""
    cipher = DES.new(key, DES.MODE_CBC)
    iv = cipher.iv # Save the random IV
    ciphertext = cipher.encrypt(pad(msg_bytes, DES.block_size))
    return iv, ciphertext

def des_decrypt(key, iv, ciphertext):
    """Decrypts with DES in CBC mode."""
    try:
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
        return plaintext
    except (ValueError, KeyError):
        return None # Decryption failed (bad padding or key)

if __name__ == "__main__":
    message = b"This is a secret message for DES."
    key = generate_des_key()
    
    print(f"Message: {message.decode()}")
    print(f"Key (hex): {key.hex()}")
    
    iv, ciphertext = des_encrypt(key, message)
    print(f"IV (hex):  {iv.hex()}")
    print(f"Cipher (hex): {ciphertext.hex()}")
    
    plaintext = des_decrypt(key, iv, ciphertext)
    if plaintext:
        print(f"Decrypted: {plaintext.decode()}")
        print(f"Success: {plaintext == message}")
    else:
        print("Decryption Failed!")
