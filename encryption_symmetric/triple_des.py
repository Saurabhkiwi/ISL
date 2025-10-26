from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_des3_key():
    """Generates a random 24-byte (192-bit) 3DES key."""
    return get_random_bytes(24) # [cite: 340]

def des3_encrypt(key, msg_bytes):
    """Encrypts with 3DES in CBC mode."""
    cipher = DES3.new(key, DES3.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(msg_bytes, DES3.block_size))
    return iv, ciphertext

def des3_decrypt(key, iv, ciphertext):
    """Decrypts with 3DES in CBC mode."""
    try:
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), DES3.block_size)
        return plaintext
    except (ValueError, KeyError):
        return None

if __name__ == "__main__":
    message = b"This is a secret message for Triple DES."
    key = generate_des3_key()
    
    print(f"Message: {message.decode()}")
    print(f"Key (hex): {key.hex()}")
    
    iv, ciphertext = des3_encrypt(key, message)
    print(f"IV (hex):  {iv.hex()}")
    print(f"Cipher (hex): {ciphertext.hex()}")
    
    plaintext = des3_decrypt(key, iv, ciphertext)
    if plaintext:
        print(f"Decrypted: {plaintext.decode()}")
        print(f"Success: {plaintext == message}")
    else:
        print("Decryption Failed!")
