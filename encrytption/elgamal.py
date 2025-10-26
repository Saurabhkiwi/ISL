from Crypto.PublicKey import ElGamal
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_elgamal_keys(bits=1024):
    """Generates an ElGamal key pair."""
    key = ElGamal.generate(bits, get_random_bytes) # [cite: 457]
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

def elgamal_hybrid_encrypt(public_key, msg_bytes):
    """Encrypts a long message using ElGamal + AES-GCM."""
    # 1. Generate a one-time AES key
    session_key = get_random_bytes(16)
    
    # 2. Encrypt the message with AES-GCM
    aes_cipher = AES.new(session_key, AES.MODE_GCM)
    nonce = aes_cipher.nonce
    ciphertext, tag = aes_cipher.encrypt_and_digest(msg_bytes)
    
    # 3. Encrypt the AES session key with ElGamal
    encrypted_session_key = public_key.encrypt(session_key, 0) # 0 is a dummy K
    
    # 4. Return all parts
    return encrypted_session_key, nonce, tag, ciphertext

def elgamal_hybrid_decrypt(private_key, enc_session_key, nonce, tag, ciphertext):
    """Decrypts an ElGamal hybrid message."""
    try:
        # 1. Decrypt the AES session key with ElGamal
        session_key = private_key.decrypt(enc_session_key)
        
        # 2. Decrypt the message with AES-GCM
        aes_cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except (ValueError, KeyError):
        return None

if __name__ == "__main__":
    message = b"This is a secret message for ElGamal (Hybrid)."
    
    public_key, private_key = generate_elgamal_keys(bits=1024)
    print(f"Message: {message.decode()}")
    
    enc_key, nonce, tag, ct = elgamal_hybrid_encrypt(public_key, message)
    print(f"Encrypted Session Key (hex): {enc_key[0].hex()[:64]}...")
    print(f"Ciphertext (hex): {ct.hex()[:64]}...")
    
    plaintext = elgamal_hybrid_decrypt(private_key, enc_key, nonce, tag, ct)
    if plaintext:
        print(f"Decrypted: {plaintext.decode()}")
        print(f"Success: {plaintext == message}")
    else:
        print("Decryption Failed!")
