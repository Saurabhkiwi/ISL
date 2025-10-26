from Crypto.Util import number
from Crypto.Hash import SHA256

def generate_rabin_keys(bits=1024):
    """Generates Rabin keys. p, q are primes where p = q = 3 (mod 4). [cite: 582]"""
    while True:
        p = number.getPrime(bits // 2)
        if p % 4 == 3:
            break
    while True:
        q = number.getPrime(bits // 2)
        if q % 4 == 3 and q != p:
            break
    n = p * q
    # Public key: n. Private key: (p, q).
    return {"n": n}, {"p": p, "q": q}

def _rabin_pad(msg_bytes):
    """Adds redundancy to find the correct root."""
    # Format: msg + SHA256(msg)[:16]
    tag = SHA256.new(msg_bytes).digest()[:16]
    return msg_bytes + tag

def _rabin_unpad(padded_bytes):
    """Checks redundancy and removes it."""
    if len(padded_bytes) < 16:
        return None
    msg = padded_bytes[:-16]
    tag = padded_bytes[-16:]
    if SHA256.new(msg).digest()[:16] == tag:
        return msg
    return None

def rabin_encrypt(public_key, msg_bytes):
    """Encrypts with Rabin. c = m^2 mod n. [cite: 586]"""
    n = public_key["n"]
    padded_msg = _rabin_pad(msg_bytes)
    m = number.bytes_to_long(padded_msg)
    if m >= n:
        raise ValueError("Message too large for key size.")
    c = pow(m, 2, n)
    return c

def rabin_decrypt(private_key, ciphertext):
    """Decrypts with Rabin by finding 4 square roots. [cite: 587-596]"""
    p = private_key["p"]
    q = private_key["q"]
    n = p * q
    
    # 1. Find roots mod p and mod q
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)
    
    # 2. Use Chinese Remainder Theorem to find 4 roots mod n
    yp = number.inverse(p, q)
    yq = number.inverse(q, p)
    
    r1 = (yq * q * mp + yp * p * mq) % n
    r2 = (yq * q * mp - yp * p * mq) % n
    r3 = (-yq * q * mp + yp * p * mq) % n
    r4 = (-yq * q * mp - yp * p * mq) % n
    
    roots = [r1, r2, r3, r4]
    
    # 3. Check padding to find correct root
    for r in roots:
        padded_bytes = number.long_to_bytes(r)
        msg = _rabin_unpad(padded_bytes)
        if msg is not None:
            return msg
    return None

if __name__ == "__main__":
    message = b"This is a secret message for Rabin."
    
    public_key, private_key = generate_rabin_keys(bits=1024)
    
    print(f"Message: {message.decode()}")
    print(f"Public n (hex): {hex(public_key['n'])[:64]}...")
    
    ciphertext = rabin_encrypt(public_key, message)
    print(f"Cipher (int): {str(ciphertext)[:64]}...")
    
    plaintext = rabin_decrypt(private_key, ciphertext)
    if plaintext:
        print(f"Decrypted: {plaintext.decode()}")
        print(f"Success: {plaintext == message}")
    else:
        print("Decryption Failed!")
