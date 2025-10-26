from Crypto.Util import number
from Crypto.Hash import SHA256

# Note: generate_rabin_keys is the same as in the Rabin Encryption block.
def generate_rabin_keys(bits=1024):
    while True: p = number.getPrime(bits // 2);
    if p % 4 == 3: break
    while True: q = number.getPrime(bits // 2);
    if q % 4 == 3 and q != p: break
    n = p * q
    return {"n": n}, {"p": p, "q": q}

def _hash_to_int(msg_bytes, n):
    """Hashes message to an integer m < n."""
    # We must ensure the hash is a quadratic residue.
    # This is complex. For a simple demo, we just hash.
    h = SHA256.new(msg_bytes).digest()
    m = number.bytes_to_long(h)
    return m % n

def rabin_sign(private_key, msg_bytes):
    """Signs by finding the square root of the hash."""
    p = private_key["p"]
    q = private_key["q"]
    n = p * q
    
    m = _hash_to_int(msg_bytes, n)
    
    # Find square root (this is the 'sign' operation)
    mp = pow(m, (p + 1) // 4, p)
    mq = pow(m, (q + 1) // 4, q)
    
    yp = number.inverse(p, q)
    yq = number.inverse(q, p)
    
    # Pick one of the roots as the signature
    s = (yq * q * mp + yp * p * mq) % n
    return s

def rabin_verify(public_key, msg_bytes, signature):
    """Verifies by squaring the signature."""
    n = public_key["n"]
    m = _hash_to_int(msg_bytes, n)
    
    # s^2 mod n
    s_squared = pow(signature, 2, n)
    
    return m == s_squared

if __name__ == "__main__":
    message = b"This message will be signed with Rabin."
    
    public_key, private_key = generate_rabin_keys(bits=1024)
    print(f"Message: {message.decode()}")
    
    signature = rabin_sign(private_key, message)
    print(f"Signature (int): {str(signature)[:64]}...")
    
    is_valid = rabin_verify(public_key, message, signature)
    print(f"Verification (Correct Msg): {is_valid}")
