from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Util import number

# --- Helper functions for manual ElGamal operations ---

def elgamal_encrypt(pub_key, m):
    """Manually encrypts message 'm' with ElGamal public key."""
    p = pub_key.p
    g = pub_key.g
    y = pub_key.y
    # Generate random k
    k = number.getRandomRange(1, p - 1)
    
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(priv_key, c1, c2):
    """Manually decrypts an ElGamal ciphertext (c1, c2)."""
    p = priv_key.p
    x = priv_key.x
    
    # Compute s = c1^x mod p
    s = pow(c1, x, p)
    # Compute s_inv = s^-1 mod p
    s_inv = number.inverse(s, p)
    
    # Compute m = c2 * s_inv mod p
    m = (c2 * s_inv) % p
    return m

# --- Main demonstration ---
print("\n--- Add'l Q1a: ElGamal (Multiplicative Homomorphism) ---")

# 1. Generate ElGamal key pair
print("Generating ElGamal key pair...")
key = ElGamal.generate(1024, get_random_bytes)
public_key = key.publickey()
private_key = key
print("ElGamal key pair generated.")

# 2. Encrypt two integers (e.g., 5 and 6)
m1 = 5
m2 = 6
print(f"Plaintext 1: {m1}")
print(f"Plaintext 2: {m2}")

c1_pair = elgamal_encrypt(public_key, m1)
c2_pair = elgamal_encrypt(public_key, m2)

print(f"Ciphertext 1 (E[5]): ({c1_pair[0]}, {c1_pair[1]})")
print(f"Ciphertext 2 (E[6]): ({c2_pair[0]}, {c2_pair[1]})")

# 3. Perform multiplication on the encrypted integers
# E(m1) * E(m2) = (c1a*c1b, c2a*c2b) = E(m1*m2)
c_prod_0 = (c1_pair[0] * c2_pair[0]) % public_key.p
c_prod_1 = (c1_pair[1] * c2_pair[1]) % public_key.p
c_prod_pair = (c_prod_0, c_prod_1)

print(f"Encrypted Product (E[5*6]): ({c_prod_pair[0]}, {c_prod_pair[1]})")

# 4. Decrypt the result and verify
decrypted_prod = elgamal_decrypt(private_key, c_prod_pair[0], c_prod_pair[1])
print(f"\nDecrypted product: {decrypted_prod}")

verification = (m1 * m2 == decrypted_prod)
print(f"Verification (5 * 6 == {decrypted_prod}): {verification}")
