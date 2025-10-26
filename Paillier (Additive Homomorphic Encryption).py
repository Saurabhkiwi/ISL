from phe import paillier # pip install phe

def generate_paillier_keys(bits=1024):
    """Generates Paillier public and private keys. [cite: 865]"""
    public_key, private_key = paillier.generate_paillier_keypair(n_length=bits)
    return public_key, private_key

def paillier_encrypt(public_key, number_int):
    """Encrypts a single integer."""
    return public_key.encrypt(number_int)

def paillier_decrypt(private_key, encrypted_number):
    """Decrypts a single integer."""
    return private_key.decrypt(encrypted_number)

if __name__ == "__main__":
    # Lab 7, Q1 data [cite: 993]
    num1 = 15
    num2 = 25
    
    public_key, private_key = generate_paillier_keys()
    print(f"Num 1: {num1}")
    print(f"Num 2: {num2}")
    
    # Encrypt
    c1 = paillier_encrypt(public_key, num1)
    c2 = paillier_encrypt(public_key, num2)
    print(f"Encrypted c1: {c1.ciphertext() % (public_key.n // 2)}... (truncated)")
    print(f"Encrypted c2: {c2.ciphertext() % (public_key.n // 2)}... (truncated)")
    
    # --- Homomorphic Properties ---
    
    # 1. Additive: E(m1) + E(m2) = E(m1 + m2)
    c_sum = c1 + c2
    m_sum = paillier_decrypt(private_key, c_sum)
    print(f"\nHomomorphic Addition:")
    print(f"  Decrypted Sum: {m_sum}")
    print(f"  Expected Sum:  {num1 + num2}")
    
    # 2. Scalar Multiplication: E(m1) * k = E(m1 * k)
    scalar = 5
    c_mul = c1 * scalar
    m_mul = paillier_decrypt(private_key, c_mul)
    print(f"\nHomomorphic Scalar Multiplication:")
    print(f"  Decrypted (c1 * {scalar}): {m_mul}")
    print(f"  Expected (m1 * {scalar}): {num1 * scalar}")
