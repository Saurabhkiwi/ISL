from Crypto.Util import number

print("\n--- Lab 7, Q2: RSA (Multiplicative Homomorphism) ---")

# 1. Implement a basic RSA encryption scheme
# Generate p, q, n, phi(n)
p = number.getPrime(512)
q = number.getPrime(512)
n = p * q
phi_n = (p - 1) * (q - 1)

# Choose e (public exponent)
e = 65537
# Compute d (private exponent)
d = number.inverse(e, phi_n)

print("Textbook RSA key pair generated.")

# 2. Encrypt two integers (7 and 3)
m1 = 7
m2 = 3
print(f"Plaintext 1: {m1}")
print(f"Plaintext 2: {m2}")

# Encrypt: c = m^e mod n
c1 = pow(m1, e, n)
c2 = pow(m2, e, n)

print(f"Ciphertext 1 (E[7]): {hex(c1)[:50]}...")
print(f"Ciphertext 2 (E[3]): {hex(c2)[:50]}...")

# 3. Perform a multiplication operation on the encrypted integers
# (c1 * c2) % n = (m1^e * m2^e) % n = ((m1*m2)^e) % n = E(m1*m2)
c_prod = (c1 * c2) % n

# Print the result of the multiplication in encrypted form
print(f"Encrypted Product (E[7*3]): {hex(c_prod)[:50]}...")

# 4. Decrypt the result and verify
# Decrypt: m = c^d mod n
decrypted_prod = pow(c_prod, d, n)
print(f"\nDecrypted product: {decrypted_prod}")

verification = (m1 * m2 == decrypted_prod)
print(f"Verification (7 * 3 == {decrypted_prod}): {verification}")
