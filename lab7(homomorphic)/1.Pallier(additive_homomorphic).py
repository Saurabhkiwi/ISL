from phe import paillier # pip install phe

print("--- Lab 7, Q1: Paillier (Additive Homomorphism) ---")

# 1. Implement the Paillier encryption scheme
# Generate a 1024-bit key pair
public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)
print("Paillier key pair generated.")

# 2. Encrypt two integers (15 and 25)
m1 = 15
m2 = 25
print(f"Plaintext 1: {m1}")
print(f"Plaintext 2: {m2}")

c1 = public_key.encrypt(m1)
c2 = public_key.encrypt(m2)

# Print the ciphertexts (showing a truncated part)
print(f"Ciphertext 1 (E[15]): {c1.ciphertext() % (public_key.n // 2)}...")
print(f"Ciphertext 2 (E[25]): {c2.ciphertext() % (public_key.n // 2)}...")

# 3. Perform an addition operation on the encrypted integers
# This performs E(m1) * E(m2) % n^2, which results in E(m1 + m2)
c_sum = c1 + c2

# Print the result of the addition in encrypted form
print(f"Encrypted Sum (E[15+25]): {c_sum.ciphertext() % (public_key.n // 2)}...")

# 4. Decrypt the result and verify
decrypted_sum = private_key.decrypt(c_sum)
print(f"\nDecrypted sum: {decrypted_sum}")

verification = (m1 + m2 == decrypted_sum)
print(f"Verification (15 + 25 == {decrypted_sum}): {verification}")
