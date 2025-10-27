from phe import paillier

print("\n--- Add'l Q1b: Secure Data Sharing (Paillier) ---")

# 1. Setup: A central authority generates keys
public_key, private_key = paillier.generate_paillier_keypair(n_length=1024)
print("Central authority generated Paillier key pair.")

# 2. Parties share encrypted data
# Hospital A has 120 cases
hospital_A_data = 120
enc_A = public_key.encrypt(hospital_A_data)
print(f"Hospital A encrypts its data ({hospital_A_data}) and sends it.")

# Hospital B has 85 cases
hospital_B_data = 85
enc_B = public_key.encrypt(hospital_B_data)
print(f"Hospital B encrypts its data ({hospital_B_data}) and sends it.")

# 3. Researcher performs calculations on combined data
print("\nA Researcher (who only has the public key) receives the data.")
# The researcher can add the encrypted values
enc_total = enc_A + enc_B
print("Researcher computes the homomorphic sum (E[A] + E[B] = E[A+B]).")
print(f"Researcher's encrypted total: {enc_total.ciphertext() % (public_key.n // 2)}...")

# 4. Decryption by authorized party
# The researcher sends the encrypted total to an Auditor (who has the private key)
print("\nAn Auditor (with the private key) decrypts the final sum.")
decrypted_total = private_key.decrypt(enc_total)

print(f"Decrypted total: {decrypted_total}")
print(f"Verification (120 + 85 == {decrypted_total}): {decrypted_total == (hospital_A_data + hospital_B_data)}")
print("Result: The total was computed without revealing the individual values.")
