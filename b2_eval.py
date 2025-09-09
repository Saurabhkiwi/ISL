import rsa
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import matplotlib.pyplot as plt
import string


# Hill Cipher Encryption/Decryption
class HillCipher:
    def __init__(self, key_matrix):
        self.key_matrix = np.array(key_matrix)
        self.inverse_key_matrix = self.mod_inverse(self.key_matrix, 26)

    def mod_inverse(self, matrix, mod):
        det = int(np.round(np.linalg.det(matrix)))  # determinant of matrix
        det_inv = pow(det, -1, mod)  # multiplicative inverse of det mod 26
        adjugate = np.round(np.linalg.inv(matrix) * det).astype(int) % mod  # adjugate matrix
        return (det_inv * adjugate) % mod

    def text_to_numbers(self, text):
        alphabet = string.ascii_uppercase
        text = text.replace(" ", "").upper()
        return [alphabet.index(c) for c in text]

    def numbers_to_text(self, numbers):
        alphabet = string.ascii_uppercase
        return ''.join([alphabet[i] for i in numbers])

    def encrypt(self, plaintext):
        plaintext_numbers = self.text_to_numbers(plaintext)
        if len(plaintext_numbers) % 2 != 0:
            plaintext_numbers.append(0)  # padding 'A' (0) if odd number of characters
        ciphertext_numbers = []
        for i in range(0, len(plaintext_numbers), 2):
            block = np.array(plaintext_numbers[i:i + 2]).reshape(2, 1)
            encrypted_block = np.dot(self.key_matrix, block) % 26
            ciphertext_numbers.extend(encrypted_block.flatten().tolist())
        return self.numbers_to_text(ciphertext_numbers)

    def decrypt(self, ciphertext):
        ciphertext_numbers = self.text_to_numbers(ciphertext)
        plaintext_numbers = []
        for i in range(0, len(ciphertext_numbers), 2):
            block = np.array(ciphertext_numbers[i:i + 2]).reshape(2, 1)
            decrypted_block = np.dot(self.inverse_key_matrix, block) % 26
            plaintext_numbers.extend(decrypted_block.flatten().tolist())
        return self.numbers_to_text(plaintext_numbers)


# AES Encryption/Decryption
def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ct_bytes  # Prepend IV for decryption


def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()


# RSA Key Generation and Encryption/Decryption
def generate_rsa_keys():
    public_key, private_key = rsa.newkeys(2048)
    return public_key, private_key


def rsa_encrypt(message, public_key):
    return rsa.encrypt(message.encode(), public_key)


def rsa_decrypt(ciphertext, private_key):
    return rsa.decrypt(ciphertext, private_key).decode()


# Helper function to measure encryption times
def measure_time(func, *args):
    start_time = time.time()
    func(*args)
    return time.time() - start_time


# Main Menu-driven Function
def main():
    while True:
        print("\nChoose an option:")
        print("1. Hill Cipher Encryption/Decryption")
        print("2. RSA Key Pair Generation and AES Key Sharing")
        print("3. AES Encryption/Decryption")
        print("4. Compare Encryption Times")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            print("\nHill Cipher Encryption/Decryption")
            hill_key_matrix = [[3, 3], [2, 5]]
            hill_cipher = HillCipher(hill_key_matrix)

            plaintext = "The key is hidden under the mattress"
            print(f"\nOriginal Plaintext: {plaintext}")

            # Hill cipher encryption
            encrypted_text = hill_cipher.encrypt(plaintext)
            print(f"Encrypted Text (Ciphertext): {encrypted_text}")

            # Hill cipher decryption
            decrypted_text = hill_cipher.decrypt(encrypted_text)
            print(f"Decrypted Text (Recovered Plaintext): {decrypted_text}")

        elif choice == '2':
            print("\nRSA Key Pair Generation and AES Key Sharing")

            # Generate RSA keys
            public_key, private_key = generate_rsa_keys()
            aes_key = b"0123456789ABCDEFGHIJKLMNOP012345"

            print("\nRSA Keys Generated:")
            print(f"Public Key: {public_key}")
            print(f"Private Key: {private_key}")

            # Encrypt AES key with RSA public key
            encrypted_aes_key = rsa_encrypt(aes_key, public_key)
            print(f"\nAES Key Encrypted using RSA: {encrypted_aes_key[:64]}")

            # Decrypt AES key with RSA private key
            decrypted_aes_key = rsa_decrypt(encrypted_aes_key, private_key)
            print(f"Decrypted AES Key: {decrypted_aes_key}")

        elif choice == '3':
            print("\nAES Encryption/Decryption")
            aes_key = b"0123456789ABCDEFGHIJKLMNOP012345"

            message = input("Enter message to encrypt: ")

            # AES encryption
            encrypted_aes = aes_encrypt(message, aes_key)
            print(f"\nEncrypted AES Message (first 64 bytes): {encrypted_aes[:64]}")

            # AES decryption
            decrypted_aes = aes_decrypt(encrypted_aes, aes_key)
            print(f"Decrypted AES Message: {decrypted_aes}")

        elif choice == '4':
            print("\nCompare Encryption Times")

            # Measure encryption times for Hill, RSA, AES
            plaintext = "The key is hidden under the mattress"
            start_time = time.time()
            hill_cipher = HillCipher([[3, 3], [2, 5]])
            hill_cipher.encrypt(plaintext)
            hill_encryption_time = time.time() - start_time

            aes_key = b"0123456789ABCDEFGHIJKLMNOP012345"
            message = "Information Security Lab Evaluation One"
            start_time = time.time()
            aes_encrypt(message, aes_key)
            aes_encryption_time = time.time() - start_time

            public_key, private_key = generate_rsa_keys()
            start_time = time.time()
            rsa_encrypt(aes_key, public_key)
            rsa_encryption_time = time.time() - start_time

            # Plot the encryption times
            techniques = ['Hill Cipher', 'RSA', 'AES']
            times = [hill_encryption_time, rsa_encryption_time, aes_encryption_time]

            plt.bar(techniques, times, color=['blue', 'green', 'red'])
            plt.xlabel('Cryptographic Technique')
            plt.ylabel('Encryption Time (seconds)')
            plt.title('Comparison of Encryption Times')
            plt.show()

        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice! Please select again.")


if __name__ == "__main__":
    main()




'''
 Implement the following scenario as a menu driven python program showcasing various 
cryptographic techniques:
  Use the Hill cipher with the key matrix [[3, 3], [2, 5]] to encipher the message "The 
key is hidden under the mattress", and then decrypt it to verify correctness. Display the key 
matrix, the ciphertext, and the recovered plaintext. Ensure that padding is handled for 
messages not fitting the block size.
  Generate RSA key pairs for an encoder and a decoder. Share the AES key: 
"0123456789ABCDEFGHIJKLMNOP012345", securely from the encoder to decoder. Show 
the key pairs generated along with encrypted and decrypted values.
  Encrypt the message using AES-128 with the key, and decrypt it to verify correctness. Read 
the message from the user and the message to be read is "Information Security Lab Evaluation 
One".
  Compare the encryption times of these techniques and plot the graph. 
'''