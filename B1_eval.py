import string
import random
import time
import rsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import matplotlib.pyplot as plt


# Playfair Cipher
class PlayfairCipher:
    def __init__(self, key):
        self.key = key
        self.matrix = self.generate_matrix(key)
        self.key_dict = self.create_key_dict(self.matrix)

    def generate_matrix(self, key):
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 'J' is omitted
        key = ''.join(dict.fromkeys(key.upper()))  # Remove duplicates
        key = ''.join([ch for ch in key if ch in alphabet])  # Remove non-alphabetical characters
        matrix = key + ''.join([ch for ch in alphabet if ch not in key])
        matrix = [matrix[i:i + 5] for i in range(0, len(matrix), 5)]
        return matrix

    def create_key_dict(self, matrix):
        key_dict = {}
        for i in range(5):
            for j in range(5):
                key_dict[matrix[i][j]] = (i, j)
        return key_dict

    def format_message(self, message):
        message = ''.join([ch.upper() for ch in message if ch.isalpha()])
        if len(message) % 2 != 0:
            message += 'X'
        return message

    def encrypt(self, message):
        message = self.format_message(message)
        ciphertext = []
        for i in range(0, len(message), 2):
            digraph = message[i:i + 2]
            r1, c1 = self.key_dict[digraph[0]]
            r2, c2 = self.key_dict[digraph[1]]

            if r1 == r2:
                ciphertext.append(self.matrix[r1][(c1 + 1) % 5])
                ciphertext.append(self.matrix[r2][(c2 + 1) % 5])
            elif c1 == c2:
                ciphertext.append(self.matrix[(r1 + 1) % 5][c1])
                ciphertext.append(self.matrix[(r2 + 1) % 5][c2])
            else:
                ciphertext.append(self.matrix[r1][c2])
                ciphertext.append(self.matrix[r2][c1])
        return ''.join(ciphertext)


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


# RSA Encryption/Decryption
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


# Main Function
def main():
    # 1. Playfair Cipher - Encrypt "The key is hidden under the door pad" with "POTATO"
    playfair = PlayfairCipher("POTATO")
    message_playfair = "The key is hidden under the door pad"

    start_time = time.time()
    encrypted_playfair = playfair.encrypt(message_playfair)
    playfair_encryption_time = time.time() - start_time

    print(f"Playfair Encrypted Message: {encrypted_playfair}")

    # 2. RSA key generation for AES key sharing
    public_key, private_key = generate_rsa_keys()
    aes_key = b"0123456789ABCDEF0123456789ABCDEF"

    start_time = time.time()
    encrypted_aes_key = rsa_encrypt(aes_key, public_key)
    rsa_encryption_time = time.time() - start_time

    print(f"AES Key Encrypted using RSA (first 64 bytes): {encrypted_aes_key[:64]}")

    # 3. AES Encryption and Decryption with key "0123456789ABCDEF0123456789ABCDEF"
    message_aes = "Information Security Lab Evaluation One"

    start_time = time.time()
    encrypted_aes = aes_encrypt(message_aes, aes_key)
    aes_encryption_time = time.time() - start_time

    print(f"AES Encrypted Message (first 64 bytes): {encrypted_aes[:64]}")

    start_time = time.time()
    decrypted_aes = aes_decrypt(encrypted_aes, aes_key)
    aes_decryption_time = time.time() - start_time

    print(f"AES Decrypted Message: {decrypted_aes}")

    # Compare Encryption Times
    print(f"\nEncryption times:")
    print(f"Playfair Cipher Encryption Time: {playfair_encryption_time:.6f} seconds")
    print(f"RSA Encryption Time: {rsa_encryption_time:.6f} seconds")
    print(f"AES Encryption Time: {aes_encryption_time:.6f} seconds")
    print(f"AES Decryption Time: {aes_decryption_time:.6f} seconds")

    # Plot the encryption times
    techniques = ['Playfair Cipher', 'RSA', 'AES']
    times = [playfair_encryption_time, rsa_encryption_time, aes_encryption_time]

    plt.bar(techniques, times, color=['blue', 'green', 'red'])
    plt.xlabel('Cryptographic Technique')
    plt.ylabel('Encryption Time (seconds)')
    plt.title('Comparison of Encryption Times for Cryptographic Techniques')
    plt.show()


if __name__ == "__main__":
    main()



'''
Implement the following scenario in python showcasing various cryptographic techniques: 
• Use the Playfair cipher with the keyword "POTATO" to encipher the message "The key is 
hidden under the door pad". 
• Generate the necessary keys for the participants and AES key must be shared by the encoder 
to the decoder using RSA public key cryptography. 
• Encrypt the message "Information Security Lab Evaluation One" using AES-128 with the key 
"0123456789ABCDEF0123456789ABCDEF", and decrypt it to verify correctness. 
• Compare the encryption times for both of these techniques and plot the graph.  
'''