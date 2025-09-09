import numpy as np
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

while(True):
    l = int(input("Enter the choice:"))
    if(l == 1):
        def preprocess_text(text):
            text = text.upper().replace(" ", "")
            if len(text) % 2 != 0:
                text += "X"
            return text


        def text_to_numbers(text):
            return [ord(c) - ord('A') for c in text]


        def numbers_to_text(numbers):
            return ''.join(chr(n + ord('A')) for n in numbers)


        def modinv(a, m):
            # Modular inverse using Extended Euclidean Algorithm
            for i in range(1, m):
                if (a * i) % m == 1:
                    return i
            return None


        def matrix_modinv_2x2(matrix, mod):
            a, b = matrix[0]
            c, d = matrix[1]
            det = (a * d - b * c) % mod
            det_inv = modinv(det, mod)
            if det_inv is None:
                raise ValueError("Matrix is not invertible modulo", mod)

            # Inverse of 2x2 matrix
            inv_matrix = np.array([[d, -b], [-c, a]]) * det_inv
            return inv_matrix % mod


        def hill_encrypt(plaintext, key_matrix):
            plaintext = preprocess_text(plaintext)
            plain_nums = text_to_numbers(plaintext)
            ciphertext = ""

            for i in range(0, len(plain_nums), 2):
                pair = np.array([[plain_nums[i]], [plain_nums[i + 1]]])
                product = np.dot(key_matrix, pair) % 26
                ciphertext += numbers_to_text(product.flatten())

            return ciphertext


        def hill_decrypt(ciphertext, key_matrix):
            cipher_nums = text_to_numbers(ciphertext)
            inverse_matrix = matrix_modinv_2x2(key_matrix, 26)
            plaintext = ""

            for i in range(0, len(cipher_nums), 2):
                pair = np.array([[cipher_nums[i]], [cipher_nums[i + 1]]])
                product = np.dot(inverse_matrix, pair) % 26
                plaintext += numbers_to_text(product.flatten())

            return plaintext


        # Key matrix: [[3, 3], [2, 5]]
        key_matrix = np.array([[3, 3], [2, 5]])
        message = "The key is hidden under the mattress"

        # Encrypt
        encrypted = hill_encrypt(message, key_matrix)
        print("Encrypted message:", encrypted)

        # Decrypt
        decrypted = hill_decrypt(encrypted, key_matrix)
        print("Decrypted message:", decrypted)

        continue

    elif(l == 2):
        def rsa_keygen(bits=2048):
            key = RSA.generate(bits)
            return key


        def rsa_en(ptext, pub_key):
            cipher = PKCS1_OAEP.new(pub_key)
            ctext = cipher.encrypt(ptext.encode('utf-8'))
            return ctext


        def rsa_de(ctext, priv_key):
            cipher = PKCS1_OAEP.new(priv_key)
            decrypted = cipher.decrypt(ctext)
            return decrypted.decode('utf-8')


        def main():
            print("Welcome to RSA")
            ptext = "0123456789ABCDEFGHIJKLMNOP012345"

            # RSA key pair
            key = rsa_keygen()
            pub_key = key.publickey()
            priv_key = key

            print("\nPublic Key (n, e):")
            print("n =", hex(pub_key.n))
            print("e =", pub_key.e)

            ctext = rsa_en(ptext, pub_key)
            print("\nYour ciphertext (hex):", binascii.hexlify(ctext).decode())

            decrypted = rsa_de(ctext, priv_key)
            print("Your decrypted plaintext:", decrypted)


        if __name__ == '__main__':
            main()

        continue

    elif(l == 3):
        message = b"Information Security Lab Evaluation One"
        key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")  # 16-byte key

        cipher = AES.new(key, AES.MODE_ECB)

        padded_text = pad(message, AES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        print("Encrypted:", ciphertext.hex())

        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded, AES.block_size)
        print("Decrypted:", decrypted.decode())

        continue

    elif(l==4):
        print("Exiting...")
        break


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
Show the output for all steps above
'''