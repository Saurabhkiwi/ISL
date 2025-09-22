from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii


def rsa_keygen(bits=2048):
    key = RSA.generate(bits)
    return key

def rsa_en(ptext, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    ctext = cipher.encrypt(ptext)
    return ctext

def rsa_de(ctext, priv_key):
    cipher = PKCS1_OAEP.new(priv_key)
    decrypted = cipher.decrypt(ctext)
    return decrypted

def main():
    


    message = b"Sensitive Information"
    key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")  # 16-byte key


    cipher = AES.new(key, AES.MODE_ECB)


    padded_text = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    print("Encrypted:", ciphertext.hex())

    r_key = rsa_keygen()
    pub_key = r_key.publickey()
    priv_key = r_key

    ctext = rsa_en(ciphertext, pub_key)
    print("\nYour ciphertext (hex):", binascii.hexlify(ctext).decode())

    decrypted_rsa = rsa_de(ctext, priv_key)
    print("Your decrypted plaintext:", decrypted_rsa)

    decrypted_padded = cipher.decrypt(decrypted_rsa)
    decrypted = unpad(decrypted_padded, AES.block_size)
    print("Decrypted:", decrypted.decode())


if __name__ == '__main__':
    main()