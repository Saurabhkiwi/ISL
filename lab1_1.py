def clear_spaces(message):
    return message.replace(' ','').upper()
#converting chars to num
def char_to_num(char):
    return ord(char) - ord('A')
def num_to_char(num):
    return chr(num+ord('A'))
def mod_inverse(a,m):
    a=a%m
    for x in range(1,m):
        if (a*x)%m==1:
            return x
    return None

#additive cipher with key=20
def additive_encrypt(plaintext,key):
    ciphertext=""
    for char in plaintext:
        c=(char_to_num(char)+key)%26
        ciphertext+=num_to_char(c)
    return ciphertext
def additive_decrypt(ciphertext,key):
    plaintext=""
    for char in ciphertext:
        c=(char_to_num(char)-key)%26
        plaintext+=num_to_char(c)
    return plaintext

#multiplicative cipher
def multiplicative_encrypt(plaintext,key):
    ciphertext=""
    for char in plaintext:
        c=(char_to_num(char)*key)%26
        ciphertext+=num_to_char(c)
    return ciphertext

def multiplicative_decrypt(ciphertext,key):
    plaintext=""
    key_inv=mod_inverse(key,26)
    for char in ciphertext:
        c=(char_to_num(char)*key_inv)%26
        plaintext+=num_to_char(c)
    return plaintext

def affine_encrypt(plaintext,a,b):
    ciphertext=""
    for char in plaintext:
        c=(a*char_to_num(char)+b)%26
        ciphertext+=num_to_char(c)
    return ciphertext
def affine_decrypt(ciphertext,a,b):
    plaintext=""
    a_inv=mod_inverse(a,26)
    for char in ciphertext:
        c=(a_inv*(char_to_num(char)-b))%26
        plaintext+=num_to_char(c)
    return plaintext


message="I am learning information security"
cleaned=clear_spaces(message)
print("Original message:",message)
print("Clear message:",cleaned)
# Additive cipher
additive_key=20
additive_enc=additive_encrypt(cleaned,additive_key)
additive_dec=additive_decrypt(additive_enc,additive_key)
print("Additive cipher:")
print("Encrypted: ",additive_enc)
print("Decrypted: ",additive_dec)
mul_key=15
multiplicative_enc=multiplicative_encrypt(cleaned,mul_key)
multiplicative_dec=multiplicative_decrypt(multiplicative_enc,mul_key)
print("Multiplicative cipher:")
print("Encrypted: ",multiplicative_enc)
print("Decrypted: ",multiplicative_dec)
a=15
b=20
aff_enc=affine_encrypt(cleaned,a,b)
aff_dec=affine_decrypt(aff_enc,a,b)
print("Affine cipher:")
print("Encrypted: ",aff_enc)
print("Decrypted: ",aff_dec)

