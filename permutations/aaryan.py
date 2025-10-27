Conversation opened. 1 unread message.

Skip to content
Using Gmail with screen readers
1 of 1,373
Fwd: signhelper
Inbox


Aaryan Paranjape <aaryan17paranjape@gmail.com>
Attachments
6:54 PM (0 minutes ago)
to me



Yours sincerely, 
Aaryan Paranjape

---------- Forwarded message ---------
From: Aaryan Paranjape <aaryan17paranjape@gmail.com>
Date: Wed, 22 Oct, 2025, 1:53 pm
Subject: Fwd: signhelper
To: Aryan Chandra <aryanchandra1@gmail.com>



Yours sincerely, 
Aaryan Paranjape


---------- Forwarded message ---------
From: Kedarnath Chowdary <kedarnath1157@gmail.com>
Date: Wed, Oct 22, 2025 at 1:51 PM
Subject: Re: signhelper
To: Aaryan Paranjape <aaryan17paranjape@gmail.com>




On Wed, 15 Oct 2025 at 14:47, Aaryan Paranjape <aaryan17paranjape@gmail.com> wrote:

Yours sincerely, 
Aaryan Paranjape


---------- Forwarded message ---------
From: Abhay <abhhaypratap007@gmail.com>
Date: Wed, Oct 15, 2025 at 6:32 AM
Subject: Fwd: signhelper
To: Aaryan Paranjape <aaryan17paranjape@gmail.com>



---------- Forwarded message ---------
From: Abhay <abhhaypratap007@gmail.com>
Date: Sun, 28 Sept 2025, 12:28 pm
Subject: signhelper
To: <rajputabhay261104@gmail.com>




 One attachment
  •  Scanned by Gmail
#!/usr/bin/env python3
"""
ALICE–BOB CRYPTO SUITE (FINAL VIVA DEMO)
Author: Kedarnath Chowdary
----------------------------------
Educational cryptography showcase demonstrating:
 - Alice signs, encrypts, and sends message.
 - Bob decrypts and verifies signature.
 - Includes tampering demo to show verification failure.
Algorithms:
  * Hash: SHA-256 / SHA-1 / MD5
  * Public-Key (KEX): RSA / ElGamal / Rabin / EC-ElGamal (192-bit)
  * Signature: RSA / ElGamal / Schnorr / DH-MAC
  * Symmetric & Classical: AES / DES / 3DES / Affine / Additive / Multiplicative /
    Vigenère / Columnar / Hill / Playfair / Autokey
"""

import hashlib, random, json, hmac, string
from math import gcd

try:
    from Crypto.Cipher import AES, DES, DES3
    from Crypto.Random import get_random_bytes
    PYCRYPTO_AVAILABLE = True
except Exception:
    PYCRYPTO_AVAILABLE = False
    print("⚠️ PyCryptodome not installed — AES/DES/3DES disabled.")

# ================================================================
# UTILITY FUNCTIONS
# ================================================================
def is_probable_prime(n, k=6):
    """Miller–Rabin primality test"""
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0: return n == p
    d, s = n-1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a, d, n)
        if x in (1, n-1): continue
        for _ in range(s-1):
            x = (x*x) % n
            if x == n-1: break
        else: return False
    return True

def generate_prime(bits, cond_fn=None):
    """Generate prime of specified bits"""
    while True:
        p = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if cond_fn and not cond_fn(p): continue
        if is_probable_prime(p): return p

def egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1: raise Exception("No inverse")
    return x % m

# ================================================================
# HASH FUNCTIONS
# ================================================================
HASH_FUNCS = {
    '1': ('SHA-256', lambda b: hashlib.sha256(b).digest()),
    '2': ('SHA-1', lambda b: hashlib.sha1(b).digest()),
    '3': ('MD5', lambda b: hashlib.md5(b).digest())
}

# ================================================================
# RSA
# ================================================================
def rsa_gen(bits=512):
    p, q = generate_prime(bits//2), generate_prime(bits//2)
    while q == p: q = generate_prime(bits//2)
    n, phi = p*q, (p-1)*(q-1)
    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1: e += 2
    d = modinv(e, phi)
    return {'n': n, 'e': e, 'd': d}

def rsa_encrypt_bytes(msg, pub):
    k = (pub['n'].bit_length() - 1)//8
    out = bytearray()
    for i in range(0, len(msg), k):
        m = int.from_bytes(msg[i:i+k], 'big')
        c = pow(m, pub['e'], pub['n'])
        out.extend(c.to_bytes((pub['n'].bit_length()+7)//8, 'big'))
    return bytes(out)

def rsa_decrypt_bytes(ct, priv):
    blen = (priv['n'].bit_length()+7)//8
    out = bytearray()
    for i in range(0, len(ct), blen):
        c = int.from_bytes(ct[i:i+blen], 'big')
        m = pow(c, priv['d'], priv['n'])
        out.extend(m.to_bytes((m.bit_length()+7)//8, 'big'))
    return bytes(out)

# ================================================================
# ELGAMAL
# ================================================================
def elgamal_gen(bits=256):
    p = generate_prime(bits)
    g, x = 2, random.randrange(2, p-2)
    y = pow(g, x, p)
    return {'p': p, 'g': g, 'x': x, 'y': y}

def elgamal_encrypt_bytes(msg, pub):
    p = pub['p']; plen = (p.bit_length()+7)//8
    out = bytearray()
    for b in msg:
        k = random.randrange(2, p-2)
        a = pow(pub['g'], k, p)
        b_enc = (pow(pub['y'], k, p) * b) % p
        out.extend(a.to_bytes(plen,'big')); out.extend(b_enc.to_bytes(plen,'big'))
    return bytes(out)

def elgamal_decrypt_bytes(ct, priv):
    """
    Robust ElGamal decryption for demo:
    - ct is sequence of (a,b) pairs where each is plen-byte big-endian.
    - decrypts each pair, computes m = (b * s_inv) % p
    - converts m to the minimal number of bytes and extends output.
    Notes: in this demo we encrypt single bytes normally, but this routine
    also supports multi-byte plaintext blocks (safer for pipelines).
    """
    p = priv['p']
    plen = (p.bit_length() + 7) // 8
    out = bytearray()
    for i in range(0, len(ct), 2 * plen):
        a = int.from_bytes(ct[i:i+plen], 'big')
        b = int.from_bytes(ct[i+plen:i+2*plen], 'big')
        s = pow(a, priv['x'], p)
        s_inv = modinv(s, p)
        m = (b * s_inv) % p
        # convert m to bytes (at least 1 byte)
        if m == 0:
            m_bytes = b'\x00'
        else:
            m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        out.extend(m_bytes)
    return bytes(out)


# ================================================================
# RABIN
# ================================================================
def rabin_gen(bits=512):
    def cond(x): return x % 4 == 3
    p = generate_prime(bits//2, cond_fn=cond)
    q = generate_prime(bits//2, cond_fn=cond)
    while q == p: q = generate_prime(bits//2, cond_fn=cond)
    return {'p': p, 'q': q, 'n': p*q}

def rabin_encrypt_bytes(msg, pub):
    n = pub['n']; k = (n.bit_length()-1)//8; out = bytearray()
    for i in range(0, len(msg), k):
        block = b'@@' + msg[i:i+k]
        m = int.from_bytes(block, 'big')
        c = (m*m) % n
        out.extend(c.to_bytes((n.bit_length()+7)//8, 'big'))
    return bytes(out)

def rabin_decrypt_bytes(ct, priv):
    p,q,n = priv['p'],priv['q'],priv['n']; out=bytearray()
    blen = (n.bit_length()+7)//8
    for i in range(0, len(ct), blen):
        c = int.from_bytes(ct[i:i+blen],'big')
        rp = pow(c,(p+1)//4,p); rq = pow(c,(q+1)//4,q)
        r = (rp*q*modinv(q,p) + rq*p*modinv(p,q)) % n
        rb = r.to_bytes((r.bit_length()+7)//8,'big')
        if rb.startswith(b'@@'): out.extend(rb[2:])
    return bytes(out)

# ================================================================
# EC-ELGAMAL (192-bit)
# ================================================================
def ec_find_curve(bits=192):
    def cond(p): return p % 4 == 3
    while True:
        p = generate_prime(bits, cond_fn=cond)
        a,b = random.randrange(1,p), random.randrange(1,p)
        if (4*a*a*a + 27*b*b) % p != 0: return {'p':p,'a':a,'b':b}

def ec_point_add(P,Q,curve):
    if P is None: return Q
    if Q is None: return P
    p,a = curve['p'],curve['a']
    x1,y1 = P; x2,y2 = Q
    if x1==x2 and (y1+y2)%p==0: return None
    if P!=Q: lam=((y2-y1)*modinv((x2-x1)%p,p))%p
    else: lam=((3*x1*x1+a)*modinv((2*y1)%p,p))%p
    x3=(lam*lam-x1-x2)%p; y3=(lam*(x1-x3)-y1)%p
    return (x3,y3)

def ec_scalar_mul(k,P,curve):
    R=None
    while k>0:
        if k&1: R=ec_point_add(R,P,curve)
        P=ec_point_add(P,P,curve)
        k>>=1
    return R

def ec_point_from_x(x,curve):
    p,a,b=curve['p'],curve['a'],curve['b']
    rhs=(pow(x,3,p)+a*x+b)%p
    y=pow(rhs,(p+1)//4,p)
    if (y*y)%p==rhs: return (x,y)
    return None

def ec_gen(bits=192):
    curve=ec_find_curve(bits)
    for x in range(2,1000):
        G=ec_point_from_x(x,curve)
        if G: break
    d=random.randrange(2,curve['p']-2)
    Q=ec_scalar_mul(d,G,curve)
    return {'curve':curve,'G':G,'d':d,'Q':Q}

def ec_elgamal_encrypt_bytes(msg,pub):
    curve,p=pub['curve'],pub['curve']['p']
    plen=(p.bit_length()+7)//8; out=bytearray()
    for b in msg:
        M=ec_point_from_x(b%p,curve) or ec_point_from_x((b+1)%p,curve)
        k=random.randrange(2,p-2)
        R=ec_scalar_mul(k,pub['G'],curve)
        S=ec_point_add(M,ec_scalar_mul(k,pub['Q'],curve),curve)
        out.extend(R[0].to_bytes(plen,'big')); out.extend(R[1].to_bytes(plen,'big'))
        out.extend(S[0].to_bytes(plen,'big')); out.extend(S[1].to_bytes(plen,'big'))
    return bytes(out)

def ec_elgamal_decrypt_bytes(ct,priv):
    curve,p=priv['curve'],priv['curve']['p']
    plen=(p.bit_length()+7)//8; out=bytearray()
    for i in range(0,len(ct),4*plen):
        rx=int.from_bytes(ct[i:i+plen],'big'); ry=int.from_bytes(ct[i+plen:i+2*plen],'big')
        sx=int.from_bytes(ct[i+2*plen:i+3*plen],'big'); sy=int.from_bytes(ct[i+3*plen:i+4*plen],'big')
        R,S=(rx,ry),(sx,sy)
        dR=ec_scalar_mul(priv['d'],R,curve)
        neg_dR=(dR[0],(-dR[1])%p)
        M=ec_point_add(S,neg_dR,curve)
        out.append(M[0]%256)
    return bytes(out)
# ================================================================
# SIGNATURE ALGORITHMS
# ================================================================
def rsa_sign_hash(h_int, priv):
    s = pow(h_int, priv['d'], priv['n'])
    return s.to_bytes((priv['n'].bit_length()+7)//8, 'big')

def rsa_verify(sig, pub, h_int):
    s = int.from_bytes(sig, 'big')
    return pow(s, pub['e'], pub['n']) == h_int

def elgamal_sign(msg_hash_int, priv):
    p,g,x = priv['p'],priv['g'],priv['x']
    while True:
        k = random.randrange(2,p-1)
        if gcd(k,p-1)==1: break
    r = pow(g,k,p)
    k_inv = modinv(k,p-1)
    s = (k_inv*(msg_hash_int - x*r)) % (p-1)
    return (r,s)

def elgamal_verify(msg_hash_int, sig, pub):
    p,g,y = pub['p'],pub['g'],pub['y']
    r,s = sig
    if not (0 < r < p): return False
    v1 = pow(g,msg_hash_int,p)
    v2 = (pow(y,r,p)*pow(r,s,p))%p
    return v1==v2

# ---------------------------
# Correct Schnorr: proper p,q,g where q | (p-1)
# ---------------------------
def find_schnorr_group(q_bits=128, p_bits=256, trials=2000):
    """
    Find (p, q, g) such that q is prime, p = k*q + 1 is prime, and g has order q.
    This is a demo/faster search (not for production). If not found quickly, retries.
    """
    for _ in range(trials):
        q = generate_prime(q_bits)
        # try small multipliers k so p has desired bit length
        k_min = (1 << (p_bits-1)) // q
        k_max = (1 << p_bits) // q
        # iterate a few random k values rather than entire range
        for __ in range(200):
            k = random.randrange(max(2, k_min), max(k_min+1, k_min+1000))
            p = k * q + 1
            if p.bit_length() != p_bits:
                continue
            if is_probable_prime(p):
                # find generator g of subgroup of order q:
                for attempt in range(50):
                    h = random.randrange(2, p-1)
                    g = pow(h, (p-1)//q, p)
                    if g != 1:
                        return p, q, g
    # fallback (very unlikely in demo): try different sizes
    raise Exception("Failed to find Schnorr group (try re-running)")

def schnorr_sign(msg_hash_int, priv=None):
    """
    Produce a Schnorr signature. For demo we generate a fresh Schnorr group
    (p,q,g) where q | (p-1), choose private x, public y = g^x, and compute signature:
      k random in [1,q-1], r = g^k mod p
      e = (msg_hash_int + r) mod q
      s = (k + x*e) mod q
    Returns a dict containing all parameters and signature values needed for verification.
    """
    # generate a proper Schnorr group
    p, q, g = find_schnorr_group(q_bits=128, p_bits=256)
    x = random.randrange(1, q)          # private key
    y = pow(g, x, p)                    # public key
    k = random.randrange(1, q)
    r = pow(g, k, p)
    e = (msg_hash_int + r) % q
    s = (k + x * e) % q
    return {'p': p, 'q': q, 'g': g, 'y': y, 'r': r, 's': s, 'e': e}

def schnorr_verify(msg_hash_int, sig):
    """
    Verify a Schnorr signature produced by schnorr_sign above.
    Expects sig to be the dict returned (contains p,q,g,y,r,s,e).
    """
    try:
        p = sig['p']; q = sig['q']; g = sig['g']
        y = sig['y']; r = sig['r']; s_val = sig['s']; e_val = sig['e']
    except Exception:
        print("[DEBUG] schnorr_verify: malformed signature object.")
        return False
    # compute v = g^s * y^{-e} mod p
    # note: y^{-e} = pow(y, q - e, p) since y^q = 1 in subgroup
    v = (pow(g, s_val, p) * pow(y, (q - e_val) % q, p)) % p
    e_check = (msg_hash_int + v) % q
    return e_check == e_val


def dh_mac_sign(msg, key):
    return hmac.new(key.to_bytes(32,'big'), msg, hashlib.sha256).digest()

def dh_mac_verify(msg, mac, key):
    expected = hmac.new(key.to_bytes(32,'big'), msg, hashlib.sha256).digest()
    return hmac.compare_digest(expected, mac)

# ================================================================
# CLASSICAL CIPHERS
# ================================================================

# ---------- Affine ----------
def affine_apply(data, a, b):
    return bytes([(a*x + b) % 256 for x in data])
def affine_invert(data, a, b):
    a_inv = modinv(a, 256)
    return bytes([(a_inv * (x - b)) % 256 for x in data])

# ---------- Additive ----------
def additive_apply(data, k):
    return bytes([(x + k) % 256 for x in data])
def additive_invert(data, k):
    return bytes([(x - k) % 256 for x in data])

# ---------- Multiplicative ----------
def multiplicative_apply(data, k):
    return bytes([(x * k) % 256 for x in data])
def multiplicative_invert(data, k):
    k_inv = modinv(k, 256)
    return bytes([(x * k_inv) % 256 for x in data])

# ---------- Vigenère ----------
def vigenere_apply(data, key):
    key_bytes = key.encode()
    return bytes([(b + key_bytes[i % len(key_bytes)]) % 256 for i, b in enumerate(data)])
def vigenere_invert(data, key):
    key_bytes = key.encode()
    return bytes([(b - key_bytes[i % len(key_bytes)]) % 256 for i, b in enumerate(data)])

# ---------- Columnar Transposition ----------
# Input tip: give key order like "3-1-4-2"
def columnar_apply(data, key_order):
    cols = len(key_order)
    rows = -(-len(data)//cols)
    padded = data + b'\x00'*(rows*cols - len(data))
    grid = [padded[i*cols:(i+1)*cols] for i in range(rows)]
    out = bytearray()
    for k in sorted(range(cols), key=lambda i:key_order[i]):
        for r in grid:
            out.append(r[k])
    return bytes(out) + bytes([len(data)%256])

def columnar_invert(data, key_order):
    pad_len = data[-1]; data = data[:-1]
    cols = len(key_order); rows = len(data)//cols
    inv_order = [0]*cols
    for i,k in enumerate(sorted(range(cols), key=lambda i:key_order[i])):
        inv_order[k]=i
    grid = [[0]*cols for _ in range(rows)]
    idx=0
    for k in sorted(range(cols), key=lambda i:key_order[i]):
        for r in range(rows):
            grid[r][k]=data[idx]; idx+=1
    flat=[grid[r][inv_order[i]] for r in range(rows) for i in range(cols)]
    return bytes(flat)[:-pad_len] if pad_len else bytes(flat)

# ---------- Hill Cipher ----------
# Input tip: use 2x2 matrix key, e.g. [[3,3],[2,5]]
def hill_apply(data, key_matrix):
    n = len(key_matrix)
    while len(data)%n != 0:
        data += b'X'
    out = bytearray()
    for i in range(0,len(data),n):
        block = [data[i+j] % 256 for j in range(n)]
        for row in key_matrix:
            val = sum((row[k]*block[k])%256 for k in range(n))%256
            out.append(val)
    return bytes(out)

def hill_invert(data, key_matrix):
    n=len(key_matrix)
    det = (key_matrix[0][0]*key_matrix[1][1]-key_matrix[0][1]*key_matrix[1][0])%256
    inv_det = modinv(det,256)
    inv_matrix = [
        [(key_matrix[1][1]*inv_det)%256, (-key_matrix[0][1]*inv_det)%256],
        [(-key_matrix[1][0]*inv_det)%256, (key_matrix[0][0]*inv_det)%256]
    ]
    out = bytearray()
    for i in range(0,len(data),n):
        block = [data[i+j]%256 for j in range(n)]
        for row in inv_matrix:
            val = sum((row[k]*block[k])%256 for k in range(n))%256
            out.append(val)
    return bytes(out)

# ---------- Playfair Cipher ----------
# Input tip: use key like "MONARCHY" (letters only)
def generate_playfair_matrix(key):
    key = "".join(dict.fromkeys(key.upper().replace("J","I")))
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix = [c for c in key + ''.join([c for c in alphabet if c not in key])]
    return [matrix[i:i+5] for i in range(0,25,5)]

def find_pos(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c]==char: return r,c

def playfair_apply(plaintext, key):
    matrix = generate_playfair_matrix(key)
    plaintext = plaintext.upper().replace("J","I")
    if len(plaintext)%2!=0: plaintext += 'X'
    out=""
    for i in range(0,len(plaintext),2):
        a,b = plaintext[i],plaintext[i+1]
        ra,ca = find_pos(matrix,a)
        rb,cb = find_pos(matrix,b)
        if ra==rb:
            out+=matrix[ra][(ca+1)%5]+matrix[rb][(cb+1)%5]
        elif ca==cb:
            out+=matrix[(ra+1)%5][ca]+matrix[(rb+1)%5][cb]
        else:
            out+=matrix[ra][cb]+matrix[rb][ca]
    return out.encode()

def playfair_invert(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    text = ciphertext.decode().upper()
    out=""
    for i in range(0,len(text),2):
        a,b = text[i],text[i+1]
        ra,ca = find_pos(matrix,a)
        rb,cb = find_pos(matrix,b)
        if ra==rb:
            out+=matrix[ra][(ca-1)%5]+matrix[rb][(cb-1)%5]
        elif ca==cb:
            out+=matrix[(ra-1)%5][ca]+matrix[(rb-1)%5][cb]
        else:
            out+=matrix[ra][cb]+matrix[rb][ca]
    return out.encode()

# ---------- Autokey Cipher ----------
# Input tip: use ASCII text key like "KEY"
# ---------- Autokey Cipher (byte-safe) ----------
# Input tip: use ASCII text key like "KEY"
def autokey_apply(data, key):
    """
    Byte-safe Autokey encryption:
      Each byte is added (mod 256) to the corresponding key byte.
      The key stream begins with the provided ASCII key and then uses previous plaintext bytes.
    Works safely even if data contains non-UTF-8 bytes.
    """
    key_bytes = key.encode()
    key_stream = bytearray(key_bytes)
    out = bytearray()
    for i, b in enumerate(data):
        # extend key stream with plaintext bytes as we go
        if i >= len(key_stream):
            key_stream.append(data[i - len(key_bytes)])
        out.append((b + key_stream[i % len(key_stream)]) % 256)
    return bytes(out)

def autokey_invert(data, key):
    """
    Byte-safe Autokey decryption (inverse of autokey_apply).
    Regenerates key stream dynamically as decrypted bytes are recovered.
    """
    key_bytes = key.encode()
    out = bytearray()
    for i, b in enumerate(data):
        if i < len(key_bytes):
            k = key_bytes[i]
        else:
            k = out[i - len(key_bytes)]
        out.append((b - k) % 256)
    return bytes(out)


# ================================================================
# AES / DES / 3DES
# ================================================================
def pkcs7_pad(data, block): pad = block - (len(data)%block); return data + bytes([pad])*pad
def pkcs7_unpad(data): return data[:-data[-1]]
def derive_key(passphrase, bits): return hashlib.sha256(passphrase.encode()).digest()[:bits//8]

# ---------- AES ----------
def aes_apply(data, passphrase, bits=128, mode='CBC'):
    key = derive_key(passphrase,bits); mode=mode.upper()
    if mode=='ECB':
        cipher=AES.new(key,AES.MODE_ECB); return cipher.encrypt(pkcs7_pad(data,16))
    if mode=='CBC':
        iv=get_random_bytes(16); cipher=AES.new(key,AES.MODE_CBC,iv)
        return iv+cipher.encrypt(pkcs7_pad(data,16))
    if mode=='CFB':
        iv=get_random_bytes(16); cipher=AES.new(key,AES.MODE_CFB,iv)
        return iv+cipher.encrypt(data)
    if mode=='CTR':
        nonce=get_random_bytes(8); cipher=AES.new(key,AES.MODE_CTR,nonce=nonce)
        return nonce+cipher.encrypt(data)

def aes_invert(ct, passphrase, bits=128, mode='CBC'):
    key=derive_key(passphrase,bits); mode=mode.upper()
    if mode=='ECB':
        cipher=AES.new(key,AES.MODE_ECB); return pkcs7_unpad(cipher.decrypt(ct))
    if mode=='CBC':
        iv,body=ct[:16],ct[16:]; cipher=AES.new(key,AES.MODE_CBC,iv)
        return pkcs7_unpad(cipher.decrypt(body))
    if mode=='CFB':
        iv,body=ct[:16],ct[16:]; cipher=AES.new(key,AES.MODE_CFB,iv)
        return cipher.decrypt(body)
    if mode=='CTR':
        nonce,body=ct[:8],ct[8:]; cipher=AES.new(key,AES.MODE_CTR,nonce=nonce)
        return cipher.decrypt(body)

# ---------- DES / 3DES ----------
# ---------- DES / 3DES (extended modes: ECB, CBC, CFB, CTR) ----------
def des_apply(data, passphrase, triple=False, mode='CBC'):
    """
    DES/3DES encrypt supporting ECB, CBC, CFB, CTR.
    - triple=True uses DES3 (3DES), else DES.
    - For CBC/CFB we prefix the ciphertext with IV (block size = 8 bytes).
    - For CTR we prefix with a nonce of length 8 bytes.
    - CFB does NOT use PKCS7 padding (stream mode), CBC/ECB do.
    """
    keylen = 24 if triple else 8   # use 24 bytes for 3DES (PyCryptodome supports 16/24; prefer 24)
    # Derive a key of requested length from SHA-256 digest (demo only)
    key_material = hashlib.sha256(passphrase.encode()).digest()
    key = key_material[:keylen]
    cls = DES3 if triple else DES
    block = cls.block_size

    mode = mode.upper()
    if mode == 'ECB':
        cipher = cls.new(key, cls.MODE_ECB)
        return cipher.encrypt(pkcs7_pad(data, block))
    if mode == 'CBC':
        iv = get_random_bytes(block)
        cipher = cls.new(key, cls.MODE_CBC, iv)
        return iv + cipher.encrypt(pkcs7_pad(data, block))
    if mode == 'CFB':
        iv = get_random_bytes(block)
        cipher = cls.new(key, cls.MODE_CFB, iv)
        # CFB is a stream mode — don't pad
        return iv + cipher.encrypt(data)
    if mode == 'CTR':
        # For CTR we use an 8-byte nonce (DES block size = 8)
        nonce = get_random_bytes(8)
        cipher = cls.new(key, cls.MODE_CTR, nonce=nonce)
        return nonce + cipher.encrypt(data)

    raise ValueError("Unsupported DES mode. Choose ECB/CBC/CFB/CTR.")

def des_invert(ct, passphrase, triple=False, mode='CBC'):
    """
    Inverse for des_apply. Expects IV/nonce prefixed for CBC/CFB/CTR.
    """
    keylen = 24 if triple else 8
    key_material = hashlib.sha256(passphrase.encode()).digest()
    key = key_material[:keylen]
    cls = DES3 if triple else DES
    block = cls.block_size

    mode = mode.upper()
    if mode == 'ECB':
        cipher = cls.new(key, cls.MODE_ECB)
        return pkcs7_unpad(cipher.decrypt(ct))
    if mode == 'CBC':
        iv, body = ct[:block], ct[block:]
        cipher = cls.new(key, cls.MODE_CBC, iv)
        return pkcs7_unpad(cipher.decrypt(body))
    if mode == 'CFB':
        iv, body = ct[:block], ct[block:]
        cipher = cls.new(key, cls.MODE_CFB, iv)
        return cipher.decrypt(body)
    if mode == 'CTR':
        nonce, body = ct[:8], ct[8:]
        cipher = cls.new(key, cls.MODE_CTR, nonce=nonce)
        return cipher.decrypt(body)

    raise ValueError("Unsupported DES mode. Choose ECB/CBC/CFB/CTR.")

# ================================================================
# STATE CLASS
# ================================================================
class State:
    def __init__(self, owner=""):
        self.owner = owner
        self.msg = b''
        self.hash = '1'
        self.kex = 'rsa'
        self.sig_choice = 'rsa'
        self.cipher_choice = None
        self.apply_mode = 'after'
        self.signature = None
        self.ct = None
        self.shared_key = None
        self.add_k = 3
        self.mult_k = 7
        self.affine_a = 5
        self.affine_b = 8
        self.vig_key = 'key'
        self.trans_key = [3,1,4,2]
        self.hill_key = [[3,3],[2,5]]
        self.playfair_key = "MONARCHY"
        self.autokey_key = "KEY"
        self.aes_bits = 128
        self.aes_mode = 'CBC'
        self.aes_pass = 'demoaes'
        self.des_pass = 'demodes'
        self.des_triple = False
        self.des_mode = 'CBC'
        self.rsa = None
        self.elg = None
        self.rabin = None
        self.ec = None

# Initialize Alice and Bob
alice = State("Alice")
bob = State("Bob")

# ================================================================
# GENERIC CIPHER APPLY/INVERT
# ================================================================
def apply_cipher(data, s):
    c = s.cipher_choice
    if c == 'affine': return affine_apply(data, s.affine_a, s.affine_b)
    if c == 'add': return additive_apply(data, s.add_k)
    if c == 'mult': return multiplicative_apply(data, s.mult_k)
    if c == 'vig': return vigenere_apply(data, s.vig_key)
    if c == 'trans': return columnar_apply(data, s.trans_key)
    if c == 'hill': return hill_apply(data, s.hill_key)
    if c == 'playfair': return playfair_apply(data.decode(errors='ignore'), s.playfair_key)
    if c == 'autokey': return autokey_apply(data, s.autokey_key)
    if c == 'aes': return aes_apply(data, s.aes_pass, s.aes_bits, s.aes_mode)
    if c in ('des', '3des'): return des_apply(data, s.des_pass, s.des_triple, s.des_mode)
    return data

def invert_cipher(data, s):
    c = s.cipher_choice
    if c == 'affine': return affine_invert(data, s.affine_a, s.affine_b)
    if c == 'add': return additive_invert(data, s.add_k)
    if c == 'mult': return multiplicative_invert(data, s.mult_k)
    if c == 'vig': return vigenere_invert(data, s.vig_key)
    if c == 'trans': return columnar_invert(data, s.trans_key)
    if c == 'hill': return hill_invert(data, s.hill_key)
    if c == 'playfair': return playfair_invert(data, s.playfair_key)
    if c == 'autokey': return autokey_invert(data, s.autokey_key)
    if c == 'aes': return aes_invert(data, s.aes_pass, s.aes_bits, s.aes_mode)
    if c in ('des', '3des'): return des_invert(data, s.des_pass, s.des_triple, s.des_mode)
    return data

# ================================================================
# ENCRYPTION & DECRYPTION PIPELINES
# ================================================================
def kex_encrypt(data, s):
    if s.kex == 'rsa': return rsa_encrypt_bytes(data, s.rsa)
    if s.kex == 'elg': return elgamal_encrypt_bytes(data, s.elg)
    if s.kex == 'rabin': return rabin_encrypt_bytes(data, s.rabin)
    if s.kex == 'ecc': return ec_elgamal_encrypt_bytes(data, s.ec)
    return data

def kex_decrypt(data, s):
    if s.kex == 'rsa': return rsa_decrypt_bytes(data, s.rsa)
    if s.kex == 'elg': return elgamal_decrypt_bytes(data, s.elg)
    if s.kex == 'rabin': return rabin_decrypt_bytes(data, s.rabin)
    if s.kex == 'ecc': return ec_elgamal_decrypt_bytes(data, s.ec)
    return data

# ================================================================
# SIGNATURE + VERIFY
# ================================================================
def sign_message(s):
    msg_hash = HASH_FUNCS[s.hash][1](s.msg)
    h_int = int.from_bytes(msg_hash, 'big')
    if s.sig_choice == 'rsa':
        if not s.rsa: s.rsa = rsa_gen(512)
        s.signature = rsa_sign_hash(h_int, s.rsa)
        print(f"[{s.owner}] Signed message using RSA.")
    elif s.sig_choice == 'elg':
        if not s.elg: s.elg = elgamal_gen(256)
        s.signature = elgamal_sign(h_int, s.elg)
        print(f"[{s.owner}] Signed message using ElGamal.")
    elif s.sig_choice == 'schnorr':
        s.signature = schnorr_sign(h_int, s.elg if s.elg else elgamal_gen(256))
        print(f"[{s.owner}] Signed message using Schnorr.")
    elif s.sig_choice == 'dhmac':
        s.shared_key = random.getrandbits(128)
        s.signature = dh_mac_sign(s.msg, s.shared_key)
        print(f"[{s.owner}] Generated DH-MAC signature.")

def verify_signature(s, msg):
    """
    Verbose signature verification:
    - Prints hash digests on both sides, signature integers, public key parts,
      and the intermediate values used by each verification algorithm.
    - Helps pinpoint whether the mismatch is caused by hashing differences,
      missing/corrupt signatures, or wrong keys.
    """
    print(f"[DEBUG] Verifying signature type: {s.sig_choice}, owner state: {s.owner}")
    if getattr(s, 'signature', None) is None:
        print(f"[{s.owner}] No signature present to verify. Did Alice sign before sending?")
        return

    # Compute the hash Bob will verify (digest + integer)
    digest = HASH_FUNCS[s.hash][1](msg)
    h_int = int.from_bytes(digest, 'big')
    print(f"[DEBUG] Message bytes (for verification): {msg!r}")
    print(f"[DEBUG] Hash func: {HASH_FUNCS[s.hash][0]}; digest (hex): {digest.hex()}")
    print(f"[DEBUG] Hash int (h_int): {h_int}")

    ok = False

    if s.sig_choice == 'rsa':
        pub = getattr(s, 'rsa', None)
        if not pub:
            print(f"[{s.owner}] RSA public key not found for verification.")
            ok = False
        else:
            # signature should be bytes
            sig = s.signature
            try:
                sig_int = int.from_bytes(sig, 'big')
            except Exception as e:
                print(f"[DEBUG] failed to parse RSA signature bytes: {e}")
                ok = False
                sig_int = None

            if sig_int is not None:
                print(f"[DEBUG] RSA signature int: {sig_int}")
                # compute recovered = sig^e mod n
                e = pub.get('e')
                n = pub.get('n')
                if e is None or n is None:
                    print("[DEBUG] RSA public key missing 'e' or 'n':", pub)
                    ok = False
                else:
                    recovered = pow(sig_int, e, n)
                    print(f"[DEBUG] Recovered value (sig^e mod n): {recovered}")
                    print(f"[DEBUG] Compare recovered == h_int ? -> {recovered == h_int}")
                    ok = (recovered == h_int)

    elif s.sig_choice == 'elg':
        pub = getattr(s, 'elg', None)
        sig = s.signature
        if not pub:
            print(f"[{s.owner}] ElGamal public key not found for verification.")
            ok = False
        else:
            try:
                r, ss = sig
            except Exception as e:
                print(f"[DEBUG] ElGamal signature parse error: {e}")
                ok = False
                r = ss = None
            if r is not None:
                p, g, y = pub.get('p'), pub.get('g'), pub.get('y')
                v1 = pow(g, h_int, p)
                v2 = (pow(y, r, p) * pow(r, ss, p)) % p
                print(f"[DEBUG] ElGamal values: p={p}, g={g}, y={y}")
                print(f"[DEBUG] v1 = g^h mod p = {v1}")
                print(f"[DEBUG] v2 = y^r * r^s mod p = {v2}")
                ok = (v1 == v2)

    elif s.sig_choice == 'schnorr':
        sig = s.signature
        try:
            p,q,g,y,r,s_val,e_val = [sig[k] for k in ('p','q','g','y','r','s','e')]
            print(f"[DEBUG] Schnorr sig contents: p={p}, q={q}, g={g}, y={y}, r={r}, s={s_val}, e={e_val}")
            v = (pow(g, s_val, p) * pow(y, q - e_val, p)) % p
            e_check = (h_int + v) % q
            print(f"[DEBUG] v={v}, e_check={e_check}, original e={e_val}")
            ok = (e_check == e_val)
        except Exception as ex:
            print(f"[DEBUG] Schnorr verification error: {ex}")
            ok = False

    elif s.sig_choice == 'dhmac':
        if not hasattr(s, 'shared_key') or s.shared_key is None:
            print(f"[{s.owner}] Shared key for DH-MAC missing; cannot verify.")
            ok = False
        else:
            mac = s.signature
            expected = hmac.new(s.shared_key.to_bytes(32, 'big'), msg, hashlib.sha256).digest()
            print(f"[DEBUG] DH-MAC computed: {expected.hex()}")
            print(f"[DEBUG] DH-MAC received: {mac.hex() if mac else None}")
            ok = hmac.compare_digest(expected, mac)

    else:
        print("[DEBUG] Unknown signature type:", s.sig_choice)
        ok = False

    print(f"[{s.owner}] Signature verification: {'✅ VALID' if ok else '❌ FAILED'}")
    # Also print a final hint if failed
    if not ok:
        print("[HINT] If verification failed, check:")
        print("  - Alice actually signed the same original plaintext bytes she sent.")
        print("  - The hash algorithm selected by Alice and Bob is the same.")
        print("  - The signature object & public key were copied to Bob correctly.")
        print("  - If you used a classical text cipher (Playfair/Hill/Autokey),")
        print("    ensure Alice signed the pre-cipher plaintext and Bob verifies the same recovered plaintext.")



# ================================================================
# ALICE → BOB SIMULATION
# ================================================================
def alice_encrypt_and_send():
    """
    Demo: Alice encrypts & sends to Bob, prints an Alice-side debug summary
    showing exactly what was signed/sent (hash, signature contents, public-key params,
    cipher/kex choices, ciphertext preview), then triggers Bob's receive/decrypt/verify.
    """
    # --- 1) Auto-generate KEX keys for demo if absent ---
    if alice.kex == 'rsa' and getattr(alice, 'rsa', None) is None:
        alice.rsa = rsa_gen(512); print("[Alice] RSA keys auto-generated (demo).")
    if alice.kex == 'elg' and getattr(alice, 'elg', None) is None:
        alice.elg = elgamal_gen(256); print("[Alice] ElGamal keys auto-generated (demo).")
    if alice.kex == 'rabin' and getattr(alice, 'rabin', None) is None:
        alice.rabin = rabin_gen(512); print("[Alice] Rabin keys auto-generated (demo).")
    if alice.kex == 'ecc' and getattr(alice, 'ec', None) is None:
        alice.ec = ec_gen(192); print("[Alice] EC-ElGamal keys auto-generated (demo).")

    # --- 1a) Auto-sign if absent (demo convenience) ---
    if getattr(alice, 'signature', None) is None:
        print("[Alice] No signature found — auto-signing now (demo).")
        sign_message(alice)

    # --- 2) Copy KEX keys to Bob for decryption (demo-only) ---
    if alice.kex == 'rsa' and getattr(alice, 'rsa', None):
        bob.rsa = alice.rsa
    elif alice.kex == 'elg' and getattr(alice, 'elg', None):
        bob.elg = alice.elg
    elif alice.kex == 'rabin' and getattr(alice, 'rabin', None):
        bob.rabin = alice.rabin
    elif alice.kex == 'ecc' and getattr(alice, 'ec', None):
        bob.ec = alice.ec

    # --- 3) Ensure Bob has public verification info if needed ---
    if alice.sig_choice == 'rsa' and getattr(alice, 'rsa', None):
        if getattr(bob, 'rsa', None) is None:
            bob.rsa = {'n': alice.rsa['n'], 'e': alice.rsa['e']}
        else:
            if 'e' not in bob.rsa and 'e' in alice.rsa: bob.rsa['e'] = alice.rsa['e']
    if alice.sig_choice == 'elg' and getattr(alice, 'elg', None):
        if getattr(bob, 'elg', None) is None:
            bob.elg = {'p': alice.elg['p'], 'g': alice.elg['g'], 'y': alice.elg['y']}
        else:
            for k in ('p','g','y'):
                if k not in bob.elg and k in alice.elg: bob.elg[k] = alice.elg[k]
    if alice.sig_choice == 'dhmac' and hasattr(alice, 'shared_key'):
        bob.shared_key = alice.shared_key

    # Copy signature and metadata
    bob.signature = alice.signature
    bob.kex = alice.kex
    bob.cipher_choice = alice.cipher_choice
    bob.sig_choice = alice.sig_choice
    bob.apply_mode = alice.apply_mode
    bob.hash = alice.hash

    # --- 4) Perform encryption according to apply_mode ---
    data = alice.msg
    if alice.apply_mode == 'before':
        data = apply_cipher(data, alice)
        data = kex_encrypt(data, alice)
    else:
        data = kex_encrypt(data, alice)
        data = apply_cipher(data, alice)

    alice.ct = data
    bob.ct = data

    # --- 5) Print Alice-side debug summary (menu-like) ---
    print("\n" + "="*60)
    print("[ALICE DEBUG SUMMARY] — what Alice signed & sent")
    print("- Message (plaintext bytes):", alice.msg)
    digest = HASH_FUNCS[alice.hash][1](alice.msg)
    print(f"- Hash function: {HASH_FUNCS[alice.hash][0]}")
    print(f"- Digest (hex): {digest.hex()}")
    print(f"- Digest length: {len(digest)} bytes")
    print(f"- Signature scheme: {alice.sig_choice.upper()}")
    # Print signature contents nicely depending on type
    if alice.sig_choice == 'rsa':
        sig_bytes = alice.signature
        print(f"  - RSA signature (hex, len={len(sig_bytes)}): {sig_bytes.hex()}")
        # show public verification fields
        if getattr(alice, 'rsa', None):
            print(f"  - RSA pub (n bitlen={alice.rsa['n'].bit_length()} e={alice.rsa['e']})")
    elif alice.sig_choice == 'elg':
        r,s = alice.signature
        print(f"  - ElGamal signature r={r} s={s}")
        if getattr(alice,'elg',None):
            print(f"  - ElGamal pub p bitlen={alice.elg['p'].bit_length()} g={alice.elg['g']} y={alice.elg['y']}")
    elif alice.sig_choice == 'schnorr':
        sig = alice.signature
        # sig contains p,q,g,y,r,s,e
        print("  - Schnorr signature parameters:")
        for k in ('p','q','g','y','r','s','e'):
            print(f"     {k} = {sig.get(k)}")
    elif alice.sig_choice == 'dhmac':
        print(f"  - DH-MAC (HMAC-SHA256) tag (hex): {alice.signature.hex()}")
        if hasattr(alice,'shared_key'): print(f"  - shared_key (int): {alice.shared_key}")

    print(f"- KEX (public-key) chosen: {alice.kex.upper()}")
    if alice.kex == 'rsa' and getattr(alice,'rsa',None):
        print(f"  - RSA n bitlen: {alice.rsa['n'].bit_length()}, e: {alice.rsa['e']}")
    if alice.kex == 'elg' and getattr(alice,'elg',None):
        print(f"  - ElGamal p bitlen: {alice.elg['p'].bit_length()}, g: {alice.elg['g']}, y: {alice.elg['y']}")
    if alice.kex == 'rabin' and getattr(alice,'rabin',None):
        print(f"  - Rabin n bitlen: {alice.rabin['n'].bit_length()}")
    if alice.kex == 'ecc' and getattr(alice,'ec',None):
        print(f"  - EC curve p bitlen: {alice.ec['curve']['p'].bit_length()}, G: {alice.ec['G']}")

    print(f"- Cipher chosen: {alice.cipher_choice}")
    if alice.cipher_choice == 'aes':
        print(f"  - AES-{alice.aes_bits}-{alice.aes_mode}, passphrase: '{alice.aes_pass}'")
    if alice.cipher_choice in ('des','3des'):
        print(f"  - {'3DES' if alice.des_triple else 'DES'}-{alice.des_mode}, passphrase: '{alice.des_pass}'")
    if alice.cipher_choice == 'trans':
        print(f"  - Columnar key order: {alice.trans_key} (input like '3-1-4-2')")
    if alice.cipher_choice == 'hill':
        print(f"  - Hill 2x2 key matrix: {alice.hill_key} (input like '3,3,2,5')")
    if alice.cipher_choice == 'playfair':
        print(f"  - Playfair key: '{alice.playfair_key}' (letters only)")
    if alice.cipher_choice == 'autokey':
        print(f"  - Autokey initial key: '{alice.autokey_key}'")

    print(f"- Apply mode: {alice.apply_mode} (cipher BEFORE/AFTER KEX)")
    print(f"- Ciphertext length: {len(alice.ct)} bytes")
    # show short hex preview (first 64 bytes)
    preview = alice.ct[:64].hex()
    if len(alice.ct) > 64: preview += "..."
    print(f"- Ciphertext preview (hex): {preview}")
    print("="*60 + "\n")

    # --- 6) Trigger Bob to receive & decrypt (so you see Bob's output too) ---
    bob_receive_and_decrypt()


def bob_receive_and_decrypt():
    data = bob.ct
    if bob.apply_mode == 'before':
        data = kex_decrypt(data, bob)
        data = invert_cipher(data, bob)
    else:
        data = invert_cipher(data, bob)
        data = kex_decrypt(data, bob)
    print(f"[Bob] Decrypted message: {data.decode(errors='ignore')}")
    verify_signature(bob, data)

def tamper_message():
    if not bob.ct:
        print("No ciphertext to tamper with.")
        return
    ct_list = bytearray(bob.ct)
    if len(ct_list) > 5:
        ct_list[5] ^= 0xFF  # flip a byte
    bob.ct = bytes(ct_list)
    print("⚠️ Ciphertext tampered! Bob will now receive a corrupted message.")

# ================================================================
# MENU SYSTEM
# ================================================================
def choose_kex(s):
    print("Select KEX (Public-Key Encryption): 1.RSA  2.ElGamal  3.Rabin  4.EC-ElGamal")
    ch = input("Choice: ").strip()
    s.kex = {'1':'rsa','2':'elg','3':'rabin','4':'ecc'}.get(ch,'rsa')

def choose_signature(s):
    print("Select Signature Scheme: 1.RSA  2.ElGamal  3.Schnorr  4.DH-MAC")
    ch = input("Choice: ").strip()
    s.sig_choice = {'1':'rsa','2':'elg','3':'schnorr','4':'dhmac'}.get(ch,'rsa')

def choose_cipher(s):
    print("Select Cipher:")
    print("1.Affine  2.Additive  3.Multiplicative  4.Vigenère  5.Columnar")
    print("6.Hill  7.Playfair  8.Autokey  9.AES  10.DES / 3DES")
    ch = input("Choice: ").strip()
    s.apply_mode = input("Apply BEFORE or AFTER KEX? [after]: ").strip().lower() or 'after'

    if ch == '1':
        s.cipher_choice = 'affine'
    elif ch == '2':
        s.cipher_choice = 'add'
        s.add_k = int(input("Enter key (0-255) [3]: ") or '3')
    elif ch == '3':
        s.cipher_choice = 'mult'
        s.mult_k = int(input("Enter key (coprime with 256) [7]: ") or '7')
    elif ch == '4':
        s.cipher_choice = 'vig'
        s.vig_key = input("Enter Vigenère ASCII key [key]: ") or 'key'
    elif ch == '5':
        s.cipher_choice = 'trans'
        key = input("Enter column order like 3-1-4-2 [3-1-4-2]: ") or '3-1-4-2'
        s.trans_key = [int(k) for k in key.split('-')]
        print("  → Columnar key set:", s.trans_key)
    elif ch == '6':
        s.cipher_choice = 'hill'
        # Hill key: expect 2x2 matrix entries as comma-separated values: "3,3,2,5"
        raw = input("Enter 2x2 Hill key as 4 comma-separated ints (e.g. 3,3,2,5) [3,3,2,5]: ") or '3,3,2,5'
        vals = [int(x.strip()) for x in raw.split(',')]
        s.hill_key = [[vals[0], vals[1]], [vals[2], vals[3]]]
        print("  → Hill key set:", s.hill_key)
    elif ch == '7':
        s.cipher_choice = 'playfair'
        s.playfair_key = input("Enter Playfair key (letters only) [MONARCHY]: ") or 'MONARCHY'
    elif ch == '8':
        s.cipher_choice = 'autokey'
        s.autokey_key = input("Enter Autokey key [KEY]: ") or 'KEY'
    elif ch == '9':
        s.cipher_choice = 'aes'
        bits = input("AES key bits (128/192/256) [128]: ").strip() or '128'
        mode = input("AES mode (ECB/CBC/CFB/CTR) [CBC]: ").strip().upper() or 'CBC'
        s.aes_bits = int(bits)
        s.aes_mode = mode
        s.aes_pass = input("AES passphrase [demoaes]: ") or 'demoaes'
        print(f"  → AES-{s.aes_bits}-{s.aes_mode} set")
    elif ch == '10':
        s.cipher_choice = '3des' if input("Use 3DES? (y/n) [n]: ").strip().lower().startswith('y') else 'des'
        mode = input("DES mode (ECB/CBC/CFB/CTR) [CBC]: ").strip().upper() or 'CBC'
        s.des_triple = (s.cipher_choice == '3des')
        s.des_mode = mode
        s.des_pass = input("DES/3DES passphrase [demodes]: ") or 'demodes'
        print(f"  → {'3DES' if s.des_triple else 'DES'}-{s.des_mode} set")
    else:
        print("Invalid choice.")
        return

    print(f"[{s.owner}] Cipher selected: {s.cipher_choice.upper()}")


def show_state():
    print(json.dumps({
        'Alice': {'hash': HASH_FUNCS[alice.hash][0],'kex': alice.kex,'cipher': alice.cipher_choice,'signature': alice.sig_choice},
        'Bob': {'kex': bob.kex,'cipher': bob.cipher_choice,'signature': bob.sig_choice}
    }, indent=2))

# ================================================================
# MAIN MENU
# ================================================================
def main():
    print("\n🔰 ALICE–BOB CRYPTO SUITE (VIVA DEMO) 🔰")
    while True:
        print("\n=== MAIN MENU ===")
        print("1. Alice: Enter message")
        print("2. Alice: Choose hash, KEX, cipher, signature")
        print("3. Alice: Sign message")
        print("4. Alice: Encrypt & send to Bob")
        print("5. Bob: Receive & decrypt")
        print("6. Tamper with ciphertext (simulate attack)")
        print("7. Show state")
        print("0. Exit")
        ch = input("Select: ").strip()
        if ch == '0': break
        elif ch == '1': alice.msg = input("[Alice] Enter message: ").encode()
        elif ch == '2':
            print("Choose hash: 1.SHA-256 2.SHA-1 3.MD5")
            alice.hash = input("Choice: ").strip() or '1'
            choose_kex(alice); choose_cipher(alice); choose_signature(alice)
        elif ch == '3': sign_message(alice)
        elif ch == '4': alice_encrypt_and_send()
        elif ch == '5': bob_receive_and_decrypt()
        elif ch == '6': tamper_message()
        elif ch == '7': show_state()
        else: print("Invalid choice.")

if __name__ == "__main__":
    main()
maindes.py
Displaying maindes.py.
