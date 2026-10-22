"""Small crypto functions used by the voting question.

Read one block at a time. Each function performs only the operation in its name.
RSA size and AES mode follow the question exactly. Small ElGamal/Paillier
parameters keep this classroom demonstration quick; this is not a real election.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, isPrime
from Crypto.Random import get_random_bytes
from secrets import randbelow
from math import gcd



# ---------- HASH THE EXACT BALLOT FILE CONTENTS ----------
# HASH TWIST: change SHA512 here only if the question specifies another hash.
def hash_ballot(ballot_bytes):
    return SHA512.new(ballot_bytes).digest()



# ---------- AES-256 CBC: ENCRYPT THE BALLOT ----------
# The key is 32 bytes; the IV/block size is still 16 bytes.
def encrypt_ballot(ballot_bytes, aes_key):
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    padded_ballot = pad(ballot_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_ballot)
    return iv, ciphertext



# ---------- AES-256 CBC: DECRYPT THE BALLOT ----------
# The SAME key and IV are required. CBC itself has no authentication tag.
def decrypt_ballot(ciphertext, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    padded_ballot = cipher.decrypt(ciphertext)
    return unpad(padded_ballot, AES.block_size)



# ---------- RSA: WRAP / UNWRAP ONLY THE AES SESSION KEY ----------
# Election setup creates RSA-4096. Do not try to encrypt the full file with RSA.
def wrap_aes_key(aes_key, public_key):
    cipher = PKCS1_OAEP.new(public_key, SHA256)
    return cipher.encrypt(aes_key)



# ---------- RSA: RECOVER THE SESSION KEY WITH THE PRIVATE KEY ----------
def unwrap_aes_key(wrapped_key, private_key):
    cipher = PKCS1_OAEP.new(private_key, SHA256)
    return cipher.decrypt(wrapped_key)



# ---------- ELGAMAL: GENERATE ONE VOTER'S SIGNING KEYS ----------
# Public = (p,g,y); private = x. These are SIGNATURE keys, not RSA keys.
def generate_signature_keys():
    p = getPrime(256)
    g = 2
    x = randbelow(p - 2) + 1
    y = pow(g, x, p)
    return [p, g, y], x



# ---------- ELGAMAL: SIGN THE SHA-512 HASH ----------
# New k for every signature. Keep this signature if you edit received data later.
def sign_hash(digest, public_key, private_key):
    p, g, y = public_key
    h = int.from_bytes(digest, 'big')

    while True:
        k = randbelow(p - 2) + 1

        if gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    s = pow(k, -1, p - 1) * (h - private_key * r) % (p - 1)
    return [r, s]



# ---------- ELGAMAL: VERIFY USING THE VOTER PUBLIC KEY ----------
def verify_hash_signature(digest, signature, public_key):
    p, g, y = public_key
    r, s = signature

    if not 1 <= r < p or not 0 <= s < p - 1:
        return False

    h = int.from_bytes(digest, 'big')
    left = pow(g, h, p)
    right = pow(y, r, p) * pow(r, s, p) % p
    return left == right



# ---------- TIMESTAMP AUTHORITY: SIGN / VERIFY A TIMESTAMP ----------
# The authority is a separate key holder. Bind its time to this ballot's hash.
def sign_timestamp(digest, timestamp, authority_private):
    timestamp_data = digest + timestamp.encode('utf-8')
    signer = pss.new(authority_private)
    return signer.sign(SHA512.new(timestamp_data))



# ---------- CHECK THE AUTHORITY SIGNATURE ON THE HASH AND TIME ----------
def verify_timestamp(digest, timestamp, signature, authority_public):
    timestamp_data = digest + timestamp.encode('utf-8')
    verifier = pss.new(authority_public)

    try:
        verifier.verify(SHA512.new(timestamp_data), signature)
        return True
    except (ValueError, TypeError):
        return False



# ---------- TWO-TRUSTEE PAILLIER KEY SETUP ----------
# This is the only mathematically longer block. Reuse it unchanged in an exam.
# Safe primes p=2p'+1 and q=2q'+1 allow 2-of-2 partial decryption.
# d=0 mod p'q' and d=1 mod n; share a line f(i)=d+a*i mod n*p'*q'.
# No complete Paillier private key is written to the election server file.
def safe_prime(bits):
    while True:
        smaller_prime = getPrime(bits - 1)
        prime = 2 * smaller_prime + 1

        if isPrime(prime):
            return prime, smaller_prime



# ---------- SPLIT THE DECRYPTION EXPONENT INTO TWO TRUSTEE SHARES ----------
def generate_threshold_keys(bits=256):
    while True:
        p, p_small = safe_prime(bits // 2)
        q, q_small = safe_prime(bits // 2)
        n = p * q
        m = p_small * q_small

        if p != q and gcd(n, m) == 1:
            break

    d = m * pow(m, -1, n)
    share_modulus = n * m
    slope = randbelow(share_modulus)
    share1 = (d + slope) % share_modulus
    share2 = (d + 2 * slope) % share_modulus
    return n, share1, share2



# ---------- PAILLIER: ENCRYPT ONE INTEGER ----------
# g=n+1. The ciphertext arithmetic is modulo n^2.
def encrypt_vote(message, n):
    if not 0 <= message < n:
        raise ValueError('Paillier message must be between 0 and n-1.')

    while True:
        r = randbelow(n - 1) + 1

        if gcd(r, n) == 1:
            break

    message_part = pow(n + 1, message, n * n)
    random_part = pow(r, n, n * n)
    return message_part * random_part % (n * n)



# ---------- PAILLIER: ADD ENCRYPTED VOTES ----------
# Multiplying ciphertexts adds plaintext values. No decryption happens here.
def add_encrypted_votes(first, second, n):
    return first * second % (n * n)



# ---------- EACH TRUSTEE PARTIALLY DECRYPTS ONLY THE FINAL TOTAL ----------
# For two trustees Delta=2, so each contribution is C^(2*Delta*share).
def partial_decrypt(total_ciphertext, share, n):
    return pow(total_ciphertext, 4 * share, n * n)



# ---------- COMBINE TWO PARTIAL RESULTS ----------
# Two-share interpolation coefficients are 4 and -2.
# The combined value encodes 16*total; divide by 16 modulo n.
# This combines partial decryptions, not raw private-key shares.
def combine_partial_results(partial1, partial2, n):
    first = pow(partial1, 8, n * n)
    second = pow(partial2, -4, n * n)
    combined = first * second % (n * n)
    l_value = (combined - 1) // n
    return l_value * pow(16, -1, n) % n
