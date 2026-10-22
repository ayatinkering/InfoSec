"""Lab 7: textbook RSA homomorphic multiplication, NOT RSA-OAEP."""

from Crypto.Util.number import getPrime
from math import gcd



# ---------- GENERATE TEXTBOOK RSA KEYS ----------
# Retry if e has no inverse; every later function receives its keys explicitly.
def generate_keys(bits=1024):
    if bits < 32:
        raise ValueError("Use at least 32 bits for this educational example.")

    e = 65537

    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        phi = (p - 1) * (q - 1)

        if p != q and gcd(e, phi) == 1:
            break

    n = p * q
    d = pow(e, -1, phi)
    return (n, e), (n, d)



# ---------- ENCRYPT A RAW INTEGER ----------
# Raw RSA preserves multiplication. OAEP deliberately changes this interface;
# do not swap RSA-OAEP ciphertexts into this homomorphic demonstration.
def encrypt(message, public_key):
    n, e = public_key

    if not 0 <= message < n:
        raise ValueError("Message must satisfy 0 <= message < n.")

    return pow(message, e, n)



# ---------- DECRYPT A RAW INTEGER ----------
def decrypt(ciphertext, private_key):
    n, d = private_key

    if not 0 <= ciphertext < n:
        raise ValueError("Ciphertext must satisfy 0 <= ciphertext < n.")

    return pow(ciphertext, d, n)



# ---------- MULTIPLY WITHOUT DECRYPTING ----------
# RSA: E(a)*E(b) mod n decrypts to a*b mod n.
# This is also a reason unpadded RSA does not provide message integrity.
def homomorphic_multiply(public_key, ciphertext_a, ciphertext_b):
    n, e = public_key
    return ciphertext_a * ciphertext_b % n



# ---------- TRY NEW VALUES ----------
# CHANGE a/b. If their product reaches n, the result wraps modulo n.
def main():
    bits = input('Educational key bits [1024]: ')

    if bits == "":
        bits = '1024'

    bits = int(bits)
    a = input('First integer [7]: ')

    if a == "":
        a = '7'

    a = int(a)
    b = input('Second integer [3]: ')

    if b == "":
        b = '3'

    b = int(b)

    public_key, private_key = generate_keys(bits)
    encrypted_a = encrypt(a, public_key)
    encrypted_b = encrypt(b, public_key)
    encrypted_product = homomorphic_multiply(public_key, encrypted_a, encrypted_b)
    result = decrypt(encrypted_product, private_key)

    print("Encrypted a:", encrypted_a)
    print("Encrypted b:", encrypted_b)
    print("Encrypted product:", encrypted_product)
    print("Decrypted product:", result)
    print("Expected modulo n:", a * b % public_key[0])



if __name__ == "__main__":
    main()
