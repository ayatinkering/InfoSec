"""Lab 7: Paillier homomorphic addition (classroom key sizes)."""

from Crypto.Util.number import getPrime
from math import gcd, lcm
from secrets import randbelow



# ---------- GENERATE PAILLIER KEYS ----------
# Public = (n,g); private = (lambda,mu). g=n+1 simplifies the formulas.
# Repeat if the primes match or lambda has no inverse modulo n.
def generate_keys(bits=1024):
    if bits < 32:
        raise ValueError("Use at least 32 bits for this educational example.")

    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)

        if p == q:
            continue

        n = p * q
        g = n + 1
        lam = lcm(p - 1, q - 1)

        if gcd(lam, n) != 1:
            continue

        mu = pow(lam, -1, n)
        return (n, g), (lam, mu)



# ---------- ENCRYPT ONE INTEGER ----------
# c = g^m * r^n mod n^2. New random r hides repeated plaintext values.
# HINT: encrypt the same m twice; the ciphertexts will usually differ.
def encrypt(public_key, message):
    n, g = public_key

    if not 0 <= message < n:
        raise ValueError("Message must satisfy 0 <= message < n.")

    while True:
        r = randbelow(n - 1) + 1

        if gcd(r, n) == 1:
            break

    modulus = n * n
    message_part = pow(g, message, modulus)
    random_part = pow(r, n, modulus)
    ciphertext = message_part * random_part % modulus
    return ciphertext



# ---------- DECRYPT ONE CIPHERTEXT ----------
# First calculate u=c^lambda mod n^2; L(u)=(u-1)//n; then m=L(u)*mu mod n.
# Range checks catch malformed inputs, but Paillier does NOT authenticate data.
def decrypt(public_key, private_key, ciphertext):
    n, g = public_key
    lam, mu = private_key

    if not 0 < ciphertext < n * n or gcd(ciphertext, n) != 1:
        raise ValueError("Ciphertext must be an invertible value modulo n^2.")

    u = pow(ciphertext, lam, n * n)
    l_value = (u - 1) // n
    return l_value * mu % n



# ---------- ADD WITHOUT DECRYPTING ----------
# Multiplying Paillier ciphertexts corresponds to ADDING plaintext integers.
# HINT: this intentional malleability is why a separate integrity check is needed.
def homomorphic_add(public_key, ciphertext_a, ciphertext_b):
    n, g = public_key
    return ciphertext_a * ciphertext_b % (n * n)



# ---------- CHOOSE VALUES AND CHECK THE SUM ----------
# CHANGE a and b. Results are modulo n: a+b >= n wraps around.
# Do not add ciphertext integers directly; call homomorphic_add().
def main():
    bits = input('Educational key bits [1024]: ')

    if bits == "":
        bits = '1024'

    bits = int(bits)
    a = input('First integer [15]: ')

    if a == "":
        a = '15'

    a = int(a)
    b = input('Second integer [25]: ')

    if b == "":
        b = '25'

    b = int(b)

    public_key, private_key = generate_keys(bits)
    encrypted_a = encrypt(public_key, a)
    encrypted_b = encrypt(public_key, b)
    encrypted_sum = homomorphic_add(public_key, encrypted_a, encrypted_b)
    result = decrypt(public_key, private_key, encrypted_sum)

    print("Encrypted a:", encrypted_a)
    print("Encrypted b:", encrypted_b)
    print("Encrypted sum:", encrypted_sum)
    print("Decrypted sum:", result)
    print("Expected modulo n:", (a + b) % public_key[0])



if __name__ == "__main__":
    main()
