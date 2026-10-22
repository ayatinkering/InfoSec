"""Lab 7: share encrypted hospital counts and time Paillier encryption."""

import time

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



# ---------- COMBINE TWO ENCRYPTED CONTRIBUTIONS ----------
# The combining server uses only public information. The authorized recipient
# later uses private_key to decrypt the total, not the individual contributions.
def combine_counts(count_a, count_b, public_key):
    encrypted_a = encrypt(public_key, count_a)
    encrypted_b = encrypt(public_key, count_b)
    return homomorphic_add(public_key, encrypted_a, encrypted_b)



# ---------- TIME ONLY ENCRYPTION ----------
# Key generation and printing are outside the measured block.
def measure_encryption(public_key, message=25, repeats=100):
    if repeats <= 0:
        raise ValueError("Repetitions must be positive.")

    durations = []

    for _ in range(repeats):
        start = time.perf_counter()
        encrypt(public_key, message)
        durations.append(time.perf_counter() - start)

    return sum(durations) / repeats, min(durations), max(durations)



# ---------- INPUTS AND DEMONSTRATION ----------
# HINT: the sum is modulo n. A corrupted but valid ciphertext may change the
# answer silently; Paillier alone supplies no authenticity or tamper detection.
def main():
    bits = input('Educational key bits [1024]: ')

    if bits == "":
        bits = '1024'

    bits = int(bits)
    count_a = input('Hospital A count [150]: ')

    if count_a == "":
        count_a = '150'

    count_a = int(count_a)
    count_b = input('Hospital B count [230]: ')

    if count_b == "":
        count_b = '230'

    count_b = int(count_b)
    repeats = input('Timing repetitions [100]: ')

    if repeats == "":
        repeats = '100'

    repeats = int(repeats)

    public_key, private_key = generate_keys(bits)
    encrypted_total = combine_counts(count_a, count_b, public_key)
    total = decrypt(public_key, private_key, encrypted_total)

    print("Combined patient count:", total)
    print("Expected modulo n:", (count_a + count_b) % public_key[0])

    average, minimum, maximum = measure_encryption(public_key, repeats=repeats)
    print("Average encryption seconds:", average)
    print("Minimum:", minimum)
    print("Maximum:", maximum)



if __name__ == "__main__":
    main()
