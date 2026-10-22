"""Lab 1, Q1. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q1-afffine.py
"""

from math import gcd

def clean(s):
    ans = ""
    for c in s.upper():
        if "A" <= c <= "Z":
            ans += c
    return ans

# FINDING MI
def mod_inv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse; the key must be coprime with the modulus.")


def encrypt(s, a, b):
    if gcd(a, 26) != 1:
        raise ValueError("Multiplicative key must be coprime with 26.")
    s = clean(s)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((a * x + b) % 26 + ord("A"))
    return ans


def decrypt(s, a, b):
    s = clean(s)
    inv = mod_inv(a, 26)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((inv * (x - b)) % 26 + ord("A"))
    return ans


def main():
    s = (input("Enter plaintext: [Enter = I am learning information security]: ") or "I am learning information security")
    a = int((input("Enter multiplicative key a: [Enter = 15]: ") or "15"))
    b = int((input("Enter additive key b: [Enter = 20]: ") or "20"))

    if gcd(a, 26) != 1:
        print("Invalid key. a must be coprime with 26.")
    else:
        c = encrypt(s, a, b)
        p = decrypt(c, a, b)

        print("Ciphertext:", c)
        print("Decrypted text:", p)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
