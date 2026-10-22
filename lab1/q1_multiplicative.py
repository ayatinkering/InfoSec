"""Lab 1, Q1. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q1-mult.py
"""

from math import gcd

def clean(s):
    ans = ""
    for c in s.upper():
        if "A" <= c <= "Z":
            ans += c

    return ans

# FINDING MULTIPLICATIVE INVERSE IN MOD m=26
def mod_inv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse; the key must be coprime with the modulus.")


def encrypt(s, k):
    if gcd(k, 26) != 1:
        raise ValueError("Multiplicative key must be coprime with 26.")
    s = clean(s)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((x * k) % 26 + ord("A"))
    return ans


def decrypt(s, k):
    s = clean(s)
    inv = mod_inv(k, 26)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((x * inv) % 26 + ord("A"))
    return ans


def main():
    s = (input("Enter plaintext: [Enter = I am learning information security]: ") or "I am learning information security")
    k = int((input("Enter key: [Enter = 15]: ") or "15"))

    if gcd(k, 26) != 1:
        print("Invalid key. Key must be coprime with 26.")
    else:
        c = encrypt(s, k)
        p = decrypt(c, k)

        print("Ciphertext:", c)
        print("Decrypted text:", p)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
