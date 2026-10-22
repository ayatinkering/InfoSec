"""Lab 1, Q4. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q4-hill.py
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
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse; the key must be coprime with the modulus.")

def inv_matrix(k):
    a = k[0][0]
    b = k[0][1]
    c = k[1][0]
    d = k[1][1]
    det = (a * d - b * c) % 26
    inv = mod_inv(det, 26)

    return [
        [(inv * d) % 26, (inv * -b) % 26],
        [(inv * -c) % 26, (inv * a) % 26]]

def change(a, b, k):
    x = ord(a) - ord("A")
    y = ord(b) - ord("A")

    p = (k[0][0] * x + k[0][1] * y) % 26
    q = (k[1][0] * x + k[1][1] * y) % 26

    return chr(p + ord("A")) + chr(q + ord("A"))


def encrypt(s, k):
    inv_matrix(k)  # Check that decryption is possible.
    s = clean(s)
    if len(s) % 2 != 0:
        s += "X"
    ans = ""
    for i in range(0, len(s), 2):
        ans += change(s[i], s[i + 1], k)
    return ans


def decrypt(s, k):
    s = clean(s)
    if len(s) % 2 != 0:
        raise ValueError("Ciphertext must contain complete letter pairs.")
    ik = inv_matrix(k)
    ans = ""

    for i in range(0, len(s), 2):
        ans += change(s[i], s[i + 1], ik)
    return ans


def main():
    s = (input("Enter plaintext: [Enter = We live in an insecure world]: ") or "We live in an insecure world")

    print("Enter the 2 x 2 key matrix:")
    a = int((input("Enter a: [Enter = 3]: ") or "3"))
    b = int((input("Enter b: [Enter = 3]: ") or "3"))
    c = int((input("Enter c: [Enter = 2]: ") or "2"))
    d = int((input("Enter d: [Enter = 7]: ") or "7"))

    k = [[a, b], [c, d]]
    det = (a * d - b * c) % 26

    if gcd(det, 26) != 1:
        print("Invalid key matrix as det isn't coprime with 26")
    else:
        ct = encrypt(s, k)
        pt = decrypt(ct, k)

        print("Ciphertext:", ct)
        print("Decrypted text:", pt)
    print("Column vectors are used. The final X may be padding.")


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
