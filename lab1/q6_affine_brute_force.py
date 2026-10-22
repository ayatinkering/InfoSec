"""Lab 1, Q6. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q6-known-plaintxt-attack.py
"""

# AFFINE KNOWN PLAINTEXT ATTACK
from math import gcd

def clean(s):
    ans = ""
    for c in s.upper():
        if "A" <= c <= "Z":
            ans += c
    return ans


def mod_inv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError("No modular inverse; the key must be coprime with the modulus.")


def decrypt(s, a, b):
    s = clean(s)
    inv = mod_inv(a, 26)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((inv * (x - b)) % 26 + ord("A"))
    return ans


def find_keys(p, c):
    p = clean(p)
    c = clean(c)
    if len(p) == 0 or len(p) != len(c):
        raise ValueError("Known texts must have the same nonzero letter count.")
    keys = []

    for a in range(26):
        if gcd(a, 26) != 1:
            continue

        for b in range(26):
            ok = True

            for i in range(len(p)):
                x = ord(p[i]) - ord("A")
                y = ord(c[i]) - ord("A")

                if (a * x + b) % 26 != y:
                    ok = False
                    break

            if ok:
                keys.append((a, b))
    return keys


def main():
    p = (input("Enter known plaintext: [Enter = ab]: ") or "ab")
    c = (input("Enter its ciphertext: [Enter = GL]: ") or "GL")
    s = (input("Enter target ciphertext: [Enter = XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS]: ") or "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS")

    keys = find_keys(p, c)

    if len(keys) == 0:
        print("No key found.")
    else:
        for a, b in keys:
            print("Key: a =", a, "b =", b)
            print("Plaintext:", decrypt(s, a, b))
    print("All 312 valid affine keys were tried. AKTERWARDS in the result is likely a manual typo.")


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
