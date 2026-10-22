"""Lab 1, Q1. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q1-additive.py
"""

def clean(s):
    ans = ""
    for c in s.upper():
        if "A" <= c <= "Z":
            ans += c
    return ans


def encrypt(s, k):
    s = clean(s)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((x + k) % 26 + ord("A"))
    return ans


def decrypt(s, k):
    s = clean(s)
    ans = ""
    for c in s:
        x = ord(c) - ord("A")
        ans += chr((x - k) % 26 + ord("A"))
    return ans


def main():
    s = (input("Enter plaintext: [Enter = I am learning information security]: ") or "I am learning information security")
    k = int((input("Enter key: [Enter = 20]: ") or "20"))

    c = encrypt(s, k)
    p = decrypt(c, k)

    print("Ciphertext:", c)
    print("Decrypted text:", p)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
