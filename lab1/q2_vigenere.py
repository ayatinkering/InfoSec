"""Lab 1, Q2. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q2-vignere.py
"""

def clean(s):
    ans = ""
    for c in s.upper():
        if "A" <= c <= "Z":
            ans += c
    return ans

def encrypt(s, k):
    s = clean(s)
    k = clean(k)
    if k == "":
        raise ValueError("Keyword must contain English letters.")
    ans = ""
    for i in range(len(s)):
        x = ord(s[i]) - ord("A")
        y = ord(k[i % len(k)]) - ord("A")
        ans += chr((x + y) % 26 + ord("A"))
    return ans


def decrypt(s, k):
    s = clean(s)
    k = clean(k)
    if k == "":
        raise ValueError("Keyword must contain English letters.")
    ans = ""
    for i in range(len(s)):
        x = ord(s[i]) - ord("A")
        y = ord(k[i % len(k)]) - ord("A")
        ans += chr((x - y) % 26 + ord("A"))
    return ans


def main():
    s = (input("Enter plaintext: [Enter = the house is being sold tonight]: ") or "the house is being sold tonight")
    k = (input("Enter keyword: [Enter = DOLLARS]: ") or "DOLLARS")

    if clean(k) == "":
        print("Keyword cannot be empty.")
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
