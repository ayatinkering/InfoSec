"""Lab 1, Q5. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q5-known-plaintxt-attack.py
"""

# ADDITIVE CIPHER

def clean(s):
    ans = ""
    for c in s.upper():
        if "A" <= c <= "Z":
            ans += c
    return ans


def find_key(p, c):
    p = clean(p)
    c = clean(c)
    if len(p) == 0 or len(p) != len(c):
        raise ValueError("Known texts must have the same nonzero letter count.")
    key = (ord(c[0]) - ord(p[0])) % 26
    for i in range(len(p)):
        if (ord(c[i]) - ord(p[i])) % 26 != key:
            raise ValueError("Known pairs do not share a single shift.")
    return key


def decrypt(s, k):
    ans = ""
    for c in s.upper():
        if "A" <= c <= "Z":
            x = ord(c) - ord("A")
            ans += chr((x - k) % 26 + ord("A"))
        else:
            ans += c
    return ans


def main():
    p = (input("Enter known plaintext: [Enter = yes]: ") or "yes")
    c = (input("Enter its ciphertext: [Enter = CIW]: ") or "CIW")
    s = (input("Enter target ciphertext: [Enter = XVIEWYWI]: ") or "XVIEWYWI")

    k = find_key(p, c)

    print("Recovered key:", k)
    print("Recovered plaintext:", decrypt(s, k))
    print("Known-plaintext attack. Manual input gives TREASUSE; likely a typo for TREASURE.")


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
