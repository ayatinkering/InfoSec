"""Lab 1, Q2. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q2-autokey.py
"""

def clean(s):
    ans = ""
    for c in s.upper():
        if "A" <= c <= "Z":
            ans += c
    return ans

def encrypt(s, k):
    s = clean(s)
    p = []
    for c in s:
        p.append(ord(c) - ord("A"))
    keys = [k]

    for x in p:
        if len(keys) == len(p):
            break
        keys.append(x)

    ans = ""
    for i in range(len(p)):
        ans += chr((p[i] + keys[i]) % 26 + ord("A"))
    return ans


def decrypt(s, k):
    s = clean(s)
    keys = [k]
    ans = ""
    for i in range(len(s)):
        x = ord(s[i]) - ord("A")
        y = (x - keys[i]) % 26
        ans += chr(y + ord("A"))
        if len(keys) < len(s):
            keys.append(y)
    return ans


def main():
    s = (input("Enter plaintext: [Enter = the house is being sold tonight]: ") or "the house is being sold tonight")
    k = int((input("Enter numeric key: [Enter = 7]: ") or "7")) % 26

    c = encrypt(s, k)
    p = decrypt(c, k)

    print("Ciphertext:", c)
    print("Decrypted text:", p)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
