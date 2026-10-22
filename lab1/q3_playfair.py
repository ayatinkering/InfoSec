"""Lab 1, Q3. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q3-playfair.py
"""

def clean(s):
    ans = ""
    for c in s.upper():
        if "A" <= c <= "Z":
            if c == "J":
                ans += "I"
            else:
                ans += c
    return ans


def make_matrix(k):
    k = clean(k)
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    s = ""
    for c in k + alpha:
        if c not in s:
            s += c

    m = []
    for i in range(5):
        m.append(list(s[i * 5:(i + 1) * 5]))
    return m

def find(m, c):
    for i in range(5):
        for j in range(5):
            if m[i][j] == c:
                return i, j

def prepare(s):
    s = clean(s)
    ans = ""
    i = 0

    while i < len(s):
        a = s[i]
        filler = "Q" if a == "X" else "X"

        if i + 1 == len(s):
            b = filler
            i += 1
        elif a == s[i + 1]:
            b = filler
            i += 1
        else:
            b = s[i + 1]
            i += 2
        ans += a + b
    return ans


def encrypt(s, m):
    s = prepare(s)
    ans = ""
    for i in range(0, len(s), 2):
        a = s[i]
        b = s[i + 1]

        r1, c1 = find(m, a)
        r2, c2 = find(m, b)
        if r1 == r2:
            ans += m[r1][(c1 + 1) % 5]
            ans += m[r2][(c2 + 1) % 5]
        elif c1 == c2:
            ans += m[(r1 + 1) % 5][c1]
            ans += m[(r2 + 1) % 5][c2]
        else:
            ans += m[r1][c2]
            ans += m[r2][c1]
    return ans


def decrypt(s, m):
    s = clean(s)
    if len(s) % 2 != 0:
        raise ValueError("Ciphertext must contain complete letter pairs.")
    ans = ""

    for i in range(0, len(s), 2):
        a = s[i]
        b = s[i + 1]

        r1, c1 = find(m, a)
        r2, c2 = find(m, b)
        if r1 == r2:
            ans += m[r1][(c1 - 1) % 5]
            ans += m[r2][(c2 - 1) % 5]
        elif c1 == c2:
            ans += m[(r1 - 1) % 5][c1]
            ans += m[(r2 - 1) % 5][c2]
        else:
            ans += m[r1][c2]
            ans += m[r2][c1]
    return ans


def main():
    s = (input("Enter plaintext: [Enter = The key is hidden under the door pad]: ") or "The key is hidden under the door pad")
    k = (input("Enter keyword: [Enter = GUIDANCE]: ") or "GUIDANCE")

    m = make_matrix(k)
    print("\nPLAYFAIR MATRIX:")
    for row in m:
        print(" ".join(row))

    c = encrypt(s, m)
    p = decrypt(c, m)

    print("Ciphertext:", c)
    print("Decrypted prepared text:", p)
    print("Decryption retains fillers; J is represented as I.")


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
