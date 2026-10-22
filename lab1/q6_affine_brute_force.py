"""Lab 1, Q6. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q6-known-plaintxt-attack.py
"""

# AFFINE KNOWN PLAINTEXT ATTACK
from math import gcd



# ---------- CLEAN TEXT ----------
# Keep English letters only and uppercase them; spaces/punctuation are removed.
# CHANGE input handling here only if the question asks you to preserve formatting.
def clean_text(text):
    result = ""

    for c in text.upper():
        if "A" <= c <= "Z":
            result += c

    return result



# ---------- FIND MODULAR INVERSE ----------
# Try values until a*x mod m equals 1. Ordinary division is not modular division.
# A multiplicative key must be coprime with 26; try key=2 to see rejection.
def find_modular_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x

    raise ValueError("No modular inverse; the key must be coprime with the modulus.")



# ---------- DECRYPT AFFINE ----------
# Undo addition FIRST, then multiply: P=inverse(a)*(C-b) mod 26.
# Reversing the order incorrectly changes the answer.
def decrypt_affine(text, a, b):
    text = clean_text(text)
    inv = find_modular_inverse(a, 26)
    result = ""

    for c in text:
        x = ord(c) - ord("A")
        result += chr((inv * (x - b)) % 26 + ord("A"))

    return result



# ---------- BRUTE FORCE AFFINE KEYS ----------
# Try all 312 valid (a,b) combinations and retain those matching the known pair.
# CHANGE the known pair and target ciphertext in main() for a different attack.
def brute_force_affine_keys(p, c):
    p = clean_text(p)
    c = clean_text(c)
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



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
# Classical ciphers have no authentication: a changed ciphertext need not raise an error.
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    p = input('Enter known plaintext: [Enter = ab]: ')

    if p == "":
        p = 'ab'

    c = input('Enter its ciphertext: [Enter = GL]: ')

    if c == "":
        c = 'GL'

    text = input('Enter target ciphertext: [Enter = XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS]: ')

    if text == "":
        text = 'XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS'

    keys = brute_force_affine_keys(p, c)

    if len(keys) == 0:
        print("No key found.")
    else:
        for a, b in keys:
            print("Key: a =", a, "b =", b)
            print("Plaintext:", decrypt_affine(text, a, b))

    print("All 312 valid affine keys were tried. AKTERWARDS in the result is likely a manual typo.")




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
clean = clean_text
mod_inv = find_modular_inverse
find_keys = brute_force_affine_keys
decrypt = decrypt_affine



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
