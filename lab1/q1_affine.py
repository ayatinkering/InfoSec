"""Lab 1, Q1. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q1-afffine.py
"""

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



# ---------- ENCRYPT AFFINE ----------
# Apply multiplication then addition: C=(multiplier*P+shift) mod 26.
# Only the multiplier needs a modular inverse; the shift may be any integer.
def encrypt_affine(text, a, b):
    if gcd(a, 26) != 1:
        raise ValueError("Multiplicative key must be coprime with 26.")

    text = clean_text(text)
    result = ""

    # Work through each letter or letter-pair in order.
    for c in text:
        x = ord(c) - ord("A")
        result += chr((a * x + b) % 26 + ord("A"))

    return result



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



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
# Classical ciphers have no authentication: a changed ciphertext need not raise an error.
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    text = input('Enter plaintext: [Enter = I am learning information security]: ')

    if text == "":
        text = 'I am learning information security'

    a = input('Enter multiplicative key a: [Enter = 15]: ')

    if a == "":
        a = '15'

    a = int(a)
    b = input('Enter additive key b: [Enter = 20]: ')

    if b == "":
        b = '20'

    b = int(b)

    if gcd(a, 26) != 1:
        print("Invalid key. a must be coprime with 26.")
    else:
        c = encrypt_affine(text, a, b)
        p = decrypt_affine(c, a, b)

        print("Ciphertext:", c)
        print("Decrypted text:", p)




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
clean = clean_text
mod_inv = find_modular_inverse
encrypt = encrypt_affine
decrypt = decrypt_affine



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
