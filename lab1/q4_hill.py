"""Lab 1, Q4. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q4-hill.py
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
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x

    raise ValueError("No modular inverse; the key must be coprime with the modulus.")



# ---------- INVERT KEY MATRIX ----------
# Compute determinant inverse and the adjugate, all modulo 26.
# A nonzero determinant is not enough: gcd(determinant,26) must be 1.
def invert_key_matrix(key):
    a = key[0][0]
    b = key[0][1]
    c = key[1][0]
    d = key[1][1]
    det = (a * d - b * c) % 26
    inv = find_modular_inverse(det, 26)

    return [
        [(inv * d) % 26, (inv * -b) % 26],
        [(inv * -c) % 26, (inv * a) % 26]]



# ---------- TRANSFORM LETTER PAIR ----------
# Treat two letters as a column vector and multiply by the supplied 2x2 matrix.
# This helper works with the original matrix to encrypt or its inverse to decrypt.
def transform_letter_pair(a, b, key):
    x = ord(a) - ord("A")
    y = ord(b) - ord("A")

    p = (key[0][0] * x + key[0][1] * y) % 26
    q = (key[1][0] * x + key[1][1] * y) % 26

    return chr(p + ord("A")) + chr(q + ord("A"))



# ---------- ENCRYPT HILL ----------
# Validate the matrix, pad an odd letter count with X, and transform each pair.
# Column-vector convention matters; a row-vector solution has different output.
def encrypt_hill(text, key):
    invert_key_matrix(key)  # Check that decryption is possible.
    text = clean_text(text)
    if len(text) % 2 != 0:
        text += "X"

    result = ""

    # Work through each letter or letter-pair in order.
    for i in range(0, len(text), 2):
        result += transform_letter_pair(text[i], text[i + 1], key)

    return result



# ---------- DECRYPT HILL ----------
# Transform each pair using the modular inverse of the encryption matrix.
# Keep any trailing padding until you know it was inserted, not part of the message.
def decrypt_hill(text, key):
    text = clean_text(text)
    if len(text) % 2 != 0:
        raise ValueError("Ciphertext must contain complete letter pairs.")

    ik = invert_key_matrix(key)
    result = ""

    for i in range(0, len(text), 2):
        result += transform_letter_pair(text[i], text[i + 1], ik)

    return result



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
# Classical ciphers have no authentication: a changed ciphertext need not raise an error.
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    text = input('Enter plaintext: [Enter = We live in an insecure world]: ')

    if text == "":
        text = 'We live in an insecure world'

    print("Enter the 2 x 2 key matrix:")
    a = input('Enter a: [Enter = 3]: ')

    if a == "":
        a = '3'

    a = int(a)
    b = input('Enter b: [Enter = 3]: ')

    if b == "":
        b = '3'

    b = int(b)
    c = input('Enter c: [Enter = 2]: ')

    if c == "":
        c = '2'

    c = int(c)
    d = input('Enter d: [Enter = 7]: ')

    if d == "":
        d = '7'

    d = int(d)

    key = [[a, b], [c, d]]
    det = (a * d - b * c) % 26

    if gcd(det, 26) != 1:
        print("Invalid key matrix as det isn't coprime with 26")
    else:
        ct = encrypt_hill(text, key)
        pt = decrypt_hill(ct, key)

        print("Ciphertext:", ct)
        print("Decrypted text:", pt)

    print("Column vectors are used. The final X may be padding.")




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
clean = clean_text
mod_inv = find_modular_inverse
inv_matrix = invert_key_matrix
change = transform_letter_pair
encrypt = encrypt_hill
decrypt = decrypt_hill



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
