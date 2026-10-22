"""Lab 1, Q3. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q3-playfair.py
"""



# ---------- CLEAN PLAYFAIR TEXT ----------
# Uppercase English letters and merge J into I for a 25-letter square.
# Decryption cannot reconstruct the original spaces or distinguish I from J.
def clean_playfair_text(text):
    result = ""

    for c in text.upper():
        if "A" <= c <= "Z":
            if c == "J":
                result += "I"
            else:
                result += c

    return result



# ---------- BUILD PLAYFAIR MATRIX ----------
# Place unique keyword letters first, then unused letters, into a 5x5 square.
# The same keyword and I/J convention must be used during decryption.
def build_playfair_matrix(key):
    key = clean_playfair_text(key)
    alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    text = ""
    for c in key + alpha:
        if c not in text:
            text += c

    m = []
    for i in range(5):
        m.append(list(text[i * 5:(i + 1) * 5]))

    return m



# ---------- FIND LETTER POSITION ----------
# Return the row and column containing one letter in the Playfair square.
# Row/column indices start at zero.
def find_letter_position(m, c):
    for i in range(5):
        for j in range(5):
            if m[i][j] == c:
                return i, j



# ---------- PREPARE LETTER PAIRS ----------
# Split text into pairs, separating equal letters and padding a final single letter.
# Use X as filler, or Q when the letter itself is X. Do not delete real X blindly.
def prepare_letter_pairs(text):
    text = clean_playfair_text(text)
    result = ""
    i = 0

    while i < len(text):
        a = text[i]
        # Repeated X needs a different filler, otherwise the pair stays XX.
        if a == "X":
            filler = "Q"
        else:
            filler = "X"

        if i + 1 == len(text):
            b = filler
            i += 1
        elif a == text[i + 1]:
            b = filler
            i += 1
        else:
            b = text[i + 1]
            i += 2

        result += a + b

    return result



# ---------- ENCRYPT PLAYFAIR ----------
# Same row: move right. Same column: move down. Otherwise swap columns.
# All three pair rules operate on the prepared pairs, not on single letters.
def encrypt_playfair(text, m):
    text = prepare_letter_pairs(text)
    result = ""

    # Work through each letter or letter-pair in order.
    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]

        r1, c1 = find_letter_position(m, a)
        r2, c2 = find_letter_position(m, b)
        if r1 == r2:
            result += m[r1][(c1 + 1) % 5]
            result += m[r2][(c2 + 1) % 5]
        elif c1 == c2:
            result += m[(r1 + 1) % 5][c1]
            result += m[(r2 + 1) % 5][c2]
        else:
            result += m[r1][c2]
            result += m[r2][c1]

    return result



# ---------- DECRYPT PLAYFAIR ----------
# Same row: move left. Same column: move up. The rectangle rule is unchanged.
# Inserted fillers remain; removing every X would destroy some real messages.
def decrypt_playfair(text, m):
    text = clean_playfair_text(text)
    if len(text) % 2 != 0:
        raise ValueError("Ciphertext must contain complete letter pairs.")

    result = ""

    for i in range(0, len(text), 2):
        a = text[i]
        b = text[i + 1]

        r1, c1 = find_letter_position(m, a)
        r2, c2 = find_letter_position(m, b)
        if r1 == r2:
            result += m[r1][(c1 - 1) % 5]
            result += m[r2][(c2 - 1) % 5]
        elif c1 == c2:
            result += m[(r1 - 1) % 5][c1]
            result += m[(r2 - 1) % 5][c2]
        else:
            result += m[r1][c2]
            result += m[r2][c1]

    return result



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
# Classical ciphers have no authentication: a changed ciphertext need not raise an error.
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    text = input('Enter plaintext: [Enter = The key is hidden under the door pad]: ')

    if text == "":
        text = 'The key is hidden under the door pad'

    key = input('Enter keyword: [Enter = GUIDANCE]: ')

    if key == "":
        key = 'GUIDANCE'

    m = build_playfair_matrix(key)
    print("\nPLAYFAIR MATRIX:")
    for row in m:
        print(" ".join(row))


    # Sender step: protect the ORIGINAL input and keep the returned result.
    c = encrypt_playfair(text, m)

    # Receiver step: decrypt this received copy. Change it BEFORE this line to test corruption.
    p = decrypt_playfair(c, m)

    print("Ciphertext:", c)
    print("Decrypted prepared text:", p)
    print("Decryption retains fillers; J is represented as I.")




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
clean = clean_playfair_text
make_matrix = build_playfair_matrix
find = find_letter_position
prepare = prepare_letter_pairs
encrypt = encrypt_playfair
decrypt = decrypt_playfair



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
