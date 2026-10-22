"""Lab 1, Q2. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q2-vignere.py
"""



# ---------- CLEAN TEXT ----------
# Keep English letters only and uppercase them; spaces/punctuation are removed.
# CHANGE input handling here only if the question asks you to preserve formatting.
def clean_text(text):
    result = ""

    for c in text.upper():
        if "A" <= c <= "Z":
            result += c

    return result



# ---------- ENCRYPT VIGENERE ----------
# Repeat the keyword; each keyword letter supplies a different Caesar shift.
# The key position wraps with position % len(keyword).
def encrypt_vigenere(text, key):
    text = clean_text(text)
    key = clean_text(key)
    if key == "":
        raise ValueError("Keyword must contain English letters.")

    result = ""

    # Work through each letter or letter-pair in order.
    for i in range(len(text)):
        x = ord(text[i]) - ord("A")
        y = ord(key[i % len(key)]) - ord("A")
        result += chr((x + y) % 26 + ord("A"))

    return result



# ---------- DECRYPT VIGENERE ----------
# Repeat the same keyword, subtracting each key letter instead of adding.
# Keep the same letter normalization and keyword alignment on both sides.
def decrypt_vigenere(text, key):
    text = clean_text(text)
    key = clean_text(key)
    if key == "":
        raise ValueError("Keyword must contain English letters.")

    result = ""

    for i in range(len(text)):
        x = ord(text[i]) - ord("A")
        y = ord(key[i % len(key)]) - ord("A")
        result += chr((x - y) % 26 + ord("A"))

    return result



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
# Classical ciphers have no authentication: a changed ciphertext need not raise an error.
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    text = input('Enter plaintext: [Enter = the house is being sold tonight]: ')

    if text == "":
        text = 'the house is being sold tonight'

    key = input('Enter keyword: [Enter = DOLLARS]: ')

    if key == "":
        key = 'DOLLARS'

    if clean_text(key) == "":
        print("Keyword cannot be empty.")
    else:
        c = encrypt_vigenere(text, key)
        p = decrypt_vigenere(c, key)

        print("Ciphertext:", c)
        print("Decrypted text:", p)




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
clean = clean_text
encrypt = encrypt_vigenere
decrypt = decrypt_vigenere



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
