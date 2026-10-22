"""Lab 1, Q1. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q1-additive.py
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



# ---------- ENCRYPT ADDITIVE ----------
# For each letter, compute C=(P+key) mod 26, then convert back to a letter.
# A=0, B=1, ... Z=25. Modulo wraps values past Z back to A.
def encrypt_additive(text, key):
    text = clean_text(text)
    result = ""

    # Work through each letter or letter-pair in order.
    for c in text:
        x = ord(c) - ord("A")
        result += chr((x + key) % 26 + ord("A"))

    return result



# ---------- DECRYPT ADDITIVE ----------
# Undo the shift with P=(C-key) mod 26.
# HINT: a wrong key produces wrong plaintext; a Caesar cipher has no tamper tag.
def decrypt_additive(text, key):
    text = clean_text(text)
    result = ""

    for c in text:
        x = ord(c) - ord("A")
        result += chr((x - key) % 26 + ord("A"))

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

    key = input('Enter key: [Enter = 20]: ')

    if key == "":
        key = '20'

    key = int(key)


    # Sender step: protect the ORIGINAL input and keep the returned result.
    c = encrypt_additive(text, key)

    # Receiver step: decrypt this received copy. Change it BEFORE this line to test corruption.
    p = decrypt_additive(c, key)

    print("Ciphertext:", c)
    print("Decrypted text:", p)




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
clean = clean_text
encrypt = encrypt_additive
decrypt = decrypt_additive



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
