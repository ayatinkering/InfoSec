"""Lab 1, Q2. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q2-autokey.py
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



# ---------- ENCRYPT AUTOKEY ----------
# Use the starting number, then extend the key stream with plaintext letters.
# Unlike Vigenere, do not repeatedly cycle the initial key.
def encrypt_autokey(text, key):
    text = clean_text(text)
    p = []

    # Work through each letter or letter-pair in order.
    for c in text:
        p.append(ord(c) - ord("A"))

    keys = [key]


    # Work through each letter or letter-pair in order.
    for x in p:
        if len(keys) == len(p):
            break

        keys.append(x)

    result = ""

    # Work through each letter or letter-pair in order.
    for i in range(len(p)):
        result += chr((p[i] + keys[i]) % 26 + ord("A"))

    return result



# ---------- DECRYPT AUTOKEY ----------
# Recover one letter, then use that recovered value as the next key entry.
# This explains how decryption builds a key stream without knowing plaintext first.
def decrypt_autokey(text, key):
    text = clean_text(text)
    keys = [key]
    result = ""

    for i in range(len(text)):
        x = ord(text[i]) - ord("A")
        y = (x - keys[i]) % 26
        result += chr(y + ord("A"))
        if len(keys) < len(text):
            keys.append(y)

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

    key = input('Enter numeric key: [Enter = 7]: ')

    if key == "":
        key = '7'

    key = int(key) % 26


    # Sender step: protect the ORIGINAL input and keep the returned result.
    c = encrypt_autokey(text, key)

    # Receiver step: decrypt this received copy. Change it BEFORE this line to test corruption.
    p = decrypt_autokey(c, key)

    print("Ciphertext:", c)
    print("Decrypted text:", p)




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
clean = clean_text
encrypt = encrypt_autokey
decrypt = decrypt_autokey



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
