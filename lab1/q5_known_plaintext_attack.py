"""Lab 1, Q5. Adapted from your ayati-all-labs code.

A=0 through Z=25. Run this file and press Enter for the manual defaults.
Import encrypt/decrypt (or attack functions) to reuse without input prompts.
Source: https://github.com/ayatinkering/ayati-all-labs/blob/main/lab1%20Symetric/q5-known-plaintxt-attack.py
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



# ---------- RECOVER SHIFT KEY ----------
# Recover key=(ciphertext-plaintext) mod 26 and check every known pair.
# Known plaintext means the attacker has matching plaintext and ciphertext.
def recover_shift_key(p, c):
    p = clean_text(p)
    c = clean_text(c)
    if len(p) == 0 or len(p) != len(c):
        raise ValueError("Known texts must have the same nonzero letter count.")

    key = (ord(c[0]) - ord(p[0])) % 26
    for i in range(len(p)):
        if (ord(c[i]) - ord(p[i])) % 26 != key:
            raise ValueError("Known pairs do not share a single shift.")

    return key



# ---------- DECRYPT ADDITIVE ----------
# Undo the shift with P=(C-key) mod 26.
# HINT: a wrong key produces wrong plaintext; a Caesar cipher has no tamper tag.
def decrypt_additive(text, key):
    result = ""

    for c in text.upper():
        if "A" <= c <= "Z":
            x = ord(c) - ord("A")
            result += chr((x - key) % 26 + ord("A"))
        else:
            result += c

    return result



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
# Classical ciphers have no authentication: a changed ciphertext need not raise an error.
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    p = input('Enter known plaintext: [Enter = yes]: ')

    if p == "":
        p = 'yes'

    c = input('Enter its ciphertext: [Enter = CIW]: ')

    if c == "":
        c = 'CIW'

    text = input('Enter target ciphertext: [Enter = XVIEWYWI]: ')

    if text == "":
        text = 'XVIEWYWI'

    key = recover_shift_key(p, c)

    print("Recovered key:", key)
    print("Recovered plaintext:", decrypt_additive(text, key))
    print("Known-plaintext attack. Manual input gives TREASUSE; likely a typo for TREASURE.")




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
clean = clean_text
find_key = recover_shift_key
decrypt = decrypt_additive



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
