"""Q4: Triple DES, with the manual's degenerate key reported explicitly."""

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

MANUAL_KEY_HEX = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
# Explicit alternative example, not a claim about the manual's intended key.
DEMO_KEY_HEX = "0123456789ABCDEFFEDCBA98765432100011223344556677"



# ---------- VALIDATE KEY ----------
# Reject a key with the wrong size or invalid algorithm-specific structure.
# Message padding never fixes a key-size error.
def validate_key(key):
    if len(key) not in (16, 24):
        raise ValueError("Triple DES requires 16 or 24 key bytes.")
    # Checks degeneracy as well as adjusting DES parity bits.
    return DES3.adjust_key_parity(key)



# ---------- ENCRYPT TRIPLE DES ----------
# Validate key components and encrypt padded data with Triple DES ECB.
# The manual key degenerates to single DES; use the labelled valid example.
def encrypt_triple_des(message, key):
    key = validate_key(key)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_message = pad(message, DES3.block_size)
    ciphertext = cipher.encrypt(padded_message)

    return ciphertext



# ---------- DECRYPT TRIPLE DES ----------
# Validate the same Triple DES key, decrypt, and remove message padding.
# Decryption reverses encryption; it does not establish the sender identity.
def decrypt_triple_des(ciphertext, key):
    key = validate_key(key)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_message = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_message, DES3.block_size)

    return plaintext



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
def main():
    print("Manual key HEX:", MANUAL_KEY_HEX)
    try:
        validate_key(bytes.fromhex(MANUAL_KEY_HEX))
    except ValueError as error:
        print("Manual key rejected:", error)
        print("All three DES components are equal: E-D-E reduces to single DES.")

    print("The following valid demonstration uses a DIFFERENT, explicitly chosen key.")
    message = input('Plaintext [Enter = Classified Text]: ')

    if message == "":
        message = 'Classified Text'

    key_hex = input('Valid key HEX [Enter = ' + DEMO_KEY_HEX + ']: ')

    if key_hex == "":
        key_hex = DEMO_KEY_HEX

    key = bytes.fromhex(key_hex)

    # Sender step: protect the ORIGINAL input and keep the returned result.
    ciphertext = encrypt_triple_des(message.encode("utf-8"), key)
    print("Mode: ECB | Supplied key HEX:", key.hex())
    print("Parity-adjusted key HEX:", validate_key(key).hex())
    print("Ciphertext HEX:", ciphertext.hex())
    print("Decrypted text:", decrypt_triple_des(ciphertext, key).decode("utf-8"))




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
encrypt = encrypt_triple_des
decrypt = decrypt_triple_des



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
        raise SystemExit(1)
