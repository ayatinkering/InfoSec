"""Q4: Triple DES, with the manual's degenerate key reported explicitly."""

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

MANUAL_KEY_HEX = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
# Explicit alternative example, not a claim about the manual's intended key.
DEMO_KEY_HEX = "0123456789ABCDEFFEDCBA98765432100011223344556677"


def validate_key(key):
    if len(key) not in (16, 24):
        raise ValueError("Triple DES requires 16 or 24 key bytes.")
    # Checks degeneracy as well as adjusting DES parity bits.
    return DES3.adjust_key_parity(key)


def encrypt(message, key):
    key = validate_key(key)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(pad(message, DES3.block_size))


def decrypt(ciphertext, key):
    key = validate_key(key)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size)


def main():
    print("Manual key HEX:", MANUAL_KEY_HEX)
    try:
        validate_key(bytes.fromhex(MANUAL_KEY_HEX))
    except ValueError as error:
        print("Manual key rejected:", error)
        print("All three DES components are equal: E-D-E reduces to single DES.")
    print("The following valid demonstration uses a DIFFERENT, explicitly chosen key.")
    message = input("Plaintext [Enter = Classified Text]: ") or "Classified Text"
    key_hex = input("Valid key HEX [Enter = " + DEMO_KEY_HEX + "]: ") or DEMO_KEY_HEX
    key = bytes.fromhex(key_hex)
    ciphertext = encrypt(message.encode("utf-8"), key)
    print("Mode: ECB | Supplied key HEX:", key.hex())
    print("Parity-adjusted key HEX:", validate_key(key).hex())
    print("Ciphertext HEX:", ciphertext.hex())
    print("Decrypted text:", decrypt(ciphertext, key).decode("utf-8"))


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
        raise SystemExit(1)
