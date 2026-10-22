"""Lab 5: custom 32-bit hash and standard message hashes."""

import hashlib



# ---------- CUSTOM HASH ----------
# Start at 5381. Multiply by 33, add the next character, and keep 32 bits.
# This is a teaching hash, not a cryptographic integrity/authentication scheme.
def custom_hash(message):
    hash_value = 5381

    for character in message:
        hash_value = (hash_value * 33 + ord(character)) & 0xFFFFFFFF

    return hash_value



# ---------- STANDARD HASHES ----------
# Encoding converts text to bytes. The hex digest is a printable hash value.
def calculate_standard_hashes(message):
    data = message.encode("utf-8")

    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA-1": hashlib.sha1(data).hexdigest(),
        "SHA-256": hashlib.sha256(data).hexdigest(),
        "SHA-512": hashlib.sha512(data).hexdigest(),
    }



# ---------- CHANGE THE INPUT AND COMPARE ----------
# HINT: change one letter or add a space. The input bytes, and hashes, change.
# MD5/SHA-1 are included for comparison; do not use them for new security designs.
def main():
    message = input('Message [Information Security]: ')

    if message == "":
        message = 'Information Security'

    print("Message:", message)
    print("Custom 32-bit hash:", custom_hash(message))

    for name, digest in calculate_standard_hashes(message).items():
        print(name + ":", digest)



if __name__ == "__main__":
    main()
