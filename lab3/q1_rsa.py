"""Q1: RSA message encryption, with textbook and RSA-OAEP variants.

Reusable functions use bytes. main() handles prompts and text conversion.
Textbook RSA is included for understanding the formulas, not real security.
"""

# Import the mathematics and standard RSA implementation.
from math import gcd
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import isPrime



# ---------- TEXTBOOK KEYS ----------
# Validate supplied primes and exponent, then derive n, phi and private exponent d.
def textbook_keys(p, q, e):
    if p == q or not isPrime(p) or not isPrime(q):
        raise ValueError("p and q must be distinct primes.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if not 1 < e < phi or gcd(e, phi) != 1:
        raise ValueError("e must lie between 1 and phi and be coprime with phi.")

    d = pow(e, -1, phi)
    return (n, e), (n, d)



# ---------- ENCRYPT NUMBER ----------
# Calculate c = message^e mod n. The numerical message must be smaller than n.
def encrypt_number(message, n, e):
    if n <= 2 or e <= 1 or not 0 <= message < n:
        raise ValueError("Need n > 2, e > 1, and 0 <= message < n.")

    return pow(message, e, n)



# ---------- DECRYPT NUMBER ----------
# Calculate message = ciphertext^d mod n using the private exponent.
def decrypt_number(ciphertext, n, d):
    if n <= 2 or d <= 0 or not 0 <= ciphertext < n:
        raise ValueError("Need n > 2, d > 0, and 0 <= ciphertext < n.")

    return pow(ciphertext, d, n)



# ---------- ENCRYPT TEXTBOOK ----------
# Encrypt each byte separately for the small-key textbook RSA demonstration.
def encrypt_textbook(message, n, e):
    result = []

    for value in message:
        result.append(encrypt_number(value, n, e))

    return result



# ---------- DECRYPT TEXTBOOK ----------
# Decrypt integer ciphertext values and reconstruct the original bytes.
def decrypt_textbook(ciphertext, n, d):
    result = []

    for value in ciphertext:
        decoded = decrypt_number(value, n, d)

        if decoded > 255:
            raise ValueError("Recovered value is not a byte; check the keys.")

        result.append(decoded)

    return bytes(result)



# ---------- GENERATE KEYS ----------
# Generate an RSA private key of the selected bit length and public exponent.
# Derive its public half with public_key(); do not give the private half to the sender.
def generate_keys(bits=2048, e=65537):
    if bits < 2048:
        raise ValueError("Use at least 2048 bits for the OAEP demonstration.")

    return RSA.generate(bits, e=e)



# ---------- ENCRYPT RSA OAEP ----------
# Encrypt a short byte message with the recipient public key and OAEP/SHA-256.
# RSA-2048/SHA-256 fits at most 190 bytes. Use hybrid encryption for files.
def encrypt_rsa_oaep(message, public_key):
    maximum = public_key.size_in_bytes() - 2 * SHA256.digest_size - 2

    if len(message) > maximum:
        raise ValueError("RSA-OAEP limit is {} bytes for this key. Use Q4 for files.".format(maximum))


    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = PKCS1_OAEP.new(public_key.public_key(), SHA256)
    return cipher.encrypt(message)



# ---------- DECRYPT RSA OAEP ----------
# Decrypt OAEP with the recipient PRIVATE key, rejecting invalid ciphertext.
# Do not confuse private-key signing with RSA message decryption.
def decrypt_rsa_oaep(ciphertext, private_key):
    if not private_key.has_private():
        raise ValueError("Decryption requires the private RSA key.")


    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = PKCS1_OAEP.new(private_key, SHA256)
    return cipher.decrypt(ciphertext)



# ---------- TEXTBOOK DEMO ----------
# Read a numerical/text RSA example and demonstrate both directions with supplied keys.
def textbook_demo():
    source = input('Keys: 1=derive from p,q; 2=enter n,e,d [1]: ')

    if source == "":
        source = '1'

    if source == "1":
        p = input('Prime p [61]: ')

        if p == "":
            p = '61'

        p = int(p)
        q = input('Prime q [53]: ')

        if q == "":
            q = '53'

        q = int(q)
        e = input('Public exponent e [17]: ')

        if e == "":
            e = '17'

        e = int(e)
        public, private = textbook_keys(p, q, e)
        n, e = public
        _, d = private
    elif source == "2":
        n = input('Modulus n [3233]: ')

        if n == "":
            n = '3233'

        n = int(n)
        e = input('Public exponent e [17]: ')

        if e == "":
            e = '17'

        e = int(e)
        d = input('Private exponent d [2753]: ')

        if d == "":
            d = '2753'

        d = int(d)
    else:
        raise ValueError("Choose key source 1 or 2.")

    print("Public (n,e):", (n, e))
    print("Private (n,d), displayed for this textbook demo:", (n, d))
    kind = input('Message: 1=text; 2=integer [1]: ')

    if kind == "":
        kind = '1'

    if kind == "1":
        text = input('Plaintext [Asymmetric Encryption]: ')

        if text == "":
            text = 'Asymmetric Encryption'

        message = text.encode("utf-8")
        ciphertext = encrypt_textbook(message, n, e)
        recovered = decrypt_textbook(ciphertext, n, d)
        print("Ciphertext integers:", ciphertext)
        print("Decrypted text:", recovered.decode("utf-8"))
    elif kind == "2":
        message = input('Integer message [65]: ')

        if message == "":
            message = '65'

        message = int(message)
        ciphertext = encrypt_number(message, n, e)
        recovered = decrypt_number(ciphertext, n, d)
        print("Ciphertext:", ciphertext)
        print("Decrypted integer:", recovered)
    else:
        raise ValueError("Choose message type 1 or 2.")

    if recovered != message:
        raise ValueError("Round trip failed; supplied keys may not match.")



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    mode = input('RSA: 1=textbook; 2=OAEP/SHA-256 [2]: ')

    if mode == "":
        mode = '2'

    if mode == "1":
        textbook_demo()
        return

    if mode != "2":
        raise ValueError("Choose mode 1 or 2.")

    text = input('Plaintext [Asymmetric Encryption]: ')

    if text == "":
        text = 'Asymmetric Encryption'

    key_path = input("Existing private PEM file [Enter=generate keys]: ").strip()

    if key_path:
        password = input('PEM password [Enter=none]: ')

        if password == "":
            password = None

        private_key = RSA.import_key(Path(key_path).read_bytes(), passphrase=password)
    else:
        bits = input('RSA key bits [2048]: ')

        if bits == "":
            bits = '2048'

        bits = int(bits)
        e = input('Public exponent [65537]: ')

        if e == "":
            e = '65537'

        e = int(e)
        private_key = generate_keys(bits, e)

    message = text.encode("utf-8")
    public_key = private_key.public_key()

    # Sender step: protect the ORIGINAL input and keep the returned result.
    ciphertext = encrypt_rsa_oaep(message, public_key)

    # Receiver step: decrypt this received copy. Change it BEFORE this line to test corruption.
    recovered = decrypt_rsa_oaep(ciphertext, private_key)

    print("Public n:", public_key.n)
    print("Public e:", public_key.e)
    print("Ciphertext HEX:", ciphertext.hex())
    print("Decrypted text:", recovered.decode("utf-8"))
    print("Verified:", recovered == message)


# Keep imports reusable: run prompts only when this file is executed.


# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
encrypt = encrypt_rsa_oaep
decrypt = decrypt_rsa_oaep



if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, TypeError) as error:
        print("Error:", error)
        raise SystemExit(1)
