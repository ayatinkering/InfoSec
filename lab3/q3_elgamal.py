"""Q3: Textbook ElGamal with input p, g, h, x and text/integer messages.

The small defaults expose the formulas. They are not production parameters.
Each text byte is encoded as byte+1 and gets a fresh random exponent.
"""

# Import prime validation and a cryptographically random integer source.
from secrets import randbelow
from Crypto.Util.number import isPrime



# ---------- VALIDATE PARAMETERS ----------
# Check that p is prime and g is in range; this does not prove generator order.
def validate_parameters(p, g):
    if p <= 3 or not isPrime(p):
        raise ValueError("p must be a prime greater than 3.")

    if not 1 < g < p - 1:
        raise ValueError("g must satisfy 1 < g < p-1.")



# ---------- GENERATE KEYS ----------
# Choose/use private x and calculate public h=g^x mod p.
# Return ((p,g,h),x), keeping public and private parts distinguishable.
def generate_keys(p, g, x=None):
    validate_parameters(p, g)

    if x is None:
        x = randbelow(p - 3) + 2

    if not 1 <= x <= p - 2:
        raise ValueError("Private x must lie between 1 and p-2.")

    return (p, g, pow(g, x, p)), x



# ---------- ENCRYPT NUMBER ----------
# Choose fresh k; calculate c1=g^k mod p and c2=message*h^k mod p.
# Fixed k is only for checking a worked example; do not deliberately reuse it.
def encrypt_number(message, public_key, k=None):
    p, g, h = public_key

    if not 0 <= message < p or not 1 <= h < p:
        raise ValueError("Need 0 <= message < p and 1 <= h < p.")

    if k is None:
        k = randbelow(p - 2) + 1

    if not 1 <= k <= p - 2:
        raise ValueError("Fresh exponent k must lie between 1 and p-2.")

    c1 = pow(g, k, p)
    c2 = message * pow(h, k, p) % p
    return c1, c2



# ---------- DECRYPT NUMBER ----------
# Calculate shared=c1^x mod p, then message=c2*inverse(shared) mod p.
def decrypt_number(ciphertext, p, x):
    c1, c2 = ciphertext

    if not 1 <= c1 < p or not 0 <= c2 < p or not 1 <= x <= p - 2:
        raise ValueError("Invalid ciphertext component or private exponent.")

    shared = pow(c1, x, p)
    return c2 * pow(shared, -1, p) % p



# ---------- ENCRYPT ELGAMAL BYTES ----------
# Encode each message byte as byte+1, and encrypt it with a random exponent.
# The +1 avoids the always-zero ciphertext component for plaintext zero.
def encrypt_elgamal_bytes(message, public_key):
    p, g, h = public_key
    validate_parameters(p, g)

    if p <= 256:
        raise ValueError("Text encoding needs p > 256, since byte+1 can equal 256.")

    ciphertext = []

    for byte in message:
        ciphertext.append(encrypt_number(byte + 1, public_key))

    return ciphertext



# ---------- DECRYPT ELGAMAL BYTES ----------
# Decrypt each ElGamal pair and subtract 1 to recover original bytes.
# Textbook ElGamal has no tag; valid modifications may alter plaintext silently.
def decrypt_elgamal_bytes(ciphertext, p, x):
    plaintext = []

    for pair in ciphertext:
        byte = decrypt_number(pair, p, x) - 1

        if not 0 <= byte <= 255:
            raise ValueError("Recovered value is not an encoded byte; check the keys.")

        plaintext.append(byte)

    return bytes(plaintext)



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    p = input('Prime modulus p [467]: ')

    if p == "":
        p = '467'

    p = int(p)
    g = input('Generator g [2]: ')

    if g == "":
        g = '2'

    g = int(g)
    private_input = input("Private exponent x [Enter=random]: ").strip()

    # Create the key once; keep the private half for this matching decryption.
    private_value = None

    if private_input:
        private_value = int(private_input)

    public_key, x = generate_keys(p, g, private_value)
    h_input = input("Public h [Enter=compute g^x mod p]: ").strip()

    if h_input and int(h_input) != public_key[2]:
        raise ValueError("Supplied h does not match g^x mod p.")

    print("Public key (p,g,h):", public_key)
    print("Private x (for this learning demonstration):", x)
    kind = input('Message: 1=text; 2=integer [1]: ')

    if kind == "":
        kind = '1'

    if kind == "1":
        text = input('Plaintext [Confidential Data]: ')

        if text == "":
            text = 'Confidential Data'

        message = text.encode("utf-8")
        ciphertext = encrypt_elgamal_bytes(message, public_key)
        recovered = decrypt_elgamal_bytes(ciphertext, p, x)
        print("Ciphertext pairs:", ciphertext)
        print("Decrypted text:", recovered.decode("utf-8"))
    elif kind == "2":
        message = input('Integer message [123]: ')

        if message == "":
            message = '123'

        message = int(message)
        k_input = input("Fresh exponent k [Enter=random; fixed value is educational]: ").strip()
        k = None

        if k_input:
            k = int(k_input)

        ciphertext = encrypt_number(message, public_key, k)
        recovered = decrypt_number(ciphertext, p, x)
        print("Ciphertext pair:", ciphertext)
        print("Decrypted integer:", recovered)
    else:
        raise ValueError("Choose message type 1 or 2.")

    print("Verified:", recovered == message)
    print("Textbook ElGamal is malleable and does not authenticate the message.")


# Run input prompts only when executed directly.


# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
encrypt = encrypt_elgamal_bytes
decrypt = decrypt_elgamal_bytes



if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError) as error:
        print("Error:", error)
        raise SystemExit(1)
