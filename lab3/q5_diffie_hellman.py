"""Q5: Finite-field Diffie-Hellman key exchange and timing for both peers.

Small default p=23 is for checking formulas by hand, not real-world security.
Public keys must be authenticated separately to prevent a middleman attack.
"""

# Import random sampling, timing, parameter checks, and key derivation.
from secrets import randbelow
from time import perf_counter
from Crypto.Util.number import isPrime
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES



# ---------- VALIDATE PARAMETERS ----------
# Check a prime modulus and a nontrivial generator candidate.
# This is basic input validation, not full production subgroup validation.
def validate_parameters(p, g):
    if p <= 3 or not isPrime(p):
        raise ValueError("p must be a prime greater than 3.")

    if not 1 < g < p - 1:
        raise ValueError("g must satisfy 1 < g < p-1.")



# ---------- GENERATE KEYPAIR ----------
# Create one peer private exponent and corresponding public DH value.
def generate_keypair(p, g, private_value=None):
    if private_value is None:
        private_value = randbelow(p - 3) + 2

    if not 2 <= private_value <= p - 2:
        raise ValueError("Private exponent must lie between 2 and p-2.")

    public_value = pow(g, private_value, p)
    return private_value, public_value



# ---------- COMPUTE SHARED SECRET ----------
# Raise the PEER public value to OUR private exponent modulo p.
# Do not transmit private exponents; DH public values still need authentication.
def compute_shared_secret(peer_public, private_value, p):
    if not 1 < peer_public < p - 1:
        raise ValueError("Peer public value is degenerate; use a suitable group/exponent.")

    if not 2 <= private_value <= p - 2:
        raise ValueError("Private exponent must lie between 2 and p-2.")

    shared = pow(peer_public, private_value, p)

    if shared in (0, 1, p - 1):
        raise ValueError("Degenerate shared secret; choose suitable group/exponents.")

    return shared



# ---------- DERIVE SESSION KEY ----------
# Turn a shared DH integer into a fixed-length AES key with HKDF.
# Both parties must use the same salt and context.
def derive_session_key(shared, p, g, salt):
    length = (p.bit_length() + 7) // 8
    secret_bytes = shared.to_bytes(length, "big")
    context = b"Lab3-DH-AES256-v1" + p.to_bytes(length, "big") + g.to_bytes(length, "big")
    return HKDF(secret_bytes, 32, salt, SHA256, context=context)



# ---------- EXCHANGE ----------
# Calculate each peer public key and shared secret, measuring the steps separately.
# This function agrees a key; it does not by itself encrypt or authenticate a message.
def exchange(p, g, alice_private=None, bob_private=None):
    validate_parameters(p, g)

    start = perf_counter()
    a, alice_public = generate_keypair(p, g, alice_private)
    alice_keygen = perf_counter() - start

    start = perf_counter()
    b, bob_public = generate_keypair(p, g, bob_private)
    bob_keygen = perf_counter() - start

    start = perf_counter()
    alice_secret = compute_shared_secret(bob_public, a, p)
    alice_agreement = perf_counter() - start

    start = perf_counter()
    bob_secret = compute_shared_secret(alice_public, b, p)
    bob_agreement = perf_counter() - start

    if alice_secret != bob_secret:
        raise ValueError("The peers did not derive the same secret.")

    return {
        'alice_private': a,
        'alice_public': alice_public,
        'bob_private': b,
        'bob_public': bob_public,
        'alice_secret': alice_secret,
        'bob_secret': bob_secret,
        'alice_keygen': alice_keygen,
        'bob_keygen': bob_keygen,
        'alice_agreement': alice_agreement,
        'bob_agreement': bob_agreement,
    }



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    p = input('Prime p, small educational default [23]: ')

    if p == "":
        p = '23'

    p = int(p)
    g = input('Generator g [5]: ')

    if g == "":
        g = '5'

    g = int(g)
    a_input = input('Alice private a [6; type random to generate]: ')

    if a_input == "":
        a_input = '6'

    b_input = input('Bob private b [15; type random to generate]: ')

    if b_input == "":
        b_input = '15'

    if a_input.lower() == "random":
        a = None
    else:
        a = int(a_input)

    if b_input.lower() == "random":
        b = None
    else:
        b = int(b_input)

    result = exchange(p, g, a, b)

    print("Alice public A = g^a mod p:", result["alice_public"])
    print("Bob public B = g^b mod p:", result["bob_public"])
    print("Alice shared B^a mod p:", result["alice_secret"])
    print("Bob shared A^b mod p:", result["bob_secret"])

    for name in ("alice_keygen", "bob_keygen", "alice_agreement", "bob_agreement"):
        print(name + " (microseconds):", round(result[name] * 1e6, 3))

    # Derive matching AES keys and show that Bob can read Alice's encrypted message.
    salt = get_random_bytes(16)
    alice_key = derive_session_key(result["alice_secret"], p, g, salt)
    bob_key = derive_session_key(result["bob_secret"], p, g, salt)
    text = input('Message after key exchange [Hello Bob]: ')

    if text == "":
        text = 'Hello Bob'

    cipher = AES.new(alice_key, AES.MODE_GCM, nonce=get_random_bytes(12))
    ciphertext, tag = cipher.encrypt_and_digest(text.encode("utf-8"))
    receiver = AES.new(bob_key, AES.MODE_GCM, nonce=cipher.nonce)

    # Receiver step: decrypt this received copy. Change it BEFORE this line to test corruption.
    recovered = receiver.decrypt_and_verify(ciphertext, tag)

    print("Derived AES keys match:", alice_key == bob_key)
    print("Ciphertext HEX:", ciphertext.hex())
    print("Bob decrypted:", recovered.decode("utf-8"))
    print("DH agrees a key; it does not authenticate the peers by itself.")


# Keep imports reusable for larger applications and tests.
if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError) as error:
        print("Error:", error)
        raise SystemExit(1)
