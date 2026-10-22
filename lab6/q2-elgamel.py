"""Lab 6: textbook ElGamal DIGITAL SIGNATURE, not ElGamal encryption."""

from Crypto.Util.number import getPrime
from Crypto.Hash import SHA256
from math import gcd
from secrets import randbelow



# ---------- GENERATE SIGNING KEYS ----------
# Public: (p,g,y). Private: x. Small bit sizes are for classroom speed only.
def generate_keys(bits=256):
    if bits < 32:
        raise ValueError("Use at least 32 bits for this educational demonstration.")

    p = getPrime(bits)
    g = 2
    x = randbelow(p - 2) + 1
    y = pow(g, x, p)

    return (p, g, y), x



# ---------- HASH BYTES TO AN INTEGER ----------
# Both signer and verifier must use the SAME hash and SAME message bytes.
def hash_message(message):
    return int.from_bytes(SHA256.new(message).digest(), "big")



# ---------- SIGN ----------
# k must have an inverse modulo p-1. Pick a NEW random k for each signature.
# Reusing k can reveal the signing key; changing k is not a tampering test.
def sign_message(message, public_key, private_key):
    p, g, y = public_key
    x = private_key
    digest = hash_message(message)

    while True:
        k = randbelow(p - 2) + 1

        if gcd(k, p - 1) == 1:
            break

    r = pow(g, k, p)
    k_inverse = pow(k, -1, p - 1)
    s = k_inverse * (digest - x * r) % (p - 1)

    return r, s



# ---------- VERIFY ----------
# Check g^H(message) == y^r * r^s (mod p), using ONLY the public key.
def verify_signature(message, signature, public_key):
    p, g, y = public_key
    r, s = signature

    if not 1 <= r < p or not 0 <= s < p - 1:
        return False

    digest = hash_message(message)
    left = pow(g, digest, p)
    right = pow(y, r, p) * pow(r, s, p) % p

    return left == right



# ---------- CHANGE MESSAGE ONLY AFTER SIGNING ----------
# HINT: edit received below, while keeping signature unchanged.
def main():
    text = input('Message [Secure Voting]: ')

    if text == "":
        text = 'Secure Voting'

    bits = input('Educational prime bits [256]: ')

    if bits == "":
        bits = '256'

    bits = int(bits)

    public_key, private_key = generate_keys(bits)
    original = text.encode("utf-8")
    signature = sign_message(original, public_key, private_key)
    # CHANGE HERE to test an altered message, keeping the signature/tag above.
    received = original
    # received = b"Different received message"

    print("Public key (p,g,y):", public_key)
    print("Signature (r,s):", signature)
    print("Signature valid:", verify_signature(received, signature, public_key))



if __name__ == "__main__":
    main()
