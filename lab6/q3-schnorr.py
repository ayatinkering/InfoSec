"""Lab 6: educational Schnorr signatures with an explicitly generated subgroup."""

import hashlib
from secrets import randbelow
from Crypto.Util.number import getPrime, isPrime



# ---------- GENERATE A PRIME-ORDER GROUP ----------
# p=2q+1 with both primes; g=4 has order q. This replaces the tiny q=11
# example, where changed messages can easily have the same challenge by chance.
def generate_parameters(bits=256):
    if bits < 32:
        raise ValueError("Use at least 32 bits for this educational demonstration.")

    while True:
        q = getPrime(bits - 1)
        p = 2 * q + 1

        if isPrime(p):
            return p, q, 4



# ---------- GENERATE THE SIGNER'S KEYS ----------
# Private x stays with the signer; public y=g^x mod p goes to the verifier.
def generate_keys(p, q, g):
    x = randbelow(q - 1) + 1
    y = pow(g, x, p)

    return y, x



# ---------- CREATE THE CHALLENGE ----------
# Bind the commitment R to the message. Use enough bytes for any chosen p.
def challenge(commitment, message, p, q):
    width = (p.bit_length() + 7) // 8
    data = commitment.to_bytes(width, "big") + message
    digest = hashlib.sha256(data).digest()

    return int.from_bytes(digest, "big") % q



# ---------- SIGN ----------
# New random k -> commitment R -> challenge e -> response s.
def sign_message(message, p, q, g, private_key):
    k = randbelow(q - 1) + 1
    commitment = pow(g, k, p)
    e = challenge(commitment, message, p, q)
    s = (k + e * private_key) % q

    return e, s



# ---------- VERIFY ----------
# Reconstruct R = g^s * y^(-e), then recompute and compare the challenge.
def verify_signature(message, signature, p, q, g, public_key):
    e, s = signature

    if not 0 <= e < q or not 0 <= s < q or not 1 < public_key < p:
        return False

    commitment = pow(g, s, p) * pow(public_key, -e, p) % p
    expected = challenge(commitment, message, p, q)

    return e == expected



# ---------- DEMONSTRATION ----------
# HINT: change received after signing, or try another person's public key.
# This is an educational construction, not a standardized production API.
def main():
    text = input('Message [Information Security]: ')

    if text == "":
        text = 'Information Security'

    bits = input('Educational group bits [256]: ')

    if bits == "":
        bits = '256'

    bits = int(bits)

    p, q, g = generate_parameters(bits)
    public_key, private_key = generate_keys(p, q, g)
    original = text.encode("utf-8")
    signature = sign_message(original, p, q, g, private_key)
    # CHANGE HERE to test an altered message, keeping the signature/tag above.
    received = original
    # received = b"Different received message"

    print("Public group (p,q,g):", (p, q, g))
    print("Public key y:", public_key)
    print("Signature (e,s):", signature)
    print("Signature valid:", verify_signature(received, signature, p, q, g, public_key))



if __name__ == "__main__":
    main()
