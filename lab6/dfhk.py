"""Lab 6: Diffie-Hellman followed by HMAC; HMAC is NOT a digital signature."""

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import getStrongPrime
from secrets import randbelow
import hmac
import hashlib



# ---------- EXCHANGE A SHARED SECRET ----------
# Both peers independently compute the same number. The group is educational;
# authenticating the exchanged public keys is a separate requirement.
def exchange_secret(bits=1024):
    p = getStrongPrime(bits)
    g = 2
    a = randbelow(p - 3) + 2
    b = randbelow(p - 3) + 2

    alice_public = pow(g, a, p)
    bob_public = pow(g, b, p)
    alice_secret = pow(bob_public, a, p)
    bob_secret = pow(alice_public, b, p)

    if alice_secret != bob_secret:
        raise ValueError("Shared secrets do not match.")

    return alice_secret, p



# ---------- DERIVE AN HMAC KEY ----------
# A raw DH integer is not directly a fixed-length key. Both parties use this KDF.
def derive_hmac_key(shared_secret, p):
    width = (p.bit_length() + 7) // 8
    shared_bytes = shared_secret.to_bytes(width, "big")

    return HKDF(shared_bytes, 32, b"demo salt", SHA256, context=b"DH-HMAC demo")



# ---------- AUTHENTICATE AND VERIFY ----------
# Both parties know the key, so either can create an HMAC. There is no
# public-key verification or signature-style non-repudiation here.
def create_hmac(message, key):
    return hmac.new(key, message, hashlib.sha256).digest()



# ---------- VERIFY A RECEIVED HMAC ----------
# Recompute the expected tag and use a timing-resistant comparison.
# A modified received message must be checked against the ORIGINAL tag.
def verify_hmac(message, tag, key):
    expected = create_hmac(message, key)
    return hmac.compare_digest(tag, expected)



# ---------- DEMONSTRATION ----------
# HINT: tamper with received AFTER creating tag; do not recompute tag afterward.
def main():
    text = input('Message [Confidential transaction]: ')

    if text == "":
        text = 'Confidential transaction'

    shared, p = exchange_secret()
    key = derive_hmac_key(shared, p)
    original = text.encode("utf-8")
    tag = create_hmac(original, key)
    # CHANGE HERE to test an altered message, keeping the signature/tag above.
    received = original
    # received = b"Different received message"

    print("HMAC HEX:", tag.hex())
    print("HMAC valid:", verify_hmac(received, tag, key))
    print("DH+HMAC is shared-key authentication, not a digital signature.")



if __name__ == "__main__":
    main()
