"""Lab 6: RSA-PSS signing, normal verification, and the wrong-public-key test."""

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss



# ---------- GENERATE ONE PERSON'S KEYS ----------
# The private key signs. Share only its public half with the verifier.
def generate_keys(bits=2048):
    return RSA.generate(bits)



# ---------- SIGN THE ORIGINAL MESSAGE ----------
# The signature protects a hash of these exact bytes, not just the sender's name.
def sign_message(message, private_key):
    # HASH TWIST: use SHA512 instead only if required; change import and BOTH functions.
    digest = SHA256.new(message)
    # SCHEME TWIST: change PSS to another required scheme on BOTH sides.
    signer = pss.new(private_key)
    signature = signer.sign(digest)

    return signature



# ---------- VERIFY A RECEIVED MESSAGE ----------
# Return True/False; do not print or generate new keys inside this function.
def verify_signature(message, signature, public_key):
    # HASH TWIST: use SHA512 instead only if required; change import and BOTH functions.
    digest = SHA256.new(message)

    verifier = pss.new(public_key)

    try:
        verifier.verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False



# ---------- DEMONSTRATION ----------
# HINT: tamper AFTER signing. Signing the changed message again makes a NEW
# valid signature and would not demonstrate detection of an altered message.
def main():
    text = input('Message [Alice]: ')

    if text == "":
        text = 'Alice'

    bits = input('RSA bits [2048]: ')

    if bits == "":
        bits = '2048'

    bits = int(bits)

    private_key = generate_keys(bits)
    public_key = private_key.publickey()

    # WRONG-KEY TWIST: uncomment this to verify with a different person's key.
    # public_key = generate_keys(bits).publickey()
    original = text.encode("utf-8")
    signature = sign_message(original, private_key)

    # CHANGE HERE after signing, without signing again.
    received = original
    # received = b"Different received message"

    print("Signature HEX:", signature.hex())
    valid = verify_signature(received, signature, public_key)
    print("Signature valid:", valid)



if __name__ == "__main__":
    main()
