"""Lab 4: named systems, key revocation, signed DH, and encrypted messages.

The in-memory registry represents trusted public-key distribution. The DH group
is educational, not a claim to implement an approved production protocol.
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getStrongPrime
from secrets import randbelow
import json



# ---------- REGISTER ONE SYSTEM ----------
# Keep private/public keys and active status together. Passing the dictionary
# explicitly makes it clear WHICH registry the function changes.
def register_system(systems, name, bits=2048):
    if name in systems:
        raise ValueError("System already registered: " + name)

    private_key = RSA.generate(bits)
    systems[name] = {
        "private": private_key,
        "public": private_key.publickey(),
        "active": True,
    }



# ---------- REVOKE ONE SYSTEM ----------
# Revocation blocks NEW exchanges in this service. It cannot erase keys or
# plaintext already held by a former recipient.
def revoke_system(systems, name):
    systems[name]["active"] = False



# ---------- CHECK AUTHORIZATION ----------
# Call before using keys. Do not merely print 'revoked' and continue encrypting.
def require_active_system(systems, name):
    if name not in systems or not systems[name]["active"]:
        raise PermissionError("Unknown or revoked system: " + name)

    return systems[name]



# ---------- BIND THE EXCHANGE TO BOTH IDENTITIES ----------
# JSON avoids ambiguity if a system name contains a separator character.
def create_transcript(sender, receiver, alice_public, bob_public):
    values = [sender, receiver, alice_public, bob_public]
    return json.dumps(values, separators=(",", ":")).encode("utf-8")



# ---------- SIGN OR VERIFY THE EXCHANGE ----------
# Both sides sign the SAME transcript with their own private key. Verifiers
# use public keys from the trusted registry, not keys supplied by an attacker.
def sign_transcript(transcript, private_key):
    return pss.new(private_key).sign(SHA256.new(transcript))



# ---------- VERIFY THE SIGNED EXCHANGE ----------
# Hash the received transcript and check its signature with the trusted public key.
# Return False if identities or DH values changed after the transcript was signed.
def verify_transcript(transcript, signature, public_key):
    try:
        pss.new(public_key).verify(SHA256.new(transcript), signature)
        return True
    except (ValueError, TypeError):
        return False



# ---------- DERIVE ONE SESSION KEY ----------
# Context and transcript bind the AES key to this specific exchange.
def derive_session_key(shared_secret, p, transcript):
    width = (p.bit_length() + 7) // 8
    shared_bytes = shared_secret.to_bytes(width, "big")
    salt = SHA256.new(transcript).digest()

    return HKDF(shared_bytes, 32, salt, SHA256, context=b"SecureCorp session")



# ---------- AUTHENTICATED DIFFIE-HELLMAN ----------
# Return Alice's and Bob's independently derived keys. They should match.
# HINT: alter received_transcript AFTER signing to test signature rejection.
def exchange_session_keys(systems, sender, receiver, p, g):
    sender_record = require_active_system(systems, sender)
    receiver_record = require_active_system(systems, receiver)

    a = randbelow(p - 3) + 2
    b = randbelow(p - 3) + 2
    alice_public = pow(g, a, p)
    bob_public = pow(g, b, p)
    transcript = create_transcript(sender, receiver, alice_public, bob_public)

    sender_signature = sign_transcript(transcript, sender_record["private"])
    receiver_signature = sign_transcript(transcript, receiver_record["private"])
    # CHANGE HERE to alter the received exchange after signatures are made.
    received_transcript = transcript
    # received_transcript = transcript + b"CHANGED"

    if not verify_transcript(received_transcript, sender_signature, sender_record["public"]):
        raise ValueError("Sender exchange signature invalid.")

    if not verify_transcript(received_transcript, receiver_signature, receiver_record["public"]):
        raise ValueError("Receiver exchange signature invalid.")

    alice_secret = pow(bob_public, a, p)
    bob_secret = pow(alice_public, b, p)
    alice_key = derive_session_key(alice_secret, p, transcript)
    bob_key = derive_session_key(bob_secret, p, transcript)

    if alice_key != bob_key:
        raise ValueError("Session keys do not match.")

    return alice_key, bob_key



# ---------- ENCRYPT ONE MESSAGE ----------
# Return the nonce and tag along with the ciphertext: decryption needs all three.
def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return cipher.nonce, tag, ciphertext



# ---------- RSA ENCRYPTION FOR SESSION-KEY DISTRIBUTION ----------
# The regular question asks for RSA encryption as well as DH key agreement.
# Encrypt only the 32-byte session key, not an arbitrarily large document.
def wrap_session_key(session_key, receiver_public_key):
    cipher = PKCS1_OAEP.new(receiver_public_key, SHA256)
    return cipher.encrypt(session_key)



def unwrap_session_key(wrapped_key, receiver_private_key):
    cipher = PKCS1_OAEP.new(receiver_private_key, SHA256)
    return cipher.decrypt(wrapped_key)



# ---------- DECRYPT AND VERIFY ONE MESSAGE ----------
# Changed data must fail tag verification before plaintext is returned.
def decrypt_message(packet, key):
    nonce, tag, ciphertext = packet
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)



# ---------- DEMONSTRATE A COMPLETE EXCHANGE ----------
# CHANGE the system names/message or the marked received copy; cryptographic functions
# above remain independent building blocks for an exam scenario.
def main():
    systems = {}
    names = input('System names, comma separated [Finance,HR,SupplyChain]: ')

    if names == "":
        names = 'Finance,HR,SupplyChain'

    for name in names.split(","):
        register_system(systems, name.strip())

    sender = input('Sender [Finance]: ')

    if sender == "":
        sender = 'Finance'

    receiver = input('Receiver [HR]: ')

    if receiver == "":
        receiver = 'HR'

    text = input('Message [Confidential financial report]: ')

    if text == "":
        text = 'Confidential financial report'

    p = getStrongPrime(1024)
    alice_key, bob_key = exchange_session_keys(systems, sender, receiver, p, 2)
    wrapped_key = wrap_session_key(alice_key, systems[receiver]['public'])
    delivered_key = unwrap_session_key(wrapped_key, systems[receiver]['private'])

    if delivered_key != bob_key:
        raise ValueError('RSA-delivered key does not match the DH-derived key.')

    packet = encrypt_message(text.encode("utf-8"), alice_key)
    recovered = decrypt_message(packet, delivered_key)

    print(sender, "->", receiver)
    print('RSA-encrypted session key:', wrapped_key.hex())
    print("Ciphertext HEX:", packet[2].hex())
    print("Received:", recovered.decode("utf-8"))

    # HINT: the second exchange must be rejected after revoking the sender.
    revoke_system(systems, sender)

    try:
        exchange_session_keys(systems, sender, receiver, p, 2)
    except PermissionError as error:
        print("Access denied after revocation:", error)



if __name__ == "__main__":
    try:
        main()
    except (ValueError, PermissionError, KeyError) as error:
        print("Error:", error)
