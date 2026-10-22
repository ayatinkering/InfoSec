"""Q2: ECC-based message encryption: ephemeral ECDH + HKDF + AES-256-GCM.

This is an explicitly defined educational hybrid, not direct ECC encryption
or a claim to implement a named ECIES standard. Packet fields are bytes.
"""

# Import the ECC, derivation, and symmetric encryption building blocks.
from pathlib import Path
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes



# ---------- GENERATE KEYS ----------
# Generate an ECC private key on the requested curve, or construct it from d.
# The public key is the curve point Q=dG, not a second independent random key.
def generate_keys(curve="P-256", private_value=None):
    if private_value is None:
        return ECC.generate(curve=curve)

    return ECC.construct(curve=curve, d=private_value)



# ---------- DERIVE KEY ----------
# Derive the same AES key from local private and peer public ECC keys plus salt.
# Both sides must use identical KDF settings and salt.
def derive_key(private_key, peer_public_key, salt):
    def kdf(shared_secret):
        return HKDF(shared_secret, 32, salt, SHA256, context=b"InfoSec-Lab3-ECDH-v1")

    return key_agreement(static_priv=private_key,
                         static_pub=peer_public_key.public_key(), kdf=kdf)



# ---------- ENCRYPT ECC HYBRID ----------
# Generate an ephemeral ECC key, derive an AES key, and encrypt with GCM.
# The packet carries only public/transport fields, never the private scalar or AES key.
def encrypt_ecc_hybrid(message, recipient_public_key):
    ephemeral = generate_keys(recipient_public_key.curve)
    ephemeral_public = ephemeral.public_key().export_key(format="DER")
    salt = get_random_bytes(16)
    key = derive_key(ephemeral, recipient_public_key, salt)


    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))

    # Authenticate this unencrypted metadata too; decryption must use the same bytes.
    cipher.update(b"Lab3-ECC-v1" + ephemeral_public + salt)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    return {
        'ephemeral_public': ephemeral_public,
        'salt': salt,
        'nonce': cipher.nonce,
        'ciphertext': ciphertext,
        'tag': tag,
    }



# ---------- DECRYPT ECC HYBRID ----------
# Derive the AES key from recipient private and ephemeral public keys, then verify.
# TAMPER HINT: change packet["tag"] or packet["ciphertext"] after encryption.
def decrypt_ecc_hybrid(packet, recipient_private_key):
    ephemeral_public = ECC.import_key(packet["ephemeral_public"])
    key = derive_key(recipient_private_key, ephemeral_public, packet["salt"])


    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = AES.new(key, AES.MODE_GCM, nonce=packet["nonce"])

    # Authenticate this unencrypted metadata too; decryption must use the same bytes.
    cipher.update(b"Lab3-ECC-v1" + packet["ephemeral_public"] + packet["salt"])

    # A changed tag/ciphertext raises ValueError; never return unverified plaintext.
    return cipher.decrypt_and_verify(packet["ciphertext"], packet["tag"])



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    text = input('Plaintext [Secure Transactions]: ')

    if text == "":
        text = 'Secure Transactions'

    key_path = input("Existing private PEM file [Enter=generate/enter scalar]: ").strip()

    if key_path:
        password = input('PEM password [Enter=none]: ')

        if password == "":
            password = None

        private_key = ECC.import_key(Path(key_path).read_bytes(), passphrase=password)
    else:
        curve = input('Curve: P-256/secp256r1, P-384, P-521 [P-256]: ')

        if curve == "":
            curve = 'P-256'

        scalar = input("Private scalar d, decimal or 0xHEX [Enter=random]: ").strip()
        value = None

        if scalar:
            if scalar.lower().startswith("0x"):
                value = int(scalar, 16)
            else:
                value = int(scalar)

        private_key = generate_keys(curve, value)

    public_key = private_key.public_key()
    message = text.encode("utf-8")

    # Sender step: protect the ORIGINAL input and keep the returned result.
    packet = encrypt_ecc_hybrid(message, public_key)

    # Receiver step: decrypt this received copy. Change it BEFORE this line to test corruption.
    recovered = decrypt_ecc_hybrid(packet, private_key)

    print("Curve:", private_key.curve)
    print("Recipient public key:\n" + public_key.export_key(format="PEM"))
    print("Ephemeral public key DER HEX:", packet["ephemeral_public"].hex())
    print("KDF salt HEX:", packet["salt"].hex())
    print("Nonce HEX:", packet["nonce"].hex())
    print("Ciphertext HEX:", packet["ciphertext"].hex())
    print("Authentication tag HEX:", packet["tag"].hex())
    print("Decrypted text:", recovered.decode("utf-8"))
    print("Verified:", recovered == message)


# Do not execute the demonstration when another question imports this file.


# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
encrypt = encrypt_ecc_hybrid
decrypt = decrypt_ecc_hybrid



if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, TypeError, KeyError) as error:
        print("Error:", error)
        raise SystemExit(1)
