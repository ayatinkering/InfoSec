"""Q1 and exam variants: DES ECB/CBC/CFB/OFB/CTR/EAX, plus 3DES ECB/CBC.

Functions use bytes. CBC/CFB/OFB return (iv, ciphertext); CTR returns
(nonce, ciphertext); EAX returns (nonce, ciphertext, tag). See the README.
The regular exercise demonstration still uses DES ECB.
"""

from Crypto.Cipher import DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad



# ---------- ENCRYPT ECB ----------
# Pad the message to complete blocks and encrypt each block independently.
# ECB has no IV or authentication. Equal plaintext blocks expose repetition.
def encrypt_ecb(message, key):
    if len(key) != 8:
        raise ValueError("DES needs an 8-byte key, including parity bits.")

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = pad(message, DES.block_size)
    ciphertext = cipher.encrypt(padded_message)

    return ciphertext



# ---------- DECRYPT ECB ----------
# Decrypt complete blocks, then remove PKCS#7 message padding.
# A padding error is not a reliable authenticity check.
def decrypt_ecb(ciphertext, key):
    if len(key) != 8:
        raise ValueError("DES needs an 8-byte key, including parity bits.")

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_message, DES.block_size)

    return plaintext



# ---------- GENERATE KEY ----------
# Generate a random symmetric key of the supported length.
# SAVE the returned key; generating a new key during decryption will not work.
def generate_key():
    """Generate a random key; save it for decryption."""
    return get_random_bytes(8)



# ---------- ENCRYPT CBC ----------
# Generate/use an IV, pad the message, and encrypt in CBC mode.
# Return (iv,ciphertext). Preserve this IV; use a fresh unpredictable IV next time.
def encrypt_cbc(message, key, iv=None):
    """CBC: returns (iv, ciphertext). Uses PKCS#7 padding."""
    if iv is None:
        iv = get_random_bytes(8)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    padded_message = pad(message, DES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    return iv, ciphertext



# ---------- DECRYPT CBC ----------
# Use the original key AND IV, decrypt, then remove message padding.
# CBC has no authentication tag. Modified data is not reliably detected.
def decrypt_cbc(ciphertext, key, iv):

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    padded_message = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_message, DES.block_size)

    return plaintext



# ---------- ENCRYPT CFB ----------
# Use the chosen feedback segment size; return (iv,ciphertext), without padding.
# segment_size is in BITS: try 8 for CFB8; both sides must use the same value.
def encrypt_cfb(message, key, iv=None, segment_size=64):
    """CFB: returns (iv, ciphertext). No padding."""
    if iv is None:
        iv = get_random_bytes(8)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_CFB, iv=iv, segment_size=segment_size)
    ciphertext = cipher.encrypt(message)
    return iv, ciphertext



# ---------- DECRYPT CFB ----------
# Recover bytes with the same key, IV and feedback segment size; no unpadding.
# The full-block defaults here differ from the library default of 8 bits.
def decrypt_cfb(ciphertext, key, iv, segment_size=64):

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_CFB, iv=iv, segment_size=segment_size)
    return cipher.decrypt(ciphertext)



# ---------- ENCRYPT OFB ----------
# Use the IV to generate an output-feedback keystream; return (iv,ciphertext).
# No padding. Do not reuse the same IV with the same key.
def encrypt_ofb(message, key, iv=None):
    """OFB: returns (iv, ciphertext). No padding."""
    if iv is None:
        iv = get_random_bytes(8)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_OFB, iv=iv)
    ciphertext = cipher.encrypt(message)
    return iv, ciphertext



# ---------- DECRYPT OFB ----------
# Recreate the keystream from the original IV and key to recover message bytes.
# Do not add unpad(): OFB did not add padding.
def decrypt_ofb(ciphertext, key, iv):

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_OFB, iv=iv)
    return cipher.decrypt(ciphertext)



# ---------- ENCRYPT CTR ----------
# Encrypt a counter stream and XOR with the message; return (nonce,ciphertext).
# No padding. Save initial_value too; never reuse the nonce/counter stream for a key.
def encrypt_ctr(message, key, nonce=None, initial_value=0):
    """CTR: returns (nonce, ciphertext); no padding. Save the counter value too."""
    if nonce is None:
        nonce = get_random_bytes(4)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_CTR, nonce=nonce, initial_value=initial_value)
    ciphertext = cipher.encrypt(message)

    return nonce, ciphertext



# ---------- DECRYPT CTR ----------
# Recreate the SAME nonce/counter stream; no message padding is involved.
# A changed nonce or starting counter gives different plaintext.
def decrypt_ctr(ciphertext, key, nonce, initial_value=0):

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_CTR, nonce=nonce, initial_value=initial_value)
    return cipher.decrypt(ciphertext)



# ---------- ENCRYPT EAX ----------
# Encrypt and compute an authentication tag, optionally covering unencrypted AAD.
# Return (nonce,ciphertext,tag). Keep all three and the same AAD.
def encrypt_eax(message, key, nonce=None, aad=b""):
    """EAX: returns (nonce, ciphertext, tag). AAD is authenticated, not encrypted."""
    if nonce is None:
        nonce = get_random_bytes(16)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)

    # Authenticate this unencrypted metadata too; decryption must use the same bytes.
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag



# ---------- DECRYPT EAX ----------
# Verify the tag and return plaintext only if authentication succeeds.
# TAMPER HINT: flip a ciphertext/tag byte AFTER encryption, without recomputing the tag.
def decrypt_eax(ciphertext, key, nonce, tag, aad=b""):
    """Return plaintext only after verification; tampering raises ValueError."""

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)

    # Authenticate this unencrypted metadata too; decryption must use the same bytes.
    cipher.update(aad)

    # A changed tag/ciphertext raises ValueError; never return unverified plaintext.
    return cipher.decrypt_and_verify(ciphertext, tag)



# ---------- ENCRYPT 3DES ECB ----------
# Apply Triple DES with 16-byte or 24-byte keys and message padding.
# Equal DES key components may collapse to single DES and are rejected.
def encrypt_3des_ecb(message, key):
    """16 bytes = two-key 3DES; 24 bytes = three-key 3DES."""
    key = DES3.adjust_key_parity(key)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_message = pad(message, DES3.block_size)
    ciphertext = cipher.encrypt(padded_message)

    return ciphertext



# ---------- DECRYPT 3DES ECB ----------
# Decrypt Triple DES ECB and remove its 8-byte-block PKCS#7 padding.
# Use exactly the same key components as encryption.
def decrypt_3des_ecb(ciphertext, key):
    key = DES3.adjust_key_parity(key)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_message = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_message, DES3.block_size)

    return plaintext



# ---------- ENCRYPT 3DES CBC ----------
# Use Triple DES CBC with an 8-byte IV; return (iv,ciphertext).
# 16 bytes selects two-key 3DES; 24 selects three-key 3DES.
def encrypt_3des_cbc(message, key, iv=None):
    """Triple DES CBC: returns (iv, ciphertext); 8-byte IV."""
    key = DES3.adjust_key_parity(key)
    if iv is None:
        iv = get_random_bytes(8)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded_message = pad(message, DES3.block_size)
    ciphertext = cipher.encrypt(padded_message)

    return iv, ciphertext



# ---------- DECRYPT 3DES CBC ----------
# Decrypt Triple DES using the original IV and then remove padding.
# Key parity adjustment does not repair repeated/degenerate key components.
def decrypt_3des_cbc(ciphertext, key, iv):
    key = DES3.adjust_key_parity(key)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    padded_message = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_message, DES3.block_size)

    return plaintext



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    message = input('Plaintext [Enter = Confidential Data]: ')

    if message == "":
        message = 'Confidential Data'

    key_text = input('Key as 8 TEXT characters [Enter = A1B2C3D4]: ')

    if key_text == "":
        key_text = 'A1B2C3D4'

    key = key_text.encode("utf-8")

    # Sender step: protect the ORIGINAL input and keep the returned result.
    ciphertext = encrypt_ecb(message.encode("utf-8"), key)
    print("Mode: ECB; key interpreted as TEXT, not hex")
    print("Key bytes:", len(key), "| Block bytes:", DES.block_size)
    print("Ciphertext HEX:", ciphertext.hex())
    print("Decrypted text:", decrypt_ecb(ciphertext, key).decode("utf-8"))




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
encrypt = encrypt_ecb
decrypt = decrypt_ecb



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
        raise SystemExit(1)
