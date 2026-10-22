"""Q1 and exam variants: DES ECB/CBC/CFB/OFB/CTR/EAX, plus 3DES ECB/CBC.

Functions use bytes. CBC/CFB/OFB return (iv, ciphertext); CTR returns
(nonce, ciphertext); EAX returns (nonce, ciphertext, tag). See the README.
The regular exercise demonstration still uses DES ECB.
"""

from Crypto.Cipher import DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def encrypt(message, key):
    if len(key) != 8:
        raise ValueError("DES needs an 8-byte key, including parity bits.")
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(message, DES.block_size))


def decrypt(ciphertext, key):
    if len(key) != 8:
        raise ValueError("DES needs an 8-byte key, including parity bits.")
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES.block_size)



def generate_key():
    """Generate a random key; save it for decryption."""
    return get_random_bytes(8)


def encrypt_ecb(message, key):
    """ECB: PKCS#7 padding; returns ciphertext bytes."""
    return encrypt(message, key)


def decrypt_ecb(ciphertext, key):
    return decrypt(ciphertext, key)


def encrypt_cbc(message, key, iv=None):
    """CBC: returns (iv, ciphertext). Uses PKCS#7 padding."""
    if iv is None:
        iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(message, DES.block_size))
    return iv, ciphertext


def decrypt_cbc(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), DES.block_size)


def encrypt_cfb(message, key, iv=None, segment_size=64):
    """CFB: returns (iv, ciphertext). No padding."""
    if iv is None:
        iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CFB, iv=iv, segment_size=segment_size)
    ciphertext = cipher.encrypt(message)
    return iv, ciphertext


def decrypt_cfb(ciphertext, key, iv, segment_size=64):
    cipher = DES.new(key, DES.MODE_CFB, iv=iv, segment_size=segment_size)
    return cipher.decrypt(ciphertext)


def encrypt_ofb(message, key, iv=None):
    """OFB: returns (iv, ciphertext). No padding."""
    if iv is None:
        iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_OFB, iv=iv)
    ciphertext = cipher.encrypt(message)
    return iv, ciphertext


def decrypt_ofb(ciphertext, key, iv):
    cipher = DES.new(key, DES.MODE_OFB, iv=iv)
    return cipher.decrypt(ciphertext)


def encrypt_ctr(message, key, nonce=None, initial_value=0):
    """CTR: returns (nonce, ciphertext); no padding. Save the counter value too."""
    if nonce is None:
        nonce = get_random_bytes(4)
    cipher = DES.new(key, DES.MODE_CTR, nonce=nonce, initial_value=initial_value)
    return nonce, cipher.encrypt(message)


def decrypt_ctr(ciphertext, key, nonce, initial_value=0):
    cipher = DES.new(key, DES.MODE_CTR, nonce=nonce, initial_value=initial_value)
    return cipher.decrypt(ciphertext)


def encrypt_eax(message, key, nonce=None, aad=b""):
    """EAX: returns (nonce, ciphertext, tag). AAD is authenticated, not encrypted."""
    if nonce is None:
        nonce = get_random_bytes(16)
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag


def decrypt_eax(ciphertext, key, nonce, tag, aad=b""):
    """Return plaintext only after verification; tampering raises ValueError."""
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_3des_ecb(message, key):
    """16 bytes = two-key 3DES; 24 bytes = three-key 3DES."""
    key = DES3.adjust_key_parity(key)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(pad(message, DES3.block_size))


def decrypt_3des_ecb(ciphertext, key):
    key = DES3.adjust_key_parity(key)
    cipher = DES3.new(key, DES3.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size)


def encrypt_3des_cbc(message, key, iv=None):
    """Triple DES CBC: returns (iv, ciphertext); 8-byte IV."""
    key = DES3.adjust_key_parity(key)
    if iv is None:
        iv = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return iv, cipher.encrypt(pad(message, DES3.block_size))


def decrypt_3des_cbc(ciphertext, key, iv):
    key = DES3.adjust_key_parity(key)
    cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size)


def main():
    message = input("Plaintext [Enter = Confidential Data]: ") or "Confidential Data"
    key_text = input("Key as 8 TEXT characters [Enter = A1B2C3D4]: ") or "A1B2C3D4"
    key = key_text.encode("utf-8")
    ciphertext = encrypt(message.encode("utf-8"), key)
    print("Mode: ECB; key interpreted as TEXT, not hex")
    print("Key bytes:", len(key), "| Block bytes:", DES.block_size)
    print("Ciphertext HEX:", ciphertext.hex())
    print("Decrypted text:", decrypt(ciphertext, key).decode("utf-8"))


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
        raise SystemExit(1)
