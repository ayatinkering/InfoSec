"""Q2 and exam variants: AES-128/192/256 in ECB/CBC/CFB/OFB/CTR/EAX/GCM.

Key length selects AES version: 16/24/32 bytes. Functions use bytes.
IV modes return (iv, ciphertext); CTR returns (nonce, ciphertext);
EAX/GCM return (nonce, ciphertext, tag). The default demo remains AES-128 ECB.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def encrypt(message, key):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES needs 16/24/32 key bytes for AES-128/192/256.")
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(message, AES.block_size))


def decrypt(ciphertext, key):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES needs 16/24/32 key bytes for AES-128/192/256.")
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)



def generate_key(bits=256):
    """Generate a random key; save it for decryption."""
    if bits not in (128, 192, 256):
        raise ValueError("Choose 128, 192, or 256 key bits.")
    return get_random_bytes(bits // 8)


def encrypt_ecb(message, key):
    """ECB: PKCS#7 padding; returns ciphertext bytes."""
    return encrypt(message, key)


def decrypt_ecb(ciphertext, key):
    return decrypt(ciphertext, key)


def encrypt_cbc(message, key, iv=None):
    """CBC: returns (iv, ciphertext). Uses PKCS#7 padding."""
    if iv is None:
        iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return iv, ciphertext


def decrypt_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def encrypt_cfb(message, key, iv=None, segment_size=128):
    """CFB: returns (iv, ciphertext). No padding."""
    if iv is None:
        iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=segment_size)
    ciphertext = cipher.encrypt(message)
    return iv, ciphertext


def decrypt_cfb(ciphertext, key, iv, segment_size=128):
    cipher = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=segment_size)
    return cipher.decrypt(ciphertext)


def encrypt_ofb(message, key, iv=None):
    """OFB: returns (iv, ciphertext). No padding."""
    if iv is None:
        iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    ciphertext = cipher.encrypt(message)
    return iv, ciphertext


def decrypt_ofb(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    return cipher.decrypt(ciphertext)


def encrypt_ctr(message, key, nonce=None, initial_value=0):
    """CTR: returns (nonce, ciphertext); no padding. Save the counter value too."""
    if nonce is None:
        nonce = get_random_bytes(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=initial_value)
    return nonce, cipher.encrypt(message)


def decrypt_ctr(ciphertext, key, nonce, initial_value=0):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce, initial_value=initial_value)
    return cipher.decrypt(ciphertext)


def encrypt_eax(message, key, nonce=None, aad=b""):
    """EAX: returns (nonce, ciphertext, tag). AAD is authenticated, not encrypted."""
    if nonce is None:
        nonce = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag


def decrypt_eax(ciphertext, key, nonce, tag, aad=b""):
    """Return plaintext only after verification; tampering raises ValueError."""
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_gcm(message, key, nonce=None, aad=b""):
    """GCM: returns (nonce, ciphertext, tag). AAD is authenticated, not encrypted."""
    if nonce is None:
        nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag


def decrypt_gcm(ciphertext, key, nonce, tag, aad=b""):
    """Return plaintext only after verification; tampering raises ValueError."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)


def main():
    message = input("Plaintext [Enter = Sensitive Information]: ") or "Sensitive Information"
    key_hex = input("Key HEX [Enter = 0123456789ABCDEF0123456789ABCDEF]: ")
    key = bytes.fromhex(key_hex or "0123456789ABCDEF0123456789ABCDEF")
    ciphertext = encrypt(message.encode("utf-8"), key)
    print("Algorithm: AES-" + str(len(key) * 8), "| Mode: ECB")
    print("Key bytes:", len(key), "| Block bytes:", AES.block_size)
    print("Ciphertext HEX:", ciphertext.hex())
    print("Decrypted text:", decrypt(ciphertext, key).decode("utf-8"))


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
        raise SystemExit(1)
