# DES/AES exam variations: functions to copy or import

Q1 and Q2 contain independent short functions. Copy the relevant function pair
and its imports into a new program, or import the question module beside it.
The `encrypt()` / `decrypt()` names retain the ECB default for the regular questions.

```python
import q1_des as des
import q2_aes128 as aes   # Filename kept for Q2; now supports all three key sizes.

message = "New question, same building blocks".encode("utf-8")
des_key = b"A1B2C3D4"                    # 8 text bytes
aes_key = aes.generate_key(256)          # 32 random bytes; save for decryption
# For a supplied hex key: aes_key = bytes.fromhex("...")
```

## Which function do I need?

Use the mode name in the question. In Q2, key length automatically selects
AES-128 (16 bytes), AES-192 (24), or AES-256 (32) for EVERY mode below.

| Mode | Encrypt function | Return value | Padding | What to retain for decryption |
| --- | --- | --- | --- | --- |
| ECB | `encrypt_ecb(message, key)` | `ciphertext` | PKCS#7 | Key and ciphertext |
| CBC | `encrypt_cbc(message, key, iv=None)` | `iv, ciphertext` | PKCS#7 | Key, IV, ciphertext |
| CFB | `encrypt_cfb(message, key, iv=None, segment_size=...)` | `iv, ciphertext` | None | Key, IV, segment size, ciphertext |
| OFB | `encrypt_ofb(message, key, iv=None)` | `iv, ciphertext` | None | Key, IV, ciphertext |
| CTR | `encrypt_ctr(message, key, nonce=None, initial_value=0)` | `nonce, ciphertext` | None | Key, nonce, initial counter, ciphertext |
| EAX | `encrypt_eax(message, key, nonce=None, aad=b"")` | `nonce, ciphertext, tag` | None | Key, nonce, tag, AAD, ciphertext |
| GCM (AES only) | `encrypt_gcm(message, key, nonce=None, aad=b"")` | `nonce, ciphertext, tag` | None | Key, nonce, tag, AAD, ciphertext |

DES has no AES-style 128/192/256 variants and has no GCM function here.
Q1 additionally has `encrypt_3des_ecb`, `decrypt_3des_ecb`,
`encrypt_3des_cbc`, `decrypt_3des_cbc`. A 16-byte key selects two-key Triple
DES, and 24 bytes selects three-key Triple DES. See Q4 for the manual key error.

## Ready-to-adapt AES calls

```python
# ECB: padded automatically.
ct = aes.encrypt_ecb(message, aes_key)
pt = aes.decrypt_ecb(ct, aes_key)

# CBC: a random IV is generated unless the question supplies one.
iv, ct = aes.encrypt_cbc(message, aes_key)
pt = aes.decrypt_cbc(ct, aes_key, iv)

# CFB: default is full-block CFB128 for AES (CFB64 for DES).
iv, ct = aes.encrypt_cfb(message, aes_key)
pt = aes.decrypt_cfb(ct, aes_key, iv)

# CFB8: pass 8 to BOTH sides. Segment size is in bits, not bytes.
iv, ct = aes.encrypt_cfb(message, aes_key, segment_size=8)
pt = aes.decrypt_cfb(ct, aes_key, iv, segment_size=8)

# OFB: no padding, including for a one-byte message.
iv, ct = aes.encrypt_ofb(message, aes_key)
pt = aes.decrypt_ofb(ct, aes_key, iv)

# CTR: same nonce AND initial counter on both sides.
nonce, ct = aes.encrypt_ctr(message, aes_key, initial_value=5)
pt = aes.decrypt_ctr(ct, aes_key, nonce, initial_value=5)

# EAX: decrypt returns only after the authentication tag is verified.
header = b"record-id:42"  # Authenticated metadata; not encrypted.
nonce, ct, tag = aes.encrypt_eax(message, aes_key, aad=header)
pt = aes.decrypt_eax(ct, aes_key, nonce, tag, aad=header)

# GCM: AES only. Altered ciphertext/nonce/tag/header raises ValueError.
nonce, ct, tag = aes.encrypt_gcm(message, aes_key, aad=header)
pt = aes.decrypt_gcm(ct, aes_key, nonce, tag, aad=header)
print(pt.decode("utf-8"))
```

The same call patterns work with `des` and `des_key`, except GCM.
For Triple DES:

```python
key = bytes.fromhex("0123456789ABCDEFFEDCBA98765432100011223344556677")
iv, ct = des.encrypt_3des_cbc(message, key)
pt = des.decrypt_3des_cbc(ct, key, iv)
```

## Supplied IVs/nonces and format pitfalls

- IVs: exactly 8 bytes for DES/3DES, 16 for AES.
- No IV/nonce is required for ECB.
- CTR nonce: 0-7 bytes for DES, 0-15 for AES; shorter leaves more counter bytes.
  Default generated sizes here are 4 bytes for DES, 8 for AES.
- CTR starts at 0 unless `initial_value` is supplied. Keep that value too.
- GCM generates a 12-byte nonce here. EAX generates 16 bytes.
- Do not reuse a nonce with the same key. Generate a fresh IV for encryption;
  CBC needs an unpredictable IV. Passing a supplied IV reproduces an exam vector.
- CFB defaults here are explicitly 64 bits for DES and 128 bits for AES.
  PyCryptodome's own default is 8, so specify the expected size when comparing
  to other code. Both sides must agree.
- `b"00000000"` is eight ASCII bytes. `bytes.fromhex("00000000")` is FOUR
  zero bytes. An AES 16-byte zero IV would be `bytes(16)`.
- Keep binary results as bytes. To store them in JSON/text, use `.hex()` for
  every binary field, then `bytes.fromhex()` when reading them back.
- EAX/GCM tags authenticate contents and AAD. CBC/CFB/OFB/CTR do not detect
  arbitrary tampering by themselves. A padding error is not authentication.

The regular Q1/Q2 demos still run ECB. These functions are tools for changed
questions, not separate additional-exercise programs. Coverage is the common
lab/exam modes above; specialized OpenPGP, key-wrapping, SIV, CCM, and OCB
protocols are outside this quick reference.

API details: [classic modes](https://www.pycryptodome.org/src/cipher/classic),
[authenticated modes](https://www.pycryptodome.org/src/cipher/modern).
