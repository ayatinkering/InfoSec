# IS LAB 1–8: BEGINNER CRYPTO TOOLBOX

**Run original e-voting question unchanged:** Terminal 1 `python server.py`, Terminal 2 `python client.py`.
**Install:** `python -m pip install pycryptodome`.

The original `client.py` and `server.py` behavior is unchanged. Their TOP comments now show which imports/calls to replace for a new PYQ. `crypto_helpers.py` contains the existing e-voting functions PLUS all the Lab 1–8 exercise helpers from the previous master.py, and new consistent beginner wrappers.

## The most important pattern
```python
from crypto_helpers import key_for, encrypt_data, decrypt_data

message = b"HELLO"
key = key_for("AES", 256)
packet = encrypt_data(message, key, "AES", "CBC")
original = decrypt_data(packet, key, "AES")
print(original.decode())
```

### Swap algorithms: only change the algorithm/key/mode
```python
key = key_for("AES", 128)                # AES-128
packet = encrypt_data(message,key,"AES","GCM")
plain = decrypt_data(packet,key,"AES")

key = key_for("AES", 192)                # AES-192
packet = encrypt_data(message,key,"AES","CTR")

key = key_for("AES", 256)                # AES-256
packet = encrypt_data(message,key,"AES","ECB")

key = key_for("DES")                     # DES (legacy)
packet = encrypt_data(message,key,"DES","CBC")
plain = decrypt_data(packet,key,"DES")

key = key_for("3DES")                    # 3DES (legacy)
packet = encrypt_data(message,key,"3DES","CBC")
plain = decrypt_data(packet,key,"3DES")
```
ECB is insecure; CBC is unauthenticated unless paired with authentication; CTR requires unique nonces; GCM authenticates ciphertext and needs unique nonces.

## Lab-by-lab copy/paste guide
**Lab 1 — classical ciphers:** `caesar_encrypt/decrypt`, `multiplicative_encrypt/decrypt`, `affine_encrypt/decrypt`, `vigenere_encrypt/decrypt`, `autokey_encrypt/decrypt`, `playfair_encrypt/decrypt`, `hill_encrypt/decrypt`, `transposition_encrypt/decrypt`. Also `lab1_brute_affine`, `lab1_clean`, `lab1_playfair_square`.

**Lab 2 — symmetric:** `key_for`, `encrypt_data`, `decrypt_data`, `aes_128_encrypt`, `aes_192_encrypt`, `aes_256_encrypt`, `des_encrypt`, `triple_des_encrypt`, `compare_time`, `lab2_compare`. Use same key and packet to decrypt.

**Lab 3 — public key:** `rsa_make_keys`, `rsa_encrypt_bytes`, `rsa_decrypt_bytes`, `ecc_make_keys`, `ecc_encrypt_demo`, `diffie_hellman_demo`, `lab3_elgamal_keys`, `lab3_elgamal_encrypt_number`, `lab3_elgamal_decrypt_number`. ECC hybrid demo is ECDH+AES, not direct textbook ECC encryption.

**Lab 4 — key management:** `lab4_key_registry`, `lab4_allowed`, `rabin_make_keys`, `rabin_encrypt_number`, `rabin_decrypt_roots`, `lab4_weak_rsa`. Key registry is an in-memory classroom demo, not a production key management service.

**Lab 5 — hashing/file/socket:** `hash_text`, `hash_bytes`, `hash_txt_file`, `write_hash_txt`, `verify_hash`, `custom_hash_5381`, `send_json`, `recv_json`, `lab5_compare`, `lab5_socket_demo`.

**Lab 6 — signatures:** `rsa_sign_bytes`, `rsa_verify_bytes` (RSA-PSS/SHA-512); `elgamal_keys`, `elgamal_sign`, `elgamal_verify`; `ecc_sign`, `ecc_verify` (ECDSA/SHA-256); `schnorr_make_keys`, `schnorr_sign`, `schnorr_verify` (toy). Use private to sign, trusted public to verify.

**Lab 7 — homomorphic:** `paillier_keys`, `paillier_encrypt`, `paillier_sum`, `paillier_decrypt`, `paillier_add_constant`, `one_hot_vote`, `lab7_rsa_multiply`, `lab7_elgamal_multiply`, `lab7_sharing`. RSA and ElGamal examples use textbook arithmetic only; they do not provide production-safe homomorphic services.

**Lab 8 — searchable encryption:** `encrypt_document`, `decrypt_document`, `build_search_index`, `search_documents`, `build_paillier_id_index`, `lab8_gpg_demo`, `lab8_snort_demo`. The last two provide command/rule demonstrations; GnuPG and Snort are external applications.

## Minimal blended example: RSA + AES + SHA + RSA signature
```python
from crypto_helpers import (
    rsa_make_keys, rsa_encrypt_bytes, rsa_decrypt_bytes,
    key_for, encrypt_data, decrypt_data,
    hash_bytes, rsa_sign_bytes, rsa_verify_bytes
)

message = b"patient_id=101"
server_pub, server_priv = rsa_make_keys(2048)
sign_pub, sign_priv = rsa_make_keys(2048)

aes_key = key_for("AES",256)
cipher_packet = encrypt_data(message,aes_key,"AES","GCM")
wrapped_key = rsa_encrypt_bytes(aes_key,server_pub)
digest = hash_bytes(message,"sha512")
signature = rsa_sign_bytes(message,sign_priv)

recovered_key = rsa_decrypt_bytes(wrapped_key,server_priv)
recovered = decrypt_data(cipher_packet,recovered_key,"AES")
print("Original:",recovered)
print("Hash OK:",hash_bytes(recovered,"sha512")==digest)
print("Signature OK:",rsa_verify_bytes(recovered,signature,sign_pub))
```

## What cannot be reduced to a one-line swap
- A new cipher may change packet format, nonce/IV handling, and server verification.
- ElGamal/ECC/RSA signatures require **trusted registered public keys**, not arbitrary client-supplied keys.
- Full threshold Paillier decryption is NOT implemented.
- Genuine public-key searchable encryption (PEKS/PKSE) is NOT implemented; the example uses HMAC tokens and optionally Paillier-encrypted document IDs.
- Secure comparison of Paillier ciphertexts is NOT a built-in property.
- A separate trusted timestamp authority is NOT implemented.
- Real GnuPG and Snort operations need installed external tools and local configuration.
- This e-voting server decrypts individual AES ballots and is NOT a privacy-preserving election system.

## Testing status
All Python files were syntax-compiled. Full runtime testing was not possible here because PyCryptodome was not installed and package download was unavailable. Run on your own machine before your exam.
