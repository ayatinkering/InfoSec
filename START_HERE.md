# Read, change, and reuse the lab programs

The study programs now use this layout:

```python
# ---------- ONE CLEAR STEP ----------
# What this step receives, what it calculates, and what it returns.
# HINT: the exact value or received copy you can change for an experiment.
def function_named_after_the_step(...):
    # Code for that step only.
    ...



# ---------- NEXT STEP ----------
# Explanation before the code, with space between independent steps.
```

Read the explanation, then the function. `main()` collects inputs and connects
the steps. Press Enter for displayed defaults. Importing the files does not
start demonstrations, listeners, or key generation.

There are no tampering prompts or test switches in the reusable functions.
Optional experiments are commented lines next to the values you can change.
Copy the functions you need and connect their return values in the new question;
the sample names/messages in `main()` do not constrain those functions.

The earlier short names such as `encrypt()` remain as compatibility names for
the descriptive implementations. They point to the same function; they do not
encrypt twice. For example, Lab 1's `encrypt = encrypt_affine` lets your previous
imports keep working while the implementation has a clearer name.

## What to open

| Lab | Folder | Main ideas |
| --- | --- | --- |
| 1 | `lab1/` | Named classical cipher functions, normalization, inverses, attacks |
| 2 | `lab2/` | Individual DES/AES modes; comments on keys, IVs, nonces, padding and tags |
| 3 | `lab3/` | RSA, ECC hybrid, ElGamal, file transfer and DH |
| 4 | `lab4/` | SecureCorp RSA/DH exchange and the regular Rabin key-management exercise |
| 5 | `lab5/` | Hash functions, socket integrity, collisions and file comparison |
| 6 | `lab6/` | Signing and verification functions; DH/HMAC; signature sockets |
| 7 | `lab7/` | Paillier addition, raw RSA multiplication, shared encrypted counts |
| 8 | `lab88/` | Your existing Lab 8 folder: HMAC search tokens and encrypted posting lists |

Existing filenames and the `lab88/` folder name have been kept. The completeness
pass adds the missing regular Lab 4 Q2 and [the PYQ1 voting example](PYQ1/README.md).

## How to test tampering correctly

1. Protect the ORIGINAL data: hash it, sign it, or encrypt/authenticate it.
2. Keep that original digest/signature/tag unchanged.
3. Change only the copy the receiver will examine.
4. Run the receiver verification on that changed copy.

If you change a message and then sign/hash it again, you have protected a NEW
message. Successful verification then is expected, not evidence of a failure.

### Signatures

Lab 6 marks the receiver-side value directly. Uncomment/change the indicated
line yourself; no extra question is asked at runtime:

```python
signature = sign_message(original, private_key)
received = original
# received = b"Changed message"    # CHANGE HERE, after signing
valid = verify_signature(received, signature, public_key)
```

Check that the result is False. A different signer's public key should also fail.
The signatures do not encrypt the message; encryption is a separate operation.

### Authenticated encryption (AES-GCM/EAX)

After encryption, flip one ciphertext/tag byte and keep the original nonce:

```python
nonce, ciphertext, tag = aes.encrypt_gcm(message, key)
changed = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

try:
    aes.decrypt_gcm(changed, key, nonce, tag)
except ValueError:
    print("Changed data rejected")
```

Use a nonempty message for the byte-flip example. See each function's return
order: some packets use `(nonce, tag, ciphertext)` instead. Names in the code
make that distinction explicit. Never ignore the tag or return plaintext before
verification completes.

### Hashes

Lab 5's client hashes its original message. Edit the commented `sent_data`
assignment to change ONLY the sent copy. The server returns the hash of what actually arrived. Different
hashes demonstrate corruption. Unkeyed hashes do not stop an attacker who can
replace both the data and its reference digest.

### Classical ciphers, CBC/CTR, and homomorphic encryption

Do not expect all modifications to raise an error. Classical ciphers, unauthenticated
modes, and the raw RSA/Paillier exercises do not contain authentication tags.
Homomorphic schemes deliberately allow certain changes to ciphertexts:

- Paillier: multiply ciphertexts to add plaintexts, modulo n.
- Raw RSA: multiply ciphertexts to multiply plaintexts, modulo n.

Those properties do not authenticate inputs or prove votes/counts are valid.
Add the signature/MAC/validation mechanism required by the larger question.

## Two-terminal examples

### Lab 5 hash transmission

1. Run `lab5/q2-server.py` and accept the host/port defaults.
2. Run `lab5/q2-client.py`, using the same host/port.
3. Run normally. To test corruption, edit the marked `sent_data` line in the
   client, restart the server, then run the client again.

Both normal and altered messages are tested, including messages larger than
one `recv()` buffer. TCP is a stream, so the server reads until the client
signals that sending has finished.

### Lab 6 signature transmission

1. Run `lab6/q4-keys.py` once. New files go under ignored `lab6/output/`.
2. Run `lab6/q4-server.py` with the public key file.
3. Run `lab6/q4-client.py` with the matching private key file.
4. For another run, restart the server; reuse the existing keys.

The key generator refuses to overwrite files. If keys already exist, skip
generation or enter new paths. Only the public key belongs with the verifier.
The plain socket verification-status reply is a local demonstration, not a
separately authenticated receipt or a complete production protocol.

## Searchable-encryption details

- `lab88/q1-sse.py`: an HMAC token finds an encrypted posting list; AES-GCM
  decrypts/verifies IDs and documents. Commented lines show how to alter a
  stored ciphertext AFTER encryption while retaining its original tag.
- `lab88/q2-pallier.py`: stable HMAC tokens plus Paillier-encrypted integer IDs.
  This is a hybrid classroom index, not a complete public-key searchable
  encryption construction. The query requires the search secret; documents
  in its local demo dictionary are plaintext.
- Query normalization is shared with indexing. Duplicate words in one document
  do not create repeated copies of that document ID.
- Repeated tokens and access patterns can still reveal information. Do not
  claim the simple indexes hide every aspect of a search.

## Run the checks

Use the same Python interpreter selected in VS Code or PyCharm:

```bash
python verify_all_labs.py
python lab2/verify_lab2.py
python lab3/verify_lab3.py
```

These verify mathematical answers, cipher round trips, signature/HMAC rejection,
revocation, search results, homomorphic arithmetic, and local socket exchanges.
The socket checks need loopback connections to be allowed.

No extra dependencies or editor-specific imports were introduced. Generated
keys remain outside Git; the same Python files run in PyCharm on the lab PC
with the dependencies from `requirements.txt` installed in its interpreter.
