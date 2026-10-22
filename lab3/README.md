# Lab 3: Asymmetric Key Ciphers

All **five regular exercises** are included. Additional exercises are excluded.
Code is spaced into logical blocks, with comments before functions/major steps.
Each program takes inputs; press Enter for the displayed defaults.

## Run in PyCharm

Use the same interpreter as Lab 2: `.venv/bin/python` on this laptop.
No new packages are needed. Install the root `requirements.txt` on a new
machine using that machine's selected Python interpreter.

Open and run any `q*.py` file in PyCharm. Or, from the repository root:

```bash
python lab3/run_all.py
python lab3/verify_lab3.py
```

Use `.venv/bin/python` instead of `python` if the shell has a different Python.
`run_all.py` runs all defaults, including Q4's 1 MiB/10 MiB in-memory benchmark.
The verification script includes local TCP tests; local sockets must be allowed.

## Find the right program

| Question | File | Main reusable functions |
| --- | --- | --- |
| Q1 | `q1_rsa.py` | `textbook_keys`, `encrypt_number`, `decrypt_number`, `encrypt_textbook`, `decrypt_textbook`, `generate_keys`, `encrypt`, `decrypt` |
| Q2 | `q2_ecc.py` | `generate_keys`, `derive_key`, `encrypt`, `decrypt` |
| Q3 | `q3_elgamal.py` | `generate_keys`, `encrypt_number`, `decrypt_number`, `encrypt`, `decrypt` |
| Q4 | `q4_file_transfer.py` | `benchmark`, `encrypt_file_bytes`, `decrypt_file_bytes`, `serialize_packet`, `send_file`, `receive_file` |
| Q5 | `q5_diffie_hellman.py` | `generate_keypair`, `compute_shared_secret`, `derive_session_key`, `exchange` |

Q1/Q2/Q3/Q5 are self-contained. Q4 imports Q1 and Q2 from the same folder.
Importing the modules does not start prompts or network listeners.
Functions work with bytes; input/output and encoding belong in `main()`.

## Q1: RSA message encryption

The regular message is **Asymmetric Encryption**. Two modes support common
exam variants without mixing mathematical RSA with padded RSA.

### Mode 1: textbook RSA

Choose to enter `p,q,e`, or directly enter `n,e,d`. Then choose a text message
or an integer. The functions expose the equations:

```text
n = p*q
phi = (p-1)*(q-1)
d = inverse(e) mod phi
public key = (n,e)
private key = (n,d)
encryption: c = m^e mod n
decryption: m = c^d mod n
```

The defaults `p=61, q=53, e=17` give `n=3233, d=2753`.
The integer `65` encrypts to `2790`, which decrypts to `65`.

For small moduli, text is processed byte by byte so the full message need not
fit in a single integer. Each byte must still be less than n. Repeated bytes
produce repeated ciphertext integers: this is a teaching implementation, not
a secure encryption scheme. It is also deliberately separate from signatures.

### Mode 2: RSA-OAEP with SHA-256 (default)

Enter the message, then either an existing private PEM file (and optional
password), or the key size and public exponent for new keys. The default
is RSA-2048 with e=65537. The sender encrypts with the public key; the receiver
decrypts with the private key. A private-key holder can derive the public half.

RSA ciphertext is one modulus long. With SHA-256:

```text
maximum message bytes = modulus_bytes - 2*32 - 2
RSA-2048 -> 256 - 64 - 2 = 190 message bytes
```

Q1 reports an error if the message is too long. For larger files, use Q4's
hybrid scheme rather than encrypting an entire file as one RSA integer.
OAEP does not identify who sent the message; anyone with the public key can
encrypt. Sender authentication needs signatures or another authentication layer.

## Q2: ECC message encryption

The regular message is **Secure Transactions**. Choose P-256 (also named
secp256r1), P-384, or P-521. Enter a private scalar d, leave it random,
or import an existing private PEM file.

ECC alone is not a complete text encryption interface. This program explicitly
defines an educational ECDH/HKDF/AES-GCM hybrid:

```text
Receiver: private d, public Q=dG
Sender:   fresh ephemeral r, public R=rG
Sender shared point:   rQ = rdG
Receiver shared point: dR = drG
Same shared bytes -> HKDF with the same salt/context -> same AES-256 key
AES-GCM encrypts the message and supplies an authentication tag.
```

The packet carries ephemeral public key R (DER), the KDF salt, AES nonce,
ciphertext, and tag. It does not contain the private scalar or AES key.
The receiver uses its private key to recover the derived key and verify GCM
before returning plaintext. No direct string-to-curve-point encoding is needed.

This is not a claim to implement a named ECIES standard. Public-key authenticity
remains an assumption; GCM proves knowledge of the session key, not the human
sender's identity. The ephemeral sender key alone does not provide forward
secrecy against later compromise of the receiver's static private key.

## Q3: ElGamal message encryption

The regular message is **Confidential Data**. Enter p, g, and x (or generate x),
then enter h if supplied or let the program compute it. A supplied h must
match the private x used by the local receiver demonstration.

```text
public key: (p,g,h), where h=g^x mod p
private key: x
fresh encryption exponent: k
c1 = g^k mod p
c2 = m*h^k mod p
shared = c1^x mod p
m = c2 * inverse(shared) mod p
```

Defaults p=467 and g=2 are small so intermediate values remain readable.
Choose text or a numerical message. Integer mode optionally accepts a fixed
k for checking a worked example; otherwise k is random. Never deliberately
reuse an encryption exponent in a real system.

Text mode encodes every UTF-8 byte as `byte+1`, so p must exceed 256. It chooses
a new random exponent for each byte and returns a list of ciphertext pairs.
The +1 avoids encoding a zero byte as zero: multiplying zero would expose it.
Integer mode permits zero, but zero necessarily leaks through c2=0.

Parameter checks validate primality and ranges; they do not prove g has the
required large order for arbitrary supplied groups. The small defaults and
raw malleable ElGamal are for the lab, not real-world secure messaging.

## Q4: File transfer and performance comparison

The manual asks for RSA-2048 and ECC secp256r1/P-256 with files such as 1 MB
and 10 MB. Both methods use **hybrid encryption**:

- RSA path: random AES-256 key -> RSA-OAEP wraps that key -> AES-GCM encrypts file.
- ECC path: ephemeral ECDH + HKDF derives AES-256 key -> AES-GCM encrypts file.

### Mode 1: benchmark (default)

Enter existing file paths separated by `|`, or generate random data at the
sizes you enter (defaults **1 and 10 MiB**, where MiB=1024*1024 bytes).
Enter repetitions. Optionally save the results to a NEW CSV file.

Every file is encrypted and decrypted by BOTH algorithms; recovered bytes
must match before the measurement is reported. Output includes:

- Key generation time, averaged separately from file operations.
- Encryption/decryption time, including wrapping/derivation and AES operations.
- Public/private key sizes as DER-encoded byte counts, not raw scalar lengths.
- Cryptographic envelope overhead: all binary fields minus plaintext size.
- JSON transport size, which additionally includes base64 and JSON expansion.

Disk I/O, socket time, JSON conversion, and equality checking are outside the
reported encryption/decryption timers. This is a full hybrid operation benchmark,
not a claim to measure only RSA versus only ECC bulk encryption. When repeats
exceeds one, key generation is averaged and the last generated key is reused for
all repeated encryptions of each dataset.

P-256 keys are smaller. AES dominates much of the cost for large files. Actual
speed depends on the machine; do not promise ECC is always faster. RSA-2048
provides roughly 112-bit classical security, while P-256 provides roughly 128:
the exercise's requested settings are not exactly equal-security comparisons.
Both asymmetric algorithms are vulnerable to a sufficiently capable quantum
computer. A faster timing does not establish greater security.

### Modes 2 and 3: actual TCP sender/receiver

1. Run Q4 in one PyCharm terminal. Choose **3=receive**, host/port, RSA or ECC,
   and a NEW destination file. It prints a public-key SHA-256 fingerprint.
2. Run Q4 again in a second terminal. Choose **2=send**, the same host/port,
   source file path, and the receiver fingerprint copied through a trusted route.
3. The receiver supplies its public key. The sender checks its fingerprint,
   encrypts the file, and sends the envelope. Only the receiver holds the private key.
4. The receiver verifies GCM before saving, then acknowledges the byte count
   and SHA-256. The sender compares these against the original data.

TCP is a byte stream: `receive_exact()` loops, and an 8-byte length prefix
frames each message. Data frames are limited to 64 MiB, including base64/JSON.
This comfortably fits the default 10 MiB example. Files are handled in memory,
not streamed in bounded chunks; this is intended for lab-sized transfers.

Existing output files are never overwritten. Default received files go under
`lab3/output/`, ignored by Git. Generated benchmark data stays in memory.
Do not commit real private keys or personal input files.

Fingerprint pinning authenticates the receiver's key only if the expected
fingerprint came from a trusted route. Leaving it blank explicitly runs an
unauthenticated local demo vulnerable to a middleman replacing the key.
There is no sender signature or login here. The acknowledgement is a diagnostic
confirmation, not a separate cryptographically authenticated receipt. Adding
those properties belongs to the signature/access-control requirements of a
larger scenario; do not claim this lab implements them.

## Q5: Diffie-Hellman key exchange

Enter p, g, Alice's private a and Bob's private b (or type `random`).
The small defaults give a hand-checkable example:

```text
p=23, g=5, a=6, b=15
A = g^a mod p = 8
B = g^b mod p = 19
Alice computes B^a mod p = 2
Bob computes A^b mod p = 2
```

Only p,g,A,B travel between peers. a and b stay private. Timings show Alice
and Bob key generation and shared-secret computation separately. HKDF converts
the shared integer to an AES key; a short AES-GCM exchange demonstrates its use.
The raw integer 2 is not itself a properly formatted AES key.

Basic validation rejects composite p and degenerate public/shared values.
For tiny groups, some randomly chosen exponents can produce degenerate results
and are rejected. Choose suitable values and try again. The program does not
provide authenticated production DH groups or a full subgroup validation scheme.
Group setup/primality checks occur outside the per-peer timing measurements.

DH **agrees** a secret; RSA encryption **transports** a secret. DH alone cannot
detect a middleman: authenticate exchanged public keys in a complete protocol.

## Reuse in a fresh question

Keep the new program in `lab3/` so imports resolve naturally:

```python
import q1_rsa as rsa
import q2_ecc as ecc
import q4_file_transfer as files

message = "New exam requirement".encode("utf-8")
receiver = rsa.generate_keys(2048)
packet = files.encrypt_file_bytes(message, "RSA", receiver.public_key())
recovered = files.decrypt_file_bytes(packet, "RSA", receiver)
print(recovered.decode("utf-8"))
```

Replace message bytes with `Path(...).read_bytes()` for a binary file. Preserve
the envelope fields and their meaning. Hashing, signatures, timestamps, and
permissions should be separate operations connected to these functions.

## References

- [RSA-OAEP and message limits](https://www.pycryptodome.org/src/cipher/oaep)
- [ECC keys](https://www.pycryptodome.org/src/public_key/ecc)
- [ECDH and key derivation](https://www.pycryptodome.org/src/protocol/dh)
- [ElGamal components](https://www.pycryptodome.org/src/public_key/elgamal)
- [NIST key-strength comparisons, Table 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
