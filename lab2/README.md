# Lab 2: DES, Triple DES, and AES

The **five regular exercise programs** are included. At your request, Q1/Q2
also contain reusable mode/key-size variants for new exam questions.
There are no separate additional-exercise programs or plots.

Code style reference: [your DES/AES lab folder](https://github.com/ayatinkering/ayati-all-labs/tree/main/lab2%20DES-AES).
Each question is self-contained, with reusable functions and input/output in
`main()`. Importing a question file does not run its demonstration.

For Q1/Q2 mode variants, key sizes, return values, and copyable examples, see
[the mode quick reference](MODE_QUICK_REFERENCE.md).

## Setup once, then run in PyCharm

Lab 1 needs no third-party packages. Lab 2 needs **PyCryptodome**.
The pinned version in the root `requirements.txt` requires **Python 3.9+**.

In PyCharm select the project's interpreter. On this laptop, use
`InfoSec/.venv/bin/python`; PyCryptodome is already installed there.
On the lab computer, select an existing prepared interpreter or create a local
environment, then install requirements using THAT interpreter. A GitHub ZIP
does not contain installed packages, and this laptop's `.venv` is not portable.

For a new environment, run these commands from the project root:

Linux/macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python lab2/run_all.py
```

Windows:

```powershell
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe lab2/run_all.py
```

Select that environment's Python in PyCharm too. You do not need to activate
the environment when calling its Python by the explicit path above.
Package installation requires internet or previously prepared compatible wheels.
Prepare and run on the actual lab computer before the exam if possible.

Run any question file individually. Press Enter for the displayed manual defaults,
or enter a new message/key. Run `run_all.py` for all defaults without typing.

## Files and functions

| Question | File | Functions for reuse |
| --- | --- | --- |
| 1 | `q1_des.py` | DES ECB/CBC/CFB/OFB/CTR/EAX, 3DES ECB/CBC, `generate_key()` |
| 2 | `q2_aes128.py` | AES-128/192/256 with ECB/CBC/CFB/OFB/CTR/EAX/GCM, `generate_key(bits)` |
| 3 | `q3_compare_des_aes256.py` | `encrypt_des`, `decrypt_des`, `encrypt_aes`, `decrypt_aes`, `measure`, `compare` |
| 4 | `q4_triple_des.py` | `encrypt`, `decrypt`, `validate_key` |
| 5 | `q5_aes192_steps.py` | `encrypt`, `decrypt`, `expand_key`, `encrypt_block`, `encrypt_with_steps` |
| Checks | `verify_lab2.py` | Run this to verify known answers, round trips, and invalid inputs |

## The shared mental model

```text
Text -> encode -> bytes -> pad -> encrypt -> ciphertext bytes
Ciphertext bytes -> decrypt -> unpad -> bytes -> decode -> text
```

- Unlike Lab 1, do not remove spaces or change case. UTF-8 encoding preserves them.
- Functions accept **bytes** and return **bytes**. Convert text only at the edges.
- `ciphertext.hex()` displays bytes; `bytes.fromhex(...)` reverses that display.
  Hex encoding is not encryption.
- To encrypt a file, pass `file.read_bytes()` instead of encoding a text string;
  write decrypted bytes back without decoding them.

## Key size versus block size

| Algorithm | Key bytes | Block bytes | Rounds |
| --- | --- | --- | --- |
| DES | 8 including parity (56 effective key bits) | 8 | 16 |
| Triple DES | 16 or 24 including parity | 8 | Three DES stages |
| AES-128 | 16 | 16 | 10 |
| AES-192 | 24 | 16 | 12 |
| AES-256 | 32 | 16 | 14 |

One byte is 8 bits. Two hex digits encode one byte. AES's block size is ALWAYS
16 bytes: the suffix changes key size and round count, not block size.
For ASCII, a character encoded as text occupies one byte; general UTF-8 text
can occupy more. Validate byte length, not merely character count.

```python
text_key = "A1B2C3D4".encode("utf-8")   # 8 bytes: valid DES length
hex_key = bytes.fromhex("A1B2C3D4")    # 4 bytes: invalid DES length
```

Keys are never silently truncated, padded, or hashed to fit. Message padding
and key validity are separate issues.

## Padding and mode

The regular questions do not name a mode. These solutions explicitly assume
**ECB with PKCS#7 padding**, matching the reference's choice. Therefore the
example ciphertexts are reproducible and no IV is involved.

For a 16-byte block, a 13-byte message gets three bytes `03 03 03`.
An exactly 16-byte message gets a FULL extra block of sixteen `10` bytes
(hexadecimal 10 = decimal 16). This avoids ambiguity when unpadding.
DES/3DES use the same rule with 8-byte blocks. Never use `rstrip()` to unpad.

ECB encrypts each block independently: equal plaintext blocks under the same
key produce equal ciphertext blocks. CBC chains blocks, needs a fresh
unpredictable IV per encryption, and requires that IV for decryption. CTR
uses a nonce/counter, requires uniqueness under the key, and needs no padding.
If a future question changes the mode, update creation/decryption and retain
the required IV or nonce; changing the constant alone is insufficient.

ECB/CBC encryption alone does not authenticate a message. Successful unpadding
does not prove authenticity. Use the signature/MAC or authenticated mode that
the scenario calls for. DES and Triple DES are legacy algorithms taught here;
they are not choices for a new secure system.

## Q1: DES

DES splits each 64-bit block into two 32-bit halves. A Feistel round computes
`L_next = R`, `R_next = L XOR F(R, round_key)`. F expands 32 bits to 48,
XORs the round key, applies S-boxes, and permutes the result. After 16 rounds,
the halves are swapped and the final permutation is applied. Decryption uses
the round keys in reverse order. The library performs these internal steps.

The supplied `A1B2C3D4` is interpreted as eight TEXT bytes, not four hex bytes.
`Confidential Data` has 17 bytes, so padding produces 24 bytes.

## Q2: AES-128

Interpret the supplied `0123456789ABCDEF0123456789ABCDEF` as HEX:
32 hex digits -> 16 bytes -> AES-128. Encoding it as text would instead give
32 bytes, which selects AES-256. Q2 now supports that variation too and labels
the version in its output. The default is still hex interpretation for AES-128.

## Q3: DES versus AES-256 performance

The message is `Performance Testing of Encryption Algorithms`. Q3 chooses
and states demonstration keys because the question does not supply keys.
Both ciphers use ECB and PKCS#7. Keys/message conversion occur before timing.

`measure()` warms up the function, repeats it, and divides elapsed time by
the repetition count. It times cipher creation plus padding/encryption, or
creation plus decryption/unpadding. It does not isolate only the internal rounds.
Printing occurs afterward. `compare()` also verifies both decryptions.

The output reports average microseconds per call and which is faster IN THAT
RUN. Hardware acceleration, Python/library overhead, message size, and machine
load affect results. Do not assume a larger key must be slower, or infer
security strength from speed. Rerun measurements when making a comparison.

## Q4: Triple DES and the invalid manual key

Encryption is `E_K3(D_K2(E_K1(P)))`. Decryption reverses that composition.
For a 16-byte key the third component equals the first (two-key Triple DES).

The manual's 48 hex digits encode 24 bytes, but its three 8-byte components
are identical. E and D cancel, reducing it to single DES. PyCryptodome rejects
this key. Parity adjustment cannot make identical components independent.

The program first reports the rejection, then uses this explicitly chosen
valid alternative by default:

```text
0123456789ABCDEFFEDCBA98765432100011223344556677
```

This is a demonstration correction, not a claim about the author's intended
key. It is printed so no result is falsely attributed to the invalid key.
`validate_key()` returns the parity-adjusted key, used consistently on both sides.

## Q5: AES-192 and actual round steps

The supplied `FEDCBA9876543210FEDCBA9876543210` is 16 bytes as hex or 32 bytes
as text; neither is 24 bytes. The program states this, then explicitly appends
`FEDCBA9876543210` to form the default 24-byte demonstration key. It accepts
another valid 48-hex-digit key if you enter one.

AES treats the block as a 4x4 byte state, filled column by column:

```text
Input bytes: b0 b1 b2 b3 b4 ... b15
State:
b0 b4 b8  b12
b1 b5 b9  b13
b2 b6 b10 b14
b3 b7 b11 b15
```

Key expansion starts from six 4-byte words. New words XOR a previous word
with the word six positions back. Every sixth word first applies RotWord,
SubWord, and Rcon. The result is 52 words grouped into thirteen 16-byte
round keys. The original key size and each round key's size differ.

1. Initial round: AddRoundKey (XOR the state with round key 0).
2. Rounds 1-11: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey.
3. Round 12: SubBytes -> ShiftRows -> AddRoundKey. No MixColumns.

SubBytes uses a nonlinear substitution table. ShiftRows cyclically shifts
each row left by its row index. MixColumns combines bytes within each column
using arithmetic in GF(2^8), not ordinary integer arithmetic. AddRoundKey
introduces the expanded secret key by XOR.

The educational implementation prints every generated word, round key, and
actual state after each transformation, for EVERY padded message block.
Its final bytes are compared to PyCryptodome. A FIPS 197 known-answer test
also checks it independently. The trace serializes states column by column.

For exam composition, use the short `encrypt()` and `decrypt()` functions
near the top; the longer implementation exists to satisfy Q5's step display.

## Compose operations in a new question

In a new file beside these question files:

```python
import q2_aes128 as aes

message = "A fresh question".encode("utf-8")
key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
ciphertext = aes.encrypt(message, key)
recovered = aes.decrypt(ciphertext, key)
print(ciphertext.hex())
print(recovered.decode("utf-8"))
```

For AES-128/192/256, Q2 now accepts 16/24/32-byte keys in every mode. Q3 and Q5
also retain their dedicated AES-256/AES-192 functions. Follow each mode's
IV/nonce requirements and the question's requested integrity mechanism.
Keep encryption, key distribution, hashing, signatures, and permissions as
separate functions so their inputs/outputs can be connected.

## Verification

From the root, using the configured interpreter:

```bash
python lab2/verify_lab2.py
```

Checks include known DES/AES answers, the FIPS AES-192 vector, comparison of
the educational implementation to the library on multiple inputs, padding
boundaries, binary/Unicode data, invalid keys, and the manual key errors.

## Technical references

- [PyCryptodome AES](https://www.pycryptodome.org/src/cipher/aes)
- [PyCryptodome Triple DES](https://www.pycryptodome.org/src/cipher/des3)
- [Modes and padding](https://www.pycryptodome.org/src/cipher/classic)
- [FIPS 197: AES specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
