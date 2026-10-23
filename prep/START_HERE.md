# START HERE — FOUR VERY EASY INFORMATION SECURITY LAB MASTER TEMPLATES

## How to think about every question

A **record** is the original input (e.g. voter ID and candidate, or patient ID and report).
A **packet** is the protected dictionary containing ciphertext, wrapped key, hash and signature.
A **key dictionary** is returned by `setup()` and holds the required public/private keys.
`crypto_helpers.py` contains reusable algorithms. **Do not edit it** when changing scenarios.
Each q1–q4 file runs alone: `python q1.py` (or q2/q3/q4).

## Memorize this order

1. `setup()` — prepare keys and system settings.
2. `read_records()` — ask for input; change field names for a new question.
3. `prepare_packet(record, keys)` — SENDER: turn input into bytes, hash, encrypt, wrap AES key, sign, and optionally encrypt numbers using Paillier.
4. `accept_record(packet, keys)` — RECEIVER: unwrap AES key, decrypt, recalculate hash, verify signature and timestamp, accept or reject.
5. `tally(keys)` — Paillier addition without decrypting individual values (only in voting/money questions).
6. `search(keys)` — search by permitted fields (constituency, branch, department, date).
7. `main()` — menu that calls the above functions.

**Q4 exception:** Rabin legal contracts do not use AES/RSA packet wrapping. The generic functions call `create_contract` and `view_contract` instead.

## Which question should I start from?

| Exam asks about | Start from | Change first |
|---|---|---|
| AES + RSA-PSS + Paillier voting + search | q1.py | `read_records`, `prepare_packet`, `accept_record`, `tally`, `search` |
| All keys/parameters from user + ElGamal + voting | q2.py | `setup`, `prepare_packet`, `accept_record` |
| AES + RSA + SHA + signature + tamper | q3.py | `read_records`, `prepare_packet`, `accept_record`, `tamper_demo` |
| Rabin + CRT + key renewal/revocation + roles | q4.py | `generate_keys`, `encrypt_text`, `decrypt_text`, `renew_key` |

## Algorithm change guide: edit THIS QUESTION FILE, not crypto_helpers.py

| Requirement | Edit sender | Edit receiver / other |
|---|---|---|
| SHA-256 instead of SHA-512 | `prepare_packet()` or `HASH_NAME` | `accept_record()` or `HASH_NAME` |
| AES-128 instead of AES-256 | `get_aes_key()` / `get_key_and_iv()` and `prepare_packet()` | `accept_record()` must use matching key size |
| AES-192 | 24-byte key | matching decryption |
| AES-256 | 32-byte key | matching decryption |
| AES-CBC | 16-byte IV and CBC encryption | CBC decryption + same IV |
| AES-GCM | nonce and authentication tag, no CBC padding | GCM decryption + verify tag |
| AES-CTR | nonce/counter, no CBC padding | matching CTR nonce/counter |
| AES-ECB | ECB mode, no IV (educational only) | ECB decryption |
| DES / 3DES | `prepare_packet()` cipher + appropriate key | `accept_record()` cipher + matching key |
| RSA key size | `setup()` | Same key pair is used for decryption |
| Signature algorithm | `setup()` keys + `prepare_packet()` signature | `accept_record()` matching verification |
| Vote to amount | `read_records()` amount + `prepare_packet()` Paillier value | `tally()` aggregate amount |
| Search by branch | `read_records()` branch | Index insertion + `search()` |
| RBAC permissions | usually none | `main()` permissions or role-specific menus |
| Different input data | `read_records()` | `accept_record()` field checks and output |

### AES helper calls (use only when the question does not require a manually provided IV)

```python
from crypto_helpers import key_for, encrypt_data, decrypt_data

key = key_for('AES', 128)          # 16 bytes
key = key_for('AES', 192)          # 24 bytes
key = key_for('AES', 256)          # 32 bytes

packet = encrypt_data(data, key, 'AES', 'CBC')
packet = encrypt_data(data, key, 'AES', 'GCM')
packet = encrypt_data(data, key, 'AES', 'CTR')
packet = encrypt_data(data, key, 'AES', 'ECB')
original = decrypt_data(packet, key, 'AES')

key = key_for('DES')
packet = encrypt_data(data, key, 'DES', 'CBC')
original = decrypt_data(packet, key, 'DES')

key = key_for('3DES')
packet = encrypt_data(data, key, '3DES', 'CBC')
original = decrypt_data(packet, key, '3DES')
```

**IMPORTANT:** Q2 and Q3 explicitly ask for a user-provided IV, so their AES-CBC code uses `AES.new(..., iv=...)` directly. Do not replace it with a helper that generates its own IV if the examiner requires manual IV input. AES-GCM also needs authentication-tag verification; it is not just a mode-name substitution.

## Read every code file top to bottom

Every function now has a `BEGINNER WALKTHROUGH` section, plus `WHY` comments beside important statements. The comments explain the purpose of each step, not only the cryptography name. These files preserve the logic of the previous set rather than changing the algorithm implementations.

## Critical caveats

- Q2's user-entered RSA primes must be large enough to fit the 32-byte AES key (`n > 2^256`); tiny classroom primes cannot do that in this implementation.
- Q2 is educational textbook RSA and manual ElGamal; it is not production-secure.
- Q1 and Q2 use Paillier one-hot vectors to count votes by candidate. Encrypting and adding candidate IDs directly gives the sum of IDs, not candidate-wise totals.
- A menu-driven local program simulates sender/receiver. It is **not a TCP client-server program**.
- Q4 uses classroom Rabin encoding; root selection can fail if the encoding does not uniquely identify a root.
- Python syntax was checked. Crypto libraries are not installed in this environment, so complete menu execution has not been validated.

## Run

```bash
python -m pip install -r requirements.txt
python q1.py
# OR python q2.py, q3.py, q4.py
```
