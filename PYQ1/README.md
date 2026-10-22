# PYQ1: the e-voting question

Run **`voting.py`** in PyCharm or VS Code. The complete question, requirements,
design choices and change points are at the top of that file.

```bash
python PYQ1/voting.py
```

Uses the existing PyCryptodome dependency. First run generates the required
RSA-4096 key and creates `.txt` files **beside the script**, independently of
the current terminal directory. Restarting reuses those files.

## Follow this menu sequence

1. Start as `admin`; register voter IDs such as `voter1` and `voter2`.
2. Switch to a registered voter; cast a vote with constituency and candidate ID.
3. Switch to `server`; verify/process the pending ballots.
4. Switch to `auditor`; search by constituency, by a time range, or both.
5. Switch to `server`; show encrypted totals. These remain ciphertexts.
6. Switch to `admin`; close the election after all pending ballots are processed.
7. Switch to `trustee1`; submit partial decryption. Repeat as `trustee2`.
8. Switch to `server`; publish the final candidate-wise results.

The role switch simulates lab login. Every action separately checks RBAC.
Client and server are separate functions/roles communicating through the `.txt`
queue in this single menu-driven program; no socket setup is needed.

## Question/marking component -> code to read

| Component | Client step | Server step |
| --- | --- | --- |
| Client/server | `cast_vote()` writes pending packets | `process_pending_ballots()` reads/verifies them |
| Encryption/decryption | AES-256-CBC ballot, RSA-4096 wrapped AES key | RSA unwrap, AES decrypt for hash comparison |
| DSS | ElGamal signature of SHA-512 ballot hash | Verify with the voter's public key |
| Hash | SHA-512 of exact serialized ballot bytes | Recompute and compare SHA-512 |
| Search | Constituency HMAC token -> index | Return matching IDs/times, without vote contents |
| Homomorphic tally | Encrypted candidate ID and per-candidate encrypted 0/1 counts | Multiply ciphertexts to add counts |
| Timestamp | Local authority signs time bound to ballot hash | Verify authority signature and deadline |
| Threshold | Each trustee holds a separate share | Combine both partial results for final totals only |
| RBAC/storage | Role-permission table | Read/write JSON-formatted `.txt` files |

## Files and small changes

- `settings.txt`: candidates, start, deadline, election-open status and public n.
- `users.txt`, `voters.txt`: role map and voter ElGamal keys.
- `ballots.txt`: encrypted packets, hashes, signatures, signed times and status.
- `search_index.txt`: token -> matching IDs/times; no plaintext candidate choices.
- `encrypted_totals.txt`: encrypted counts; `partial_results.txt`: trustee outputs.
- `results.txt`: final plaintext totals after both trustees contribute.
- Key `.txt` files: local election/authority keys and separate trustee shares.

Change the candidate table in `setup_election()` before first initialization.
After initialization, edit `settings.txt` for an exam deadline variation. Signed
timestamps cannot simply be edited without invalidating their authority signature.
For a fresh practice election, move the generated `.txt` files elsewhere, then run
again. Generated data/keys are ignored by Git and are not part of the download.

## How to adapt the same building blocks

Read `cast_vote()` first, then `verify_received_ballot()`. The generic order is:

```text
Collect fields -> serialize bytes -> hash -> sign -> encrypt -> save/send
Read/receive -> decrypt -> hash comparison -> signature/time checks -> process
```

For a medical/banking question, replace the ballot dictionary fields with the
requested record fields. Crypto helpers accept bytes, keys and integers, so the
algorithm blocks do not depend on the story. Keep the required algorithms/modes.

Comments mark where to alter the received ciphertext while retaining its original
hash/signature. No tampering questions or switches are added to the program.

## Two details needed to interpret the paper

Summing raw candidate IDs does not give candidate-wise counts. That is why the
ballot carries the requested encrypted ID plus encrypted 0/1 candidate counts.
The hash/signature cover those count ciphertexts as part of the ballot.

The authority is simulated by a separate function and RSA key. The server
temporarily recovers the AES ballot for the required hash comparison, but never
decrypts individual Paillier ciphertexts. Threshold decryption operates on the
final count ciphertexts using both trustees' partial results; it is not merely
two approval flags followed by ordinary decryption. This is a lab implementation
without threshold-share correctness proofs or real OS-level role separation.

The two-share arithmetic follows the threshold Paillier construction described
in [Damgård and Jurik's paper](https://www.brics.dk/RS/00/45/).
