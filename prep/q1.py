# ============================================================================
# Q1 — RSA-SIGNED E-VOTING
# ============================================================================
# EXACT ALGORITHMS USED:
# AES-256-CBC | RSA-OAEP key wrapping | SHA-512 | RSA-PSS signature | Paillier one-hot | HMAC search | timestamp | RBAC
# KEY INPUTS: AES key: user input; RSA/Paillier keys: generated
#
# SHARED GENERIC NAMES: setup, read_records, prepare_packet, accept_record, tally, search, main
# crypto_helpers.py contains reusable algorithms. DO NOT edit it for a new exam.
# This file contains the scenario, packet fields, and menu. EDIT THIS q1.py.
#
# CHANGE BY EXAM REQUIREMENT (change both encryption and decryption!):
#   HASH: q1.py prepare_packet() AND accept_record(), e.g. sha256/sha512.
#   AES KEY SIZE: 128=16 bytes, 192=24 bytes, 256=32 bytes.
#   AES MODE: ECB / CBC / CTR / GCM. Only CBC uses the question's user IV.
#   AES -> DES / 3DES: change BOTH cipher operations and key lengths.
#   SIGNATURE: change prepare_packet() sign AND accept_record() verify;
#              match public/private key generation in setup().
#   RSA KEY SIZE: change setup() or RSA_BITS, NOT crypto_helpers.py.
#   FIELDS: change read_records(), prepare_packet(), accept_record(), main().
#   NUMERIC TALLY: change prepare_packet() Paillier field AND tally().
#   SEARCH: change index insertion in accept_record() AND search().
#   RBAC: change main() permission checks (or login/menu in Q4).
#
# IMPORTANT: The alternatives below are STUDY COMMENTS, not drop-in edits.
# User-supplied IV questions require a special AES-CBC path; helper encrypt_data
# normally creates its own IV. Never change only the cipher name in one place.
# ============================================================================
# AES / DES / 3DES EXAM REFERENCE (for q1/q2/q3; Q4 is Rabin, not AES):
# from crypto_helpers import key_for, encrypt_data, decrypt_data
# key = key_for("AES", 128)  # AES-128 (16 bytes)
# key = key_for("AES", 192)  # AES-192 (24 bytes)
# key = key_for("AES", 256)  # AES-256 (32 bytes)
# packet = encrypt_data(data, key, "AES", "ECB")
# packet = encrypt_data(data, key, "AES", "CBC")
# packet = encrypt_data(data, key, "AES", "CTR")
# packet = encrypt_data(data, key, "AES", "GCM")
# data = decrypt_data(packet, key, "AES")  # mode read from packet
# key = key_for("DES")
# packet = encrypt_data(data, key, "DES", "CBC")
# data = decrypt_data(packet, key, "DES")
# key = key_for("3DES")
# packet = encrypt_data(data, key, "3DES", "CBC")
# data = decrypt_data(packet, key, "3DES")
# NOTE: ECB is insecure; shown only because it appears in lab exercises.
# NOTE: The q2 manual RSA/ElGamal/Paillier are EDUCATIONAL, not secure production.
# ============================================================================

"""
QUESTION 1 — NATIONAL E-VOTING (RSA SIGNATURE VERSION)
SOURCE REQUIREMENTS: Menu-driven voting; AES-256-CBC with user-supplied 32-byte key;
RSA public-key encryption of AES key; SHA-512; RSA-PSS/SHA-512 signature;
Paillier encrypted candidate-wise vote tally; timestamp/deadline; RBAC;
HMAC searchable index by constituency and date; display verification results.

==================== EXACT EXAM CHANGE MAP ====================
file.txt: replace the example rows if reading from a file (optional here).
q1.py SETTINGS: change CANDIDATES, DEADLINE_HOURS, AES_BITS, AES_MODE.
q1.py setup(): change RSA_BITS, signature key size, Paillier setup.
q1.py prepare_packet(): change ballot fields, hash, encryption and signing.
q1.py accept_record(): match decrypt, hash, signature and timestamp checks.
q1.py tally(): change candidate-wise indicators or numeric amounts.
q1.py search(): change searchable fields and search prompts.
q1.py main(): change menu options.
crypto_helpers.py: DO NOT CHANGE; it supplies reusable algorithms.
NO TCP sockets: client and server are simulated as separate functions here.
===============================================================
"""
import json
from datetime import datetime, timezone, timedelta
from getpass import getpass
from Crypto.Random import get_random_bytes
from crypto_helpers import (to_bytes, hash_bytes, key_for, encrypt_data, decrypt_data,
    rsa_make_keys, rsa_encrypt, rsa_decrypt, rsa_sign_bytes, rsa_verify_bytes,
    paillier_make_keys, paillier_encrypt, paillier_add, paillier_decrypt,
    one_hot_vote, add_to_index, search_index, issue_timestamp, check_timestamp)

# ============= CHANGE SETTINGS HERE =============
CANDIDATES = {1: 'Candidate A', 2: 'Candidate B', 3: 'Candidate C'}
RSA_BITS = 2048  # CHANGE to 4096 if the question requires RSA-4096
AES_BITS = 256
AES_MODE = 'CBC'
HASH_NAME = 'sha512'
DEADLINE_HOURS = 24

records = []              # accepted encrypted ballot packets
index = {}                # HMAC searchable index
seen_ids = set()          # reject duplicate IDs in this classroom demo


# --- EDIT q1.py :: read_records() :: INPUT FIELDS ---

# =====================================================================
# BEGINNER WALKTHROUGH: read_records() — FILE: q1.py
# INPUT: Ask for one record and return a dictionary. Dictionary keys are field names; values are user inputs.
# CHANGE: For a new question, edit the input prompts and dictionary fields HERE. If the question says read file.txt, replace input() with file reading here.
# =====================================================================
def read_records():
    """CLIENT INPUT: change dictionary fields HERE for any new scenario."""
    # WHY: Return the result to the function that called us.
    return {'id': input('Voter ID: ').strip(),
            'constituency': input('Constituency: ').strip(),
            'candidate': int(input('Candidate (1/2/3): ')),
            'date': datetime.now(timezone.utc).date().isoformat()}


# --- EDIT q1.py :: setup() :: KEY SETUP ---

# =====================================================================
# BEGINNER WALKTHROUGH: setup() — FILE: q1.py
# KEYS: Set up the keys and configuration before any record is sent.
# CHANGE: For different RSA sizes, signature algorithms, Paillier parameters or deadlines, edit this function.
# =====================================================================
def setup():
    """SERVER SETUP: change key sizes and voting deadline here."""
    public, private = rsa_make_keys(RSA_BITS)
    signer_public, signer_private = rsa_make_keys(2048)
    pai_public, pai_private = paillier_make_keys()
    # WHY: Return the result to the function that called us.
    return dict(public=public, private=private, signer_public=signer_public,
                signer_private=signer_private, pai_public=pai_public,
                pai_private=pai_private, search_secret=get_random_bytes(32),
                timestamp_secret=get_random_bytes(32),
                deadline=datetime.now(timezone.utc) + timedelta(hours=DEADLINE_HOURS))



# =====================================================================
# BEGINNER WALKTHROUGH: get_aes_key() — FILE: q1.py
# KEY: AES-128 needs 16 bytes; AES-192 needs 24; AES-256 needs 32. Hex input uses twice as many characters.
# =====================================================================
def get_aes_key():
    """CLIENT INPUT: exactly 32 UTF-8 bytes or 64 hexadecimal characters."""
    # WHY: Repeat until the user exits or valid input is obtained.
    while True:
        value = getpass('Enter AES-256 key (32 bytes or 64 hex characters): ')
        # WHY: Try the operation; catch invalid inputs below instead of crashing.
        try:
            key = bytes.fromhex(value) if len(value) == 64 else value.encode()
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if len(key) == 32:
                # WHY: Return the result to the function that called us.
                return key
        except ValueError:
            pass
        # WHY: Show the result or status on screen.
        print('Invalid AES-256 key. Try again.')


# --- EDIT q1.py :: prepare_packet() :: SENDER / ENCRYPT ---

# =====================================================================
# BEGINNER WALKTHROUGH: prepare_packet() — FILE: q1.py
# SENDER: This is the CLIENT / SENDER half. It prepares a protected packet from the original record.
# ORDER: Convert record to bytes -> hash -> encrypt -> protect key -> sign / encrypt numbers -> return packet.
# CHANGE: Change algorithm, input field names and encrypted numeric values HERE. Make matching changes in accept_record().
# =====================================================================
def prepare_packet(record, keys):
    """CLIENT: hash -> AES -> RSA wrap -> Paillier one-hot -> RSA-PSS sign."""
    # WHY: Convert the dictionary or message into bytes because cryptographic algorithms operate on bytes.
    data = to_bytes(record)
    key = get_aes_key()
    # WHY: Encrypt the plaintext using the selected symmetric cipher and key.
    encrypted = encrypt_data(data, key, 'AES', AES_MODE)
    # WHY: Create a one-hot vote vector: candidate 2 of 3 becomes [0, 1, 0].
    vector = one_hot_vote(record['candidate'], len(CANDIDATES))
    # WHY: Build or obtain a dictionary that groups the relevant fields together.
    packet = {
        'id': record['id'], 'constituency': record['constituency'],
        'date': record['date'], 'hash': hash_bytes(data, HASH_NAME),
        'encrypted': encrypted, 'wrapped_key': rsa_encrypt(key, keys['public']),
        'votes': [paillier_encrypt(x, keys['pai_public']) for x in vector],
        'ticket': issue_timestamp(keys['timestamp_secret'])
    }
    # Sign the ENTIRE submitted packet, including encrypted vote values.
    # WHY: Convert the dictionary or message into bytes because cryptographic algorithms operate on bytes.
    packet['signature'] = rsa_sign_bytes(to_bytes(packet), keys['signer_private'])
    # WHY: Return the result to the function that called us.
    return packet


# --- EDIT q1.py :: accept_record() :: RECEIVER / DECRYPT ---

# =====================================================================
# BEGINNER WALKTHROUGH: accept_record() — FILE: q1.py
# RECEIVER: This is the SERVER / RECEIVER half, simulated inside the same Python program.
# ORDER: Recover key -> decrypt -> recalculate hash -> verify signature -> check metadata/time -> accept.
# CHANGE: Whenever prepare_packet() changes its cipher, signature, hash or packet keys, update this function too.
# =====================================================================
def accept_record(packet, keys):
    """SERVER: verify signature -> time -> unwrap AES -> decrypt -> hash -> store."""
    # WHY: Work with the signature: sender creates it, receiver checks it.
    signature = packet['signature']
    # WHY: Work with the signature: sender creates it, receiver checks it.
    unsigned = {k: v for k, v in packet.items() if k != 'signature'}
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not rsa_verify_bytes(to_bytes(unsigned), signature, keys['signer_public']):
        # WHY: Work with the signature: sender creates it, receiver checks it.
        raise ValueError('INVALID RSA signature / tampering detected')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not check_timestamp(packet['ticket'], keys['timestamp_secret'], keys['deadline']):
        # WHY: Reject invalid input by raising a clear error.
        raise ValueError('Invalid or late timestamp')
    # WHY: Recover the AES session key using the receiver RSA PRIVATE key.
    key = rsa_decrypt(packet['wrapped_key'], keys['private'])
    # WHY: Decrypt using the matching key, cipher and IV/nonce.
    data = decrypt_data(packet['encrypted'], key, 'AES')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if hash_bytes(data, HASH_NAME) != packet['hash']:
        # WHY: Reject invalid input by raising a clear error.
        raise ValueError('SHA-512 integrity check failed')
    # WHY: Convert decrypted JSON bytes back into a Python dictionary.
    record = json.loads(data)
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if record['id'] != packet['id'] or record['constituency'] != packet['constituency']:
        # WHY: Reject invalid input by raising a clear error.
        raise ValueError('Metadata mismatch')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if record['id'] in seen_ids:
        # WHY: Reject invalid input by raising a clear error.
        raise ValueError('Duplicate voter ID')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if record['candidate'] not in CANDIDATES or len(packet['votes']) != len(CANDIDATES):
        # WHY: Reject invalid input by raising a clear error.
        raise ValueError('Invalid candidate/vector length')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if record['date'] != packet['date']:
        # WHY: Reject invalid input by raising a clear error.
        raise ValueError('Date mismatch')
    # NOTE: This classroom demo cannot cryptographically prove that the
    # Paillier vector matches the AES-encrypted candidate without a ZK proof.
    # WHY: Store the accepted record in the in-memory list.
    records.append(packet)
    seen_ids.add(record['id'])
    # WHY: Convert a search term into an HMAC token for the searchable index.
    add_to_index(index, record['id'],
                 [f"place:{record['constituency']}", f"date:{record['date']}"],
                 keys['search_secret'])
    # WHY: Return the result to the function that called us.
    return record


# --- EDIT q1.py :: tally() :: PAILLIER TALLY ---

# =====================================================================
# BEGINNER WALKTHROUGH: tally() — FILE: q1.py
# PAILLIER: Add ciphertexts while they remain encrypted. Decrypt only the final aggregate.
# CHANGE: For money, aggregate encrypted amount. For votes, use one encrypted 0/1 per candidate and tally each column.
# =====================================================================
def tally(keys):
    """SERVER: add Paillier ciphertexts by candidate; decrypt ONLY totals."""
    # WHY: Repeat this operation for each item in the collection.
    for column, name in CANDIDATES.items():
        # WHY: Work with encrypted data; do not treat ciphertext as plaintext.
        encrypted_values = [p['votes'][column - 1] for p in records]
        # WHY: Combine encrypted Paillier values WITHOUT decrypting each record.
        total = paillier_decrypt(paillier_add(encrypted_values, keys['pai_public']),
                                 keys['pai_public'], keys['pai_private'])
        # WHY: Show the result or status on screen.
        print(name, ':', total, 'votes')


# --- EDIT q1.py :: search() :: SEARCH ---

# =====================================================================
# BEGINNER WALKTHROUGH: search() — FILE: q1.py
# SEARCH: Use the question-specific searchable fields and display matching IDs, not sensitive plaintext.
# CHANGE: If the exam changes constituency to branch / department / date, update indexing and this search prompt together.
# =====================================================================
def search(keys):
    """SERVER: keyword search by constituency or date, without vote choice."""
    # WHY: Ask the user to enter the value required by this question.
    field = input('Search field (place/date): ').strip().lower()
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if field not in ('place', 'date'):
        # WHY: Show the result or status on screen.
        # WHY: Show the result or status on screen.
        print('Choose place or date'); return
    # WHY: Ask the user to enter the value required by this question.
    value = input('Search value: ').strip().lower()
    # WHY: Show the result or status on screen.
    print('Matching voter IDs:', search_index(index, f'{field}:{value}', keys['search_secret']))


# --- EDIT q1.py :: main() :: MENU ---

# =====================================================================
# BEGINNER WALKTHROUGH: main() — FILE: q1.py
# MENU: The while loop keeps showing choices until the user exits.
# FLOW: A menu choice calls one of the functions above. There is NO separate socket server here.
# CHANGE: Rename choices and add/remove operations HERE, not in crypto_helpers.py.
# =====================================================================
def main():
    keys = setup()
    # WHY: Repeat until the user exits or valid input is obtained.
    while True:
        # WHY: Show the result or status on screen.
        print('\n1. Cast vote  2. Verify accepted ballots  3. Tally  4. Search  5. Tamper test  0. Exit')
        # WHY: Ask the user to enter the value required by this question.
        choice = input('Choice: ').strip()
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice == '0': break
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice == '1':
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if input('Role (voter/admin/auditor): ').strip().lower() != 'voter':
                # WHY: Show the result or status on screen.
                print('ACCESS DENIED'); continue
            # WHY: Try the operation; catch invalid inputs below instead of crashing.
            try:
                # WHY: Build or obtain a dictionary that groups the relevant fields together.
                record = read_records()
                # WHY: Check this condition before continuing; invalid data must not be accepted.
                if not record['id'] or not record['constituency']:
                    # WHY: Reject invalid input by raising a clear error.
                    raise ValueError('ID and constituency are required')
                # WHY: Build or obtain a dictionary that groups the relevant fields together.
                packet = prepare_packet(record, keys)
                # WHY: Show the result or status on screen.
                print('SHA-512:', packet['hash'])
                # WHY: Show the result or status on screen.
                print('AES ciphertext:', packet['encrypted'])
                # WHY: Show the result or status on screen.
                print('RSA-encrypted AES key:', packet['wrapped_key'])
                # WHY: Show the result or status on screen.
                print('RSA signature:', packet['signature'])
                # WHY: Show the result or status on screen.
                print('Verified and accepted:', accept_record(packet, keys))
            except (ValueError, KeyError, TypeError) as exc:
                # WHY: Show the result or status on screen.
                print('Rejected:', exc)
        # WHY: Handle this alternative menu choice.
        elif choice in ('2', '3', '4', '5'):
            # WHY: Ask the user to enter the value required by this question.
            role = input('Role (admin/auditor/voter): ').strip().lower()
            permissions = {'admin': {'2', '3', '4', '5'}, 'auditor': {'2', '4'}, 'voter': set()}
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if choice not in permissions.get(role, set()):
                # WHY: Show the result or status on screen.
                print('ACCESS DENIED'); continue
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if choice == '2':
                # WHY: Repeat this operation for each item in the collection.
                for p in records:
                    # WHY: Work with the signature: sender creates it, receiver checks it.
                    signed = {k: v for k, v in p.items() if k != 'signature'}
                    # WHY: Show the result or status on screen.
                    print(p['id'], 'SIGNATURE VALID:',
                          rsa_verify_bytes(to_bytes(signed), p['signature'], keys['signer_public']))
            # WHY: Handle this alternative menu choice.
            # WHY: Handle this alternative menu choice.
            elif choice == '3': tally(keys)
            # WHY: Handle this alternative menu choice.
            # WHY: Handle this alternative menu choice.
            elif choice == '4': search(keys)
            # WHY: Handle this alternative menu choice.
            elif choice == '5':
                # WHY: Check this condition before continuing; invalid data must not be accepted.
                if not records:
                    # WHY: Show the result or status on screen.
                    print('Cast a vote first'); continue
                bad = dict(records[0]); bad['hash'] = '0' * 128
                # WHY: Work with the signature: sender creates it, receiver checks it.
                signed = {k: v for k, v in bad.items() if k != 'signature'}
                # WHY: Show the result or status on screen.
                print('Tampered packet accepted?',
                      rsa_verify_bytes(to_bytes(signed), bad['signature'], keys['signer_public']))
        else: print('Invalid choice')


if __name__ == '__main__':
    main()
