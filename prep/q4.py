# ============================================================================
# Q4 — RABIN LEGAL CONTRACT KMS
# ============================================================================
# EXACT ALGORITHMS USED:
# Rabin c=m² mod n | CRT four-root decryption | role access | key revoke/renew | RSA comparison
# KEY INPUTS: Rabin primes p and q: user input, p%4=q%4=3
#
# SHARED GENERIC NAMES: setup, read_records, prepare_packet, accept_record, submit, search, main
# crypto_helpers.py contains reusable algorithms. DO NOT edit it for a new exam.
# This file contains the scenario, packet fields, and menu. EDIT THIS q4.py.
#
# CHANGE BY EXAM REQUIREMENT (change both encryption and decryption!):
#   HASH: q4.py prepare_packet() AND accept_record(), e.g. sha256/sha512.
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
QUESTION 4 — LEGAL CONTRACTS: RABIN CRYPTOSYSTEM + KEY MANAGEMENT
SOURCE REQUIREMENTS: User enters DISTINCT primes p and q, BOTH = 3 mod 4;
compute n=pq; encrypt numerical message; decrypt via four CRT roots;
select correct root using explicit encoding/validation; roles Lawyer, Client,
Administrator; restrict document access; revoke and renew keys; compare
Rabin and RSA; store encrypted contracts and key metadata.

===================== EXACT EXAM CHANGE MAP =====================
q4.py SETTINGS: change DATA_FILE, KEY_FILE, user roles/passwords.
q4.py generate_keys(): change prime rules or key input.
q4.py encrypt_text()/decrypt_text(): change Rabin encoding/validation.
q4.py create_contract(): change document fields and allowed creators.
q4.py view_contract(): change access-control rule.
q4.py revoke_key()/renew_key(): change lifecycle policy.
q4.py compare_rabin_rsa(): change comparison output.
q4.py main(): change menu choices.
crypto_helpers.py: DO NOT CHANGE; Rabin root helper reused here.
NO SOCKETS: this is a local menu-driven application.
=================================================================
SECURITY NOTE: small Rabin parameters, fixed byte encoding and passwords
in source are ONLY classroom examples. Never store p/q alongside encrypted
contracts in a real system; keys are separate in this demonstration.
"""
import json
import math
from pathlib import Path
from getpass import getpass
from crypto_helpers import rabin_encrypt_number, rabin_decrypt_roots

DATA_FILE = 'contracts.txt'      # CHANGE FILE NAME HERE
KEY_FILE = 'rabin_keys.txt'      # CHANGE FILE NAME HERE
USERS = {
    'admin': {'password': 'admin123', 'role': 'Administrator'},
    'lawyer': {'password': 'lawyer123', 'role': 'Lawyer'},
    'client': {'password': 'client123', 'role': 'Client'},
}


def load_json(filename, default):
    path = Path(filename)
    # WHY: Return the result to the function that called us.
    return json.loads(path.read_text()) if path.exists() else default


def save_json(filename, value):
    # WHY: Save the result in a file so it persists after the program exits.
    Path(filename).write_text(json.dumps(value, indent=2))


def is_prime(n):
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if n < 2: return False
    # WHY: Return the result to the function that called us.
    return all(n % i for i in range(2, math.isqrt(n) + 1))



# =====================================================================
# BEGINNER WALKTHROUGH: generate_keys() — FILE: q4.py
# RABIN SETUP: Ask for p and q, check both are distinct primes congruent to 3 modulo 4, then calculate n = p*q.
# =====================================================================
def generate_keys():
    """SETUP: user inputs Blum primes p/q; n must support encoded byte blocks."""
    # WHY: Repeat until the user exits or valid input is obtained.
    while True:
        # WHY: Try the operation; catch invalid inputs below instead of crashing.
        try:
            # WHY: Ask the user to enter the value required by this question.
            p = int(input('Rabin prime p (3 mod 4): '))
            # WHY: Ask the user to enter the value required by this question.
            q = int(input('Rabin prime q (3 mod 4): '))
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if p == q or not is_prime(p) or not is_prime(q) or p % 4 != 3 or q % 4 != 3:
                # WHY: Reject invalid input by raising a clear error.
                raise ValueError('Need distinct primes p,q = 3 mod 4')
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if p*q <= 511: raise ValueError('Need n > 511 for byte encoding')
            # WHY: Return the result to the function that called us.
            return {'p': p, 'q': q, 'n': p*q, 'revoked': False}
        except ValueError as exc:
            # WHY: Show the result or status on screen.
            print('Invalid keys:', exc)



# =====================================================================
# BEGINNER WALKTHROUGH: encrypt_text() — FILE: q4.py
# RABIN ENCRYPT: Convert each text byte into an encoded number and encrypt it with m² mod n.
# =====================================================================
def encrypt_text(text, n):
    """CLIENT: encode each byte as 256+byte, then Rabin c=m² mod n."""
    result = []
    # WHY: Repeat this operation for each item in the collection.
    for byte in text.encode('utf-8'):
        m = 256 + byte
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if m >= n: raise ValueError('Rabin modulus too small')
        result.append(rabin_encrypt_number(m, n))
    # WHY: Return the result to the function that called us.
    return result



# =====================================================================
# BEGINNER WALKTHROUGH: decrypt_text() — FILE: q4.py
# RABIN DECRYPT: Compute possible square roots using CRT, then use the encoding rule to identify the correct plaintext byte.
# =====================================================================
def decrypt_text(ciphertexts, p, q):
    """SERVER: find four roots; select unique encoded root in [256,511]."""
    result = bytearray()
    # WHY: Repeat this operation for each item in the collection.
    for cipher in ciphertexts:
        roots = rabin_decrypt_roots(cipher, p, q)
        valid = [r for r in roots if 256 <= r <= 511]
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if len(valid) != 1:
            # WHY: Reject invalid input by raising a clear error.
            raise ValueError(f'Ambiguous Rabin roots {roots}; choose different encoding/primes')
        result.append(valid[0] - 256)
    # WHY: Return the result to the function that called us.
    return result.decode('utf-8')


def login():
    # WHY: Ask the user to enter the value required by this question.
    username = input('Username: ').strip().lower()
    password = getpass('Password: ')
    user = USERS.get(username)
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not user or user['password'] != password:
        # WHY: Show the result or status on screen.
        # WHY: Show the result or status on screen.
        print('Invalid credentials'); return None, None
    # WHY: Return the result to the function that called us.
    return username, user['role']


def current_keys():
    keys = load_json(KEY_FILE, None)
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if keys is None or keys['revoked']:
        # WHY: Show the result or status on screen.
        # WHY: Show the result or status on screen.
        print('No active keys: administrator must initialize/renew'); return None
    # WHY: Return the result to the function that called us.
    return keys



# =====================================================================
# BEGINNER WALKTHROUGH: create_contract() — FILE: q4.py
# CONTRACT CREATE: Check permission, collect details, encrypt text, save an encrypted record.
# =====================================================================
def create_contract(username, role):
    """Only Lawyer/Admin can create a contract for a registered Client."""
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if role not in ('Lawyer', 'Administrator'):
        # WHY: Show the result or status on screen.
        # WHY: Show the result or status on screen.
        print('ACCESS DENIED'); return
    keys = current_keys()
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not keys: return
    # WHY: Ask the user to enter the value required by this question.
    title = input('Contract title: ').strip()
    # WHY: Ask the user to enter the value required by this question.
    owner = input('Client owner username: ').strip().lower()
    # WHY: Ask the user to enter the value required by this question.
    text = input('Contract text: ')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if owner not in USERS or USERS[owner]['role'] != 'Client':
        # WHY: Show the result or status on screen.
        # WHY: Show the result or status on screen.
        print('Owner must be a registered Client'); return
    # WHY: Try the operation; catch invalid inputs below instead of crashing.
    try:
        # WHY: Work with encrypted data; do not treat ciphertext as plaintext.
        ciphertext = encrypt_text(text, keys['n'])
        contracts = load_json(DATA_FILE, {})
        cid = str(max([int(k) for k in contracts] or [0]) + 1)
        contracts[cid] = {'title': title, 'owner': owner,
                          'lawyer': username if role == 'Lawyer' else '',
                          'ciphertext': ciphertext, 'key_n': keys['n']}
        save_json(DATA_FILE, contracts)
        # WHY: Show the result or status on screen.
        print('Encrypted contract saved, ID:', cid, 'Ciphertext:', ciphertext)
    except (ValueError, UnicodeError) as exc:
        # WHY: Show the result or status on screen.
        print('Encryption error:', exc)



# =====================================================================
# BEGINNER WALKTHROUGH: view_contract() — FILE: q4.py
# CONTRACT VIEW: Find the contract, check user permission, decrypt only if the key is valid.
# =====================================================================
def view_contract(username, role):
    """Check RBAC and document ownership BEFORE decrypting."""
    contracts = load_json(DATA_FILE, {})
    # WHY: Repeat this operation for each item in the collection.
    # WHY: Repeat this operation for each item in the collection.
    for cid, record in contracts.items(): print(cid, record['title'])
    # WHY: Ask the user to enter the value required by this question.
    cid = input('Contract ID: ').strip()
    doc = contracts.get(cid)
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not doc:
        # WHY: Show the result or status on screen.
        # WHY: Show the result or status on screen.
        print('Not found'); return
    permitted = (role == 'Administrator' or
                 (role == 'Client' and doc['owner'] == username) or
                 (role == 'Lawyer' and doc['lawyer'] == username))
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not permitted:
        # WHY: Show the result or status on screen.
        # WHY: Show the result or status on screen.
        print('ACCESS DENIED'); return
    keys = current_keys()
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not keys or keys['n'] != doc['key_n']:
        # WHY: Show the result or status on screen.
        # WHY: Show the result or status on screen.
        print('Current key unavailable for this contract'); return
    # WHY: Try the operation; catch invalid inputs below instead of crashing.
    try:
        # WHY: Show the result or status on screen.
        print('Ciphertext:', doc['ciphertext'])
        # WHY: Show the result or status on screen.
        print('Decrypted contract:', decrypt_text(doc['ciphertext'], keys['p'], keys['q']))
    except (ValueError, UnicodeError) as exc:
        # WHY: Show the result or status on screen.
        print('Decryption failed:', exc)



# =====================================================================
# BEGINNER WALKTHROUGH: revoke_key() — FILE: q4.py
# KEY REVOKE: Mark current key revoked so it cannot be used for new decryption operations.
# =====================================================================
def revoke_key():
    keys = load_json(KEY_FILE, None)
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not keys:
        # WHY: Show the result or status on screen.
        # WHY: Show the result or status on screen.
        print('No keys to revoke'); return
    # WHY: Retrieve a named key or setting from the keys dictionary returned by setup().
    keys['revoked'] = True
    save_json(KEY_FILE, keys)
    # WHY: Show the result or status on screen.
    print('Key revoked; decryption blocked until renewal')



# =====================================================================
# BEGINNER WALKTHROUGH: renew_key() — FILE: q4.py
# KEY RENEW: Decrypt existing documents with old keys, create replacement keys, re-encrypt, and save.
# =====================================================================
def renew_key():
    """Re-encrypt existing contracts using old keys BEFORE replacing them."""
    old = load_json(KEY_FILE, None)
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not old:
        # WHY: Show the result or status on screen.
        # WHY: Show the result or status on screen.
        print('Initialize keys first'); return
    contracts = load_json(DATA_FILE, {})
    plaintexts = {}
    # WHY: Try the operation; catch invalid inputs below instead of crashing.
    try:
        # WHY: Repeat this operation for each item in the collection.
        for cid, doc in contracts.items():
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if doc['key_n'] != old['n']: raise ValueError('Key mismatch')
            # WHY: Work with encrypted data; do not treat ciphertext as plaintext.
            plaintexts[cid] = decrypt_text(doc['ciphertext'], old['p'], old['q'])
        new = generate_keys()
        # WHY: Repeat this operation for each item in the collection.
        for cid, doc in contracts.items():
            # WHY: Work with encrypted data; do not treat ciphertext as plaintext.
            doc['ciphertext'] = encrypt_text(plaintexts[cid], new['n'])
            doc['key_n'] = new['n']
        save_json(DATA_FILE, contracts)
        save_json(KEY_FILE, new)
        # WHY: Show the result or status on screen.
        print('Keys renewed and contracts re-encrypted')
    except (ValueError, UnicodeError) as exc:
        # WHY: Show the result or status on screen.
        print('Renewal failed; old keys retained if save not reached:', exc)


def compare_rabin_rsa():
    """Short conceptual comparison required by the question."""
    # WHY: Show the result or status on screen.
    print('RABIN: c = m² mod n; decryption yields up to FOUR roots via CRT.')
    # WHY: Show the result or status on screen.
    print('RSA: c = m^e mod n; with correct key, one plaintext integer is recovered.')
    # WHY: Show the result or status on screen.
    print('RABIN: explicit redundancy/encoding is needed to select a root.')
    # WHY: Show the result or status on screen.
    print('RSA: use OAEP padding for secure encryption, not textbook RSA.')


# GENERIC NAMES — Q4 equivalent of the same exam template structure.
# The Rabin question uses contract files, not a signed AES packet.
# Therefore prepare_packet() performs Rabin encryption and accept_record()
# performs authorized Rabin decryption through the existing functions.

# --- EDIT q4.py :: setup() :: KEY SETUP ---

# =====================================================================
# BEGINNER WALKTHROUGH: setup() — FILE: q4.py
# KEYS: Set up the keys and configuration before any record is sent.
# CHANGE: For different RSA sizes, signature algorithms, Paillier parameters or deadlines, edit this function.
# =====================================================================
def setup():
    """Q4 SETUP: initial keys are generated from admin_menu() when requested."""
    # WHY: Return the result to the function that called us.
    return current_keys()


# --- EDIT q4.py :: read_records() :: INPUT FIELDS ---

# =====================================================================
# BEGINNER WALKTHROUGH: read_records() — FILE: q4.py
# INPUT: Ask for one record and return a dictionary. Dictionary keys are field names; values are user inputs.
# CHANGE: For a new question, edit the input prompts and dictionary fields HERE. If the question says read file.txt, replace input() with file reading here.
# =====================================================================
def read_records():
    """Q4 INPUT: contract details are read in create_contract() for role checks."""
    # WHY: Return the result to the function that called us.
    return load_json(DATA_FILE, {})


# --- EDIT q4.py :: prepare_packet() :: SENDER / ENCRYPT ---

# =====================================================================
# BEGINNER WALKTHROUGH: prepare_packet() — FILE: q4.py
# SENDER: This is the CLIENT / SENDER half. It prepares a protected packet from the original record.
# ORDER: Convert record to bytes -> hash -> encrypt -> protect key -> sign / encrypt numbers -> return packet.
# CHANGE: Change algorithm, input field names and encrypted numeric values HERE. Make matching changes in accept_record().
# =====================================================================
def prepare_packet(username, role):
    """Q4 SENDER: Rabin-encrypt and store a contract; delegates to create_contract."""
    # WHY: Return the result to the function that called us.
    return create_contract(username, role)


# --- EDIT q4.py :: accept_record() :: RECEIVER / DECRYPT ---

# =====================================================================
# BEGINNER WALKTHROUGH: accept_record() — FILE: q4.py
# RECEIVER: This is the SERVER / RECEIVER half, simulated inside the same Python program.
# ORDER: Recover key -> decrypt -> recalculate hash -> verify signature -> check metadata/time -> accept.
# CHANGE: Whenever prepare_packet() changes its cipher, signature, hash or packet keys, update this function too.
# =====================================================================
def accept_record(username, role):
    """Q4 RECEIVER: RBAC-check, CRT-decrypt, and display; delegates to view_contract."""
    # WHY: Return the result to the function that called us.
    return view_contract(username, role)


def submit(username, role):
    """Generic submit alias: Q4 contract creation."""
    # WHY: Return the result to the function that called us.
    return prepare_packet(username, role)


# --- EDIT q4.py :: search() :: SEARCH ---

# =====================================================================
# BEGINNER WALKTHROUGH: search() — FILE: q4.py
# SEARCH: Use the question-specific searchable fields and display matching IDs, not sensitive plaintext.
# CHANGE: If the exam changes constituency to branch / department / date, update indexing and this search prompt together.
# =====================================================================
def search():
    """Q4 LIST: display saved contract IDs/titles; authorization remains in accept_record."""
    # WHY: Repeat this operation for each item in the collection.
    for cid, doc in read_records().items():
        # WHY: Show the result or status on screen.
        print(cid, doc.get('title', '(untitled)'))


def admin_menu():
    # WHY: Repeat until the user exits or valid input is obtained.
    while True:
        # WHY: Show the result or status on screen.
        print('\nADMIN: 1. Generate keys  2. Revoke  3. Renew  4. Compare Rabin/RSA  0. Logout')
        # WHY: Ask the user to enter the value required by this question.
        choice = input('Choice: ')
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice == '0': break
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice == '1':
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if Path(KEY_FILE).exists(): print('Use renew instead')
            else: save_json(KEY_FILE, generate_keys())
        # WHY: Handle this alternative menu choice.
        # WHY: Handle this alternative menu choice.
        elif choice == '2': revoke_key()
        # WHY: Handle this alternative menu choice.
        # WHY: Handle this alternative menu choice.
        elif choice == '3': renew_key()
        # WHY: Handle this alternative menu choice.
        # WHY: Handle this alternative menu choice.
        elif choice == '4': compare_rabin_rsa()


def user_menu(username, role):
    # WHY: Repeat until the user exits or valid input is obtained.
    while True:
        # WHY: Show the result or status on screen.
        print('\n1. Create/encrypt contract  2. View/decrypt contract  0. Logout')
        # WHY: Ask the user to enter the value required by this question.
        choice = input('Choice: ')
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice == '0': break
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice == '1': submit(username, role)
        # WHY: Handle this alternative menu choice.
        # WHY: Handle this alternative menu choice.
        elif choice == '2': accept_record(username, role)


# --- EDIT q4.py :: main() :: MENU ---

# =====================================================================
# BEGINNER WALKTHROUGH: main() — FILE: q4.py
# MENU: The while loop keeps showing choices until the user exits.
# FLOW: A menu choice calls one of the functions above. There is NO separate socket server here.
# CHANGE: Rename choices and add/remove operations HERE, not in crypto_helpers.py.
# =====================================================================
def main():
    # WHY: Repeat until the user exits or valid input is obtained.
    while True:
        # WHY: Show the result or status on screen.
        print('\n=== RABIN LEGAL CONTRACTS ===\n1. Login  0. Exit')
        # WHY: Ask the user to enter the value required by this question.
        choice = input('Choice: ')
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice == '0': break
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice != '1': continue
        username, role = login()
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if not username: continue
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if role == 'Administrator': admin_menu()
        else: user_menu(username, role)


if __name__ == '__main__':
    main()
