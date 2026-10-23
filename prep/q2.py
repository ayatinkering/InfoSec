# ============================================================================
# Q2 — ELGAMAL-SIGNED E-VOTING
# ============================================================================
# EXACT ALGORITHMS USED:
# AES-256-CBC | user-input RSA parameters (textbook RSA) | SHA-512 | ElGamal signature | manual Paillier one-hot | HMAC search | RBAC
# KEY INPUTS: RSA/ElGamal/Paillier parameters, AES key and IV: user input
#
# SHARED GENERIC NAMES: setup, read_records, prepare_packet, accept_record, tally, search, main
# crypto_helpers.py contains reusable algorithms. DO NOT edit it for a new exam.
# This file contains the scenario, packet fields, and menu. EDIT THIS q2.py.
#
# CHANGE BY EXAM REQUIREMENT (change both encryption and decryption!):
#   HASH: q2.py prepare_packet() AND accept_record(), e.g. sha256/sha512.
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
QUESTION 2 — NATIONAL E-VOTING (USER-ENTERED PARAMETERS + ELGAMAL)
SOURCE REQUIREMENTS: Menu-driven; voter ID, constituency, candidate, timestamp;
SHA-512; AES-256-CBC using USER-ENTERED AES key and IV; RSA public/private
parameters USER-ENTERED; ElGamal signature on SHA-512; Paillier ciphertext
aggregation; voting-period validation; searchable index (place or time range);
RBAC; show encrypt/decrypt, hash/signature verification, tally and search.

===================== EXACT EXAM CHANGE MAP =====================
q2.py setup(): change requested user inputs (RSA p/q/e, Paillier p/q,
                ElGamal p/g/x, AES key/IV, deadline).
q2.py prepare_packet(): change metadata fields, SHA, AES, RSA wrap,
                        ElGamal sign, Paillier candidate vector.
q2.py accept_record(): reverse operations, verify signature/hash/time.
q2.py tally(): encrypted per-candidate sums; NOT sum of candidate IDs.
q2.py search(): change constituency/date or time-range search.
q2.py main(): change menu and RBAC permissions.
crypto_helpers.py: DO NOT CHANGE; this question uses its AES/hash/one-hot
functions, but textbook user-entered RSA/Paillier/ElGamal arithmetic is
written in this file because the master key generators generate keys.
NO SOCKETS: client and server operations are simulated as functions.
=================================================================

EXAM NOTE: textbook RSA wrapping a 32-byte AES key requires n > 2^256.
Small example primes cannot encrypt the full key as one integer. This code
checks that condition rather than silently corrupting the AES key.
Manual prime/nonce inputs and textbook RSA are EDUCATIONAL ONLY.
"""
import json
import math
import hashlib
import hmac
from datetime import datetime
from getpass import getpass
from Crypto.Util.number import isPrime
from crypto_helpers import (to_bytes, hash_bytes, encrypt_data, decrypt_data,
                            one_hot_vote, search_token)

CANDIDATES = {1: 'Candidate A', 2: 'Candidate B', 3: 'Candidate C'}
records = []
index = {}
seen = set()


def number(prompt):
    # WHY: Repeat until the user exits or valid input is obtained.
    while True:
        # WHY: Try the operation; catch invalid inputs below instead of crashing.
        # WHY: Try the operation; catch invalid inputs below instead of crashing.
        try: return int(input(prompt))
        # WHY: Handle an error and display a useful message.
        except ValueError: print('Enter an integer')


def is_prime(n):
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if n < 2: return False
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if n % 2 == 0: return n == 2
    # Educational primality test. Use a proven primality routine in production.
    # WHY: Return the result to the function that called us.
    return all(n % d for d in range(3, math.isqrt(n) + 1, 2))


def key_bytes(prompt, size):
    """User enters exact bytes as hex; do not derive a key from arbitrary text."""
    # WHY: Repeat until the user exits or valid input is obtained.
    while True:
        # WHY: Try the operation; catch invalid inputs below instead of crashing.
        try:
            data = bytes.fromhex(getpass(f'{prompt} ({size*2} hex chars): '))
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if len(data) == size: return data
        except ValueError: pass
        # WHY: Show the result or status on screen.
        print('Incorrect length / invalid hex')


# --- EDIT q2.py :: setup() :: KEY SETUP ---

# =====================================================================
# BEGINNER WALKTHROUGH: setup() — FILE: q2.py
# KEYS: Set up the keys and configuration before any record is sent.
# CHANGE: For different RSA sizes, signature algorithms, Paillier parameters or deadlines, edit this function.
# =====================================================================
def setup():
    """SERVER/CLIENT SETUP: all requested crypto inputs are USER-ENTERED."""
    # WHY: Show the result or status on screen.
    print('\n--- RSA USER PARAMETERS ---')
    p = number('RSA prime p: '); q = number('RSA prime q: '); e = number('RSA exponent e: ')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if p == q or not isPrime(p) or not isPrime(q): raise ValueError('RSA p/q must be distinct primes')
    n = p * q; phi = (p - 1) * (q - 1)
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not 1 < e < phi or math.gcd(e, phi) != 1: raise ValueError('Invalid RSA e')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if n <= (1 << 256):
        # WHY: Reject invalid input by raising a clear error.
        raise ValueError('RSA modulus too small for 32-byte AES key. Enter large primes (n > 2^256).')
    rsa = {'n': n, 'e': e, 'd': pow(e, -1, phi)}

    # WHY: Show the result or status on screen.
    print('\n--- PAILLIER USER PARAMETERS ---')
    p = number('Paillier prime p: '); q = number('Paillier prime q: ')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if p == q or not isPrime(p) or not isPrime(q): raise ValueError('Paillier p/q must be distinct primes')
    pn = p * q; lam = math.lcm(p - 1, q - 1)
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if math.gcd(lam, pn) != 1: raise ValueError('Choose different Paillier primes')
    pai = {'n': pn, 'g': pn + 1, 'lam': lam, 'mu': pow(lam, -1, pn)}

    # WHY: Show the result or status on screen.
    print('\n--- ELGAMAL USER PARAMETERS ---')
    p = number('ElGamal prime p: '); g = number('Generator g: '); x = number('Private key x: ')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not isPrime(p) or not 1 < g < p or not 1 <= x <= p - 2:
        # WHY: Reject invalid input by raising a clear error.
        raise ValueError('Invalid ElGamal parameters')
    elg = {'p': p, 'g': g, 'x': x, 'y': pow(g, x, p)}

    # WHY: Show the result or status on screen.
    print('\n--- AES-256-CBC USER PARAMETERS ---')
    aes_key = key_bytes('AES-256 key', 32)
    iv = key_bytes('CBC IV', 16)
    # WHY: Ask the user to enter the value required by this question.
    start = datetime.fromisoformat(input('Voting start (YYYY-MM-DD HH:MM:SS): '))
    # WHY: Ask the user to enter the value required by this question.
    end = datetime.fromisoformat(input('Voting end   (YYYY-MM-DD HH:MM:SS): '))
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if start >= end: raise ValueError('Start must precede end')
    # WHY: Show the result or status on screen.
    print('WARNING: Never reuse a CBC IV with the same key in real systems.')
    # WHY: Return the result to the function that called us.
    return {'rsa': rsa, 'pai': pai, 'elg': elg, 'aes': aes_key, 'iv': iv,
            'start': start, 'end': end, 'index_key': hashlib.sha256(aes_key + b'index').digest()}



# =====================================================================
# BEGINNER WALKTHROUGH: sign_hash() — FILE: q2.py
# ELGAMAL SIGN: Use the private key and a nonce k to sign the SHA-512 hash. Never reuse k in real cryptography.
# =====================================================================
def sign_hash(digest, elg):
    """ElGamal signature of SHA-512 integer; user enters signing nonce k."""
    p = elg['p']; h = int(digest, 16) % (p - 1)
    k = number('Enter ElGamal nonce k (coprime to p-1): ')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not 1 <= k < p-1 or math.gcd(k, p-1) != 1:
        # WHY: Reject invalid input by raising a clear error.
        raise ValueError('Invalid ElGamal nonce k')
    r = pow(elg['g'], k, p)
    s = ((h - elg['x'] * r) * pow(k, -1, p-1)) % (p-1)
    # WHY: Return the result to the function that called us.
    return [r, s]



# =====================================================================
# BEGINNER WALKTHROUGH: verify_signature() — FILE: q2.py
# ELGAMAL VERIFY: Check the signature with the public key. If false, reject the record.
# =====================================================================
def verify_signature(digest, sig, elg):
    p = elg['p']; r, s = sig
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not (1 <= r < p and 0 <= s < p-1): return False
    h = int(digest, 16) % (p-1)
    # WHY: Return the result to the function that called us.
    return pow(elg['g'], h, p) == pow(elg['y'], r, p) * pow(r, s, p) % p



# =====================================================================
# BEGINNER WALKTHROUGH: paillier_encrypt_manual() — FILE: q2.py
# PAILLIER ENCRYPT: Encrypt one integer with user-entered randomness r, as required by Q2.
# =====================================================================
def paillier_encrypt_manual(m, pai):
    """Paillier with user-entered randomness r."""
    n = pai['n']
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not 0 <= m < n: raise ValueError('Paillier message must be < n')
    r = number('Paillier random r (coprime to n): ')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not 1 <= r < n or math.gcd(r, n) != 1: raise ValueError('Invalid Paillier r')
    # WHY: Return the result to the function that called us.
    return (pow(pai['g'], m, n*n) * pow(r, n, n*n)) % (n*n)



# =====================================================================
# BEGINNER WALKTHROUGH: paillier_decrypt_manual() — FILE: q2.py
# PAILLIER DECRYPT: Decrypt the FINAL aggregate using the Paillier private parameters.
# =====================================================================
def paillier_decrypt_manual(c, pai):
    n = pai['n']; u = pow(c, pai['lam'], n*n)
    # WHY: Return the result to the function that called us.
    return ((u-1)//n * pai['mu']) % n


# --- EDIT q2.py :: read_records() :: INPUT FIELDS ---

# =====================================================================
# BEGINNER WALKTHROUGH: read_records() — FILE: q2.py
# INPUT: Ask for one record and return a dictionary. Dictionary keys are field names; values are user inputs.
# CHANGE: For a new question, edit the input prompts and dictionary fields HERE. If the question says read file.txt, replace input() with file reading here.
# =====================================================================
def read_records():
    """CLIENT INPUT: change this dictionary for banking/hospital/new fields."""
    # WHY: Return the result to the function that called us.
    return {'voter_id': input('Voter ID: ').strip(),
            'constituency': input('Constituency: ').strip(),
            'candidate': number('Candidate (1/2/3): '),
            'timestamp': input('Voting time (YYYY-MM-DD HH:MM:SS): ').strip()}


# --- EDIT q2.py :: prepare_packet() :: SENDER / ENCRYPT ---

# =====================================================================
# BEGINNER WALKTHROUGH: prepare_packet() — FILE: q2.py
# SENDER: This is the CLIENT / SENDER half. It prepares a protected packet from the original record.
# ORDER: Convert record to bytes -> hash -> encrypt -> protect key -> sign / encrypt numbers -> return packet.
# CHANGE: Change algorithm, input field names and encrypted numeric values HERE. Make matching changes in accept_record().
# =====================================================================
def prepare_packet(record, keys):
    """CLIENT: hash -> AES-CBC with USER IV -> RSA -> ElGamal -> Paillier."""
    metadata = {'voter_id': record['voter_id'], 'constituency': record['constituency'],
                'timestamp': record['timestamp']}
    # WHY: Convert the dictionary or message into bytes because cryptographic algorithms operate on bytes.
    data = to_bytes(metadata)
    # WHY: Calculate a fixed-length digest. Sender and receiver MUST use the same hash algorithm.
    digest = hash_bytes(data, 'sha512')
    # Use master AES helper. It chooses a fresh IV internally, so to honor
    # the question's REQUIRED user-entered IV, use the AES primitive here.
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    # WHY: Retrieve a named key or setting from the keys dictionary returned by setup().
    cipher = AES.new(keys['aes'], AES.MODE_CBC, iv=keys['iv'])
    # WHY: Work with encrypted data; do not treat ciphertext as plaintext.
    encrypted = {'iv': keys['iv'].hex(), 'ct': cipher.encrypt(pad(data, 16)).hex()}
    # WHY: Retrieve a named key or setting from the keys dictionary returned by setup().
    aes_number = int.from_bytes(keys['aes'], 'big')
    # WHY: Encrypt (wrap) the AES session key using the receiver RSA PUBLIC key.
    wrapped = pow(aes_number, keys['rsa']['e'], keys['rsa']['n'])
    # WHY: Generate the digital signature using the sender PRIVATE signing key.
    signature = sign_hash(digest, keys['elg'])
    # One-hot votes: count EACH candidate, not the sum of candidate IDs.
    # WHY: Create a one-hot vote vector: candidate 2 of 3 becomes [0, 1, 0].
    vector = one_hot_vote(record['candidate'], len(CANDIDATES))
    # WHY: Encrypt a numerical value using the Paillier PUBLIC key.
    encrypted_votes = [paillier_encrypt_manual(x, keys['pai']) for x in vector]
    # WHY: Return the result to the function that called us.
    return {'voter_id': record['voter_id'], 'constituency': record['constituency'],
            'timestamp': record['timestamp'], 'hash': digest, 'encrypted': encrypted,
            'wrapped_key': wrapped, 'signature': signature, 'votes': encrypted_votes}


# --- EDIT q2.py :: accept_record() :: RECEIVER / DECRYPT ---

# =====================================================================
# BEGINNER WALKTHROUGH: accept_record() — FILE: q2.py
# RECEIVER: This is the SERVER / RECEIVER half, simulated inside the same Python program.
# ORDER: Recover key -> decrypt -> recalculate hash -> verify signature -> check metadata/time -> accept.
# CHANGE: Whenever prepare_packet() changes its cipher, signature, hash or packet keys, update this function too.
# =====================================================================
def accept_record(packet, keys):
    """SERVER: RSA unwrap -> AES decrypt -> SHA-512 -> ElGamal verify -> time."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    # WHY: Convert the dictionary or message into bytes because cryptographic algorithms operate on bytes.
    recovered = pow(packet['wrapped_key'], keys['rsa']['d'], keys['rsa']['n']).to_bytes(32, 'big')
    # WHY: Work with encrypted data; do not treat ciphertext as plaintext.
    encrypted = packet['encrypted']
    # WHY: Encrypt the plaintext using the selected symmetric cipher and key.
    data = unpad(AES.new(recovered, AES.MODE_CBC, iv=bytes.fromhex(encrypted['iv']))
                 .decrypt(bytes.fromhex(encrypted['ct'])), 16)
    # WHY: Calculate a fixed-length digest. Sender and receiver MUST use the same hash algorithm.
    digest = hash_bytes(data, 'sha512')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not hmac.compare_digest(digest, packet['hash']): raise ValueError('Hash mismatch')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not verify_signature(digest, packet['signature'], keys['elg']):
        # WHY: Work with the signature: sender creates it, receiver checks it.
        raise ValueError('ElGamal signature invalid')
    # WHY: Convert decrypted JSON bytes back into a Python dictionary.
    metadata = json.loads(data)
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if metadata['voter_id'] != packet['voter_id'] or metadata['constituency'] != packet['constituency']:
        # WHY: Reject invalid input by raising a clear error.
        raise ValueError('Metadata mismatch')
    # WHY: Parse or check the date/time for this record.
    timestamp = datetime.fromisoformat(metadata['timestamp'])
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if not keys['start'] <= timestamp <= keys['end']:
        # WHY: Reject invalid input by raising a clear error.
        raise ValueError('Vote outside allowed time')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if packet['voter_id'] in seen: raise ValueError('Duplicate voter')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if len(packet['votes']) != len(CANDIDATES): raise ValueError('Invalid vote vector')
    # NOTE: no zero-knowledge proof linking encrypted votes to the metadata.
    # WHY: Store the accepted record in the in-memory list.
    # WHY: Store the accepted record in the in-memory list.
    seen.add(packet['voter_id']); records.append(packet)
    term = 'place:' + packet['constituency'].lower()
    # WHY: Convert a search term into an HMAC token for the searchable index.
    index.setdefault(search_token(term, keys['index_key']), []).append(packet['voter_id'])
    # WHY: Return the result to the function that called us.
    return metadata


# --- EDIT q2.py :: tally() :: PAILLIER TALLY ---

# =====================================================================
# BEGINNER WALKTHROUGH: tally() — FILE: q2.py
# PAILLIER: Add ciphertexts while they remain encrypted. Decrypt only the final aggregate.
# CHANGE: For money, aggregate encrypted amount. For votes, use one encrypted 0/1 per candidate and tally each column.
# =====================================================================
def tally(keys):
    """SERVER: multiply Paillier ciphertexts column-wise, decrypt aggregate."""
    # WHY: Retrieve a named key or setting from the keys dictionary returned by setup().
    n = keys['pai']['n']
    # WHY: Repeat this operation for each item in the collection.
    for candidate, name in CANDIDATES.items():
        # WHY: Combine encrypted Paillier values WITHOUT decrypting each record.
        aggregate = 1
        # WHY: Repeat this operation for each item in the collection.
        for packet in records:
            # WHY: Combine encrypted Paillier values WITHOUT decrypting each record.
            aggregate = aggregate * packet['votes'][candidate-1] % (n*n)
        # WHY: Show the result or status on screen.
        print(name, ':', paillier_decrypt_manual(aggregate, keys['pai']))


# --- EDIT q2.py :: search() :: SEARCH ---

# =====================================================================
# BEGINNER WALKTHROUGH: search() — FILE: q2.py
# SEARCH: Use the question-specific searchable fields and display matching IDs, not sensitive plaintext.
# CHANGE: If the exam changes constituency to branch / department / date, update indexing and this search prompt together.
# =====================================================================
def search(keys):
    """SERVER: HMAC index for constituency; timestamp range on metadata."""
    # WHY: Ask the user to enter the value required by this question.
    choice = input('1. Constituency  2. Time range: ')
    # WHY: Check this condition before continuing; invalid data must not be accepted.
    if choice == '1':
        # WHY: Ask the user to enter the value required by this question.
        place = input('Constituency: ').strip().lower()
        # WHY: Show the result or status on screen.
        print('IDs:', index.get(search_token('place:'+place, keys['index_key']), []))
    # WHY: Handle this alternative menu choice.
    elif choice == '2':
        # WHY: Ask the user to enter the value required by this question.
        start = datetime.fromisoformat(input('Start time: '))
        # WHY: Ask the user to enter the value required by this question.
        end = datetime.fromisoformat(input('End time: '))
        # WHY: Show the result or status on screen.
        print('IDs:', [r['voter_id'] for r in records if start <= datetime.fromisoformat(r['timestamp']) <= end])
        # WHY: Show the result or status on screen.
        print('Note: range scan uses visible timestamp metadata, not full encrypted range search.')


# --- EDIT q2.py :: main() :: MENU ---

# =====================================================================
# BEGINNER WALKTHROUGH: main() — FILE: q2.py
# MENU: The while loop keeps showing choices until the user exits.
# FLOW: A menu choice calls one of the functions above. There is NO separate socket server here.
# CHANGE: Rename choices and add/remove operations HERE, not in crypto_helpers.py.
# =====================================================================
def main():
    # WHY: Try the operation; catch invalid inputs below instead of crashing.
    # WHY: Try the operation; catch invalid inputs below instead of crashing.
    try: keys = setup()
    except ValueError as exc:
        # WHY: Show the result or status on screen.
        # WHY: Show the result or status on screen.
        print('SETUP ERROR:', exc); return
    # WHY: Repeat until the user exits or valid input is obtained.
    while True:
        # WHY: Show the result or status on screen.
        print('\n1. Cast vote  2. Verify vote  3. Tally  4. Search  5. Save records  0. Exit')
        # WHY: Ask the user to enter the value required by this question.
        choice = input('Choice: ').strip()
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice == '0': break
        # WHY: Ask the user to enter the value required by this question.
        role = input('Role (voter/server/admin): ').strip().lower()
        permissions = {'voter': {'1'}, 'server': {'2'}, 'admin': {'3', '4', '5'}}
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice not in permissions.get(role, set()):
            # WHY: Show the result or status on screen.
            print('ACCESS DENIED'); continue
        # WHY: Try the operation; catch invalid inputs below instead of crashing.
        try:
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if choice == '1':
                # WHY: Build or obtain a dictionary that groups the relevant fields together.
                record = read_records()
                # WHY: Check this condition before continuing; invalid data must not be accepted.
                if not record['voter_id'] or not record['constituency'] or record['candidate'] not in CANDIDATES:
                    # WHY: Reject invalid input by raising a clear error.
                    raise ValueError('Invalid voter/constituency/candidate')
                # WHY: Build or obtain a dictionary that groups the relevant fields together.
                packet = prepare_packet(record, keys)
                # WHY: Show the result or status on screen.
                print('Encrypted AES:', packet['encrypted'])
                # WHY: Show the result or status on screen.
                print('RSA-wrapped key:', packet['wrapped_key'])
                # WHY: Show the result or status on screen.
                print('SHA-512:', packet['hash'])
                # WHY: Show the result or status on screen.
                print('ElGamal signature:', packet['signature'])
                # WHY: Show the result or status on screen.
                print('Paillier vote vector:', packet['votes'])
                # WHY: Show the result or status on screen.
                print('Accepted:', accept_record(packet, keys))
            # WHY: Handle this alternative menu choice.
            elif choice == '2':
                # WHY: Repeat this operation for each item in the collection.
                for packet in records:
                    # WHY: Show the result or status on screen.
                    print(packet['voter_id'], 'valid:', accept_verification_only(packet, keys))
            # WHY: Handle this alternative menu choice.
            # WHY: Handle this alternative menu choice.
            elif choice == '3': tally(keys)
            # WHY: Handle this alternative menu choice.
            # WHY: Handle this alternative menu choice.
            elif choice == '4': search(keys)
            # WHY: Handle this alternative menu choice.
            elif choice == '5':
                # WHY: Work with encrypted data; do not treat ciphertext as plaintext.
                with open('q2_encrypted_records.json', 'w') as file:
                    # WHY: Save the result in a file so it persists after the program exits.
                    json.dump(records, file, indent=2)
                # WHY: Show the result or status on screen.
                print('Saved encrypted records')
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            # WHY: Show the result or status on screen.
            print('ERROR:', exc)


def accept_verification_only(packet, keys):
    """Read-only verification; does NOT append the record twice."""
    # WHY: Return the result to the function that called us.
    return verify_signature(packet['hash'], packet['signature'], keys['elg']) and \
           keys['start'] <= datetime.fromisoformat(packet['timestamp']) <= keys['end']


if __name__ == '__main__':
    main()
