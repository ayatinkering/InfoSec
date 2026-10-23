# ============================================================================
# Q3 — HOSPITAL REPORT SECURITY
# ============================================================================
# EXACT ALGORITHMS USED:
# AES-256-CBC | RSA-OAEP key wrapping | SHA-512 | RSA-PSS signature | tamper detection
# KEY INPUTS: AES key and IV: user input; RSA key pairs: generated
#
# SHARED GENERIC NAMES: setup, read_records, prepare_packet, accept_record, tamper_demo, main
# crypto_helpers.py contains reusable algorithms. DO NOT edit it for a new exam.
# This file contains the scenario, packet fields, and menu. EDIT THIS q3.py.
#
# CHANGE BY EXAM REQUIREMENT (change both encryption and decryption!):
#   HASH: q3.py prepare_packet() AND accept_record(), e.g. sha256/sha512.
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
QUESTION 3 — HOSPITAL REPORT SECURITY
SOURCE REQUIREMENTS: Menu-driven sender enters patient ID, doctor ID, report;
AES-256-CBC with USER-ENTERED key and IV; RSA encrypt AES key using receiver
public key; SHA-512 hash; RSA digital signature; receiver decrypts key/report;
verify hash/signature; display ciphertext, wrapped key, hashes, signature;
show success and tampered-message detection; handle invalid inputs.

===================== EXACT EXAM CHANGE MAP =====================
q3.py get_key_and_iv(): change AES key length/mode/input requirements.
q3.py setup(): change RSA key size or key source (PEM file vs generated).
q3.py prepare_packet(): change record fields, hash, encryption, signature.
q3.py accept_record(): change corresponding decryption/verification.
q3.py tamper_demo(): change which data is deliberately modified.
q3.py main(): change menu.
crypto_helpers.py: DO NOT CHANGE; uses master RSA, SHA, RSA-PSS functions.
NO SOCKETS: sender and receiver are two functions in the same program.
=================================================================
"""
import json
import hmac
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from crypto_helpers import (to_bytes, hash_bytes, rsa_make_keys, rsa_encrypt,
                            rsa_decrypt, rsa_sign_bytes, rsa_verify_bytes)

RSA_BITS = 2048           # CHANGE HERE for RSA-4096
HASH_NAME = 'sha512'      # CHANGE HERE and accept_record() if question changes hash
records = []


# --- EDIT q3.py :: read_records() :: INPUT FIELDS ---

# =====================================================================
# BEGINNER WALKTHROUGH: read_records() — FILE: q3.py
# INPUT: Ask for one record and return a dictionary. Dictionary keys are field names; values are user inputs.
# CHANGE: For a new question, edit the input prompts and dictionary fields HERE. If the question says read file.txt, replace input() with file reading here.
# =====================================================================
def read_records():
    """SENDER INPUT: change these fields for a different record scenario."""
    # WHY: Return the result to the function that called us.
    return {'patient_id': input('Patient ID: ').strip(),
            'doctor_id': input('Doctor ID: ').strip(),
            'report': input('Medical report: ').strip()}


# --- EDIT q3.py :: setup() :: KEY SETUP ---

# =====================================================================
# BEGINNER WALKTHROUGH: setup() — FILE: q3.py
# KEYS: Set up the keys and configuration before any record is sent.
# CHANGE: For different RSA sizes, signature algorithms, Paillier parameters or deadlines, edit this function.
# =====================================================================
def setup():
    """Generate receiver RSA keys and separate sender signing keys."""
    receiver_public, receiver_private = rsa_make_keys(RSA_BITS)
    sender_public, sender_private = rsa_make_keys(RSA_BITS)
    # WHY: Return the result to the function that called us.
    return {'receiver_public': receiver_public, 'receiver_private': receiver_private,
            'sender_public': sender_public, 'sender_private': sender_private}


def read_hex(prompt, size):
    # WHY: Repeat until the user exits or valid input is obtained.
    while True:
        # WHY: Try the operation; catch invalid inputs below instead of crashing.
        try:
            result = bytes.fromhex(getpass(f'{prompt} ({size*2} hex chars): '))
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if len(result) == size: return result
        except ValueError: pass
        # WHY: Show the result or status on screen.
        print('Invalid input; use exact number of hex characters.')



# =====================================================================
# BEGINNER WALKTHROUGH: get_key_and_iv() — FILE: q3.py
# KEY + IV: AES-256 key = 32 bytes; CBC IV = 16 bytes. The exam explicitly asks the user to supply both.
# =====================================================================
def get_key_and_iv():
    """User enters EXACT AES-256 key and CBC IV, as the question requires."""
    # WHY: Return the result to the function that called us.
    return read_hex('AES-256 key', 32), read_hex('CBC IV', 16)


# --- EDIT q3.py :: prepare_packet() :: SENDER / ENCRYPT ---

# =====================================================================
# BEGINNER WALKTHROUGH: prepare_packet() — FILE: q3.py
# SENDER: This is the CLIENT / SENDER half. It prepares a protected packet from the original record.
# ORDER: Convert record to bytes -> hash -> encrypt -> protect key -> sign / encrypt numbers -> return packet.
# CHANGE: Change algorithm, input field names and encrypted numeric values HERE. Make matching changes in accept_record().
# =====================================================================
def prepare_packet(record, keys):
    """SENDER: hash -> RSA-PSS sign -> AES-CBC -> RSA wrap AES key."""
    aes_key, iv = get_key_and_iv()
    # WHY: Convert the dictionary or message into bytes because cryptographic algorithms operate on bytes.
    data = to_bytes(record)
    # WHY: Calculate a fixed-length digest. Sender and receiver MUST use the same hash algorithm.
    digest = hash_bytes(data, HASH_NAME)
    # WHY: Encrypt the plaintext using the selected symmetric cipher and key.
    encrypted = AES.new(aes_key, AES.MODE_CBC, iv=iv).encrypt(pad(data, 16))
    # WHY: Build or obtain a dictionary that groups the relevant fields together.
    packet = {'patient_id': record['patient_id'], 'doctor_id': record['doctor_id'],
              'iv': iv.hex(), 'ciphertext': encrypted.hex(),
              'wrapped_key': rsa_encrypt(aes_key, keys['receiver_public']),
              'hash': digest, 'signature': rsa_sign_bytes(data, keys['sender_private'])}
    # WHY: Return the result to the function that called us.
    return packet


# --- EDIT q3.py :: accept_record() :: RECEIVER / DECRYPT ---

# =====================================================================
# BEGINNER WALKTHROUGH: accept_record() — FILE: q3.py
# RECEIVER: This is the SERVER / RECEIVER half, simulated inside the same Python program.
# ORDER: Recover key -> decrypt -> recalculate hash -> verify signature -> check metadata/time -> accept.
# CHANGE: Whenever prepare_packet() changes its cipher, signature, hash or packet keys, update this function too.
# =====================================================================
def accept_record(packet, keys):
    """RECEIVER: RSA unwrap -> AES decrypt -> hash + RSA-PSS verification."""
    # WHY: Recover the AES session key using the receiver RSA PRIVATE key.
    aes_key = rsa_decrypt(packet['wrapped_key'], keys['receiver_private'])
    decrypted = unpad(AES.new(aes_key, AES.MODE_CBC, iv=bytes.fromhex(packet['iv']))
                      .decrypt(bytes.fromhex(packet['ciphertext'])), 16)
    # WHY: Calculate a fixed-length digest. Sender and receiver MUST use the same hash algorithm.
    received_hash = hash_bytes(decrypted, HASH_NAME)
    hash_valid = hmac.compare_digest(packet['hash'], received_hash)
    # WHY: Verify the digital signature using the sender PUBLIC verification key.
    signature_valid = rsa_verify_bytes(decrypted, packet['signature'], keys['sender_public'])
    # WHY: Convert decrypted JSON bytes back into a Python dictionary.
    record = json.loads(decrypted)
    metadata_valid = record['patient_id'] == packet['patient_id'] and record['doctor_id'] == packet['doctor_id']
    # WHY: Show the result or status on screen.
    print('\n===== RECEIVER VERIFICATION =====')
    # WHY: Show the result or status on screen.
    print('Recovered report:', record['report'])
    # WHY: Show the result or status on screen.
    print('Original hash:', packet['hash'])
    # WHY: Show the result or status on screen.
    print('Received hash:', received_hash)
    # WHY: Show the result or status on screen.
    print('Hash matches:', hash_valid)
    # WHY: Show the result or status on screen.
    print('Signature valid:', signature_valid)
    # WHY: Show the result or status on screen.
    print('Metadata matches:', metadata_valid)
    # WHY: Show the result or status on screen.
    print('FINAL ACCEPTED:', hash_valid and signature_valid and metadata_valid)
    # WHY: Return the result to the function that called us.
    return hash_valid and signature_valid and metadata_valid



# =====================================================================
# BEGINNER WALKTHROUGH: tamper_demo() — FILE: q3.py
# TAMPERING: Change a protected value AFTER encryption/signing. Receiver should reject it or fail decryption.
# =====================================================================
def tamper_demo(packet, keys):
    """Alter ciphertext AFTER sender signed. Invalid CBC padding may be detected."""
    changed = dict(packet)
    # WHY: Work with encrypted data; do not treat ciphertext as plaintext.
    cipher = bytearray.fromhex(changed['ciphertext'])
    cipher[-1] ^= 1
    # WHY: Work with encrypted data; do not treat ciphertext as plaintext.
    changed['ciphertext'] = cipher.hex()
    # WHY: Try the operation; catch invalid inputs below instead of crashing.
    try:
        # WHY: Show the result or status on screen.
        print('Tampered accepted?', accept_record(changed, keys))
    except (ValueError, KeyError, TypeError) as exc:
        # WHY: Show the result or status on screen.
        print('TAMPERING DETECTED / DECRYPTION FAILED:', exc)


# --- EDIT q3.py :: main() :: MENU ---

# =====================================================================
# BEGINNER WALKTHROUGH: main() — FILE: q3.py
# MENU: The while loop keeps showing choices until the user exits.
# FLOW: A menu choice calls one of the functions above. There is NO separate socket server here.
# CHANGE: Rename choices and add/remove operations HERE, not in crypto_helpers.py.
# =====================================================================
def main():
    keys = setup()
    # WHY: Repeat until the user exits or valid input is obtained.
    while True:
        # WHY: Show the result or status on screen.
        print('\n1. Send and verify report  2. Tampering demonstration  3. View records  0. Exit')
        # WHY: Ask the user to enter the value required by this question.
        choice = input('Choice: ').strip()
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice == '0': break
        # WHY: Check this condition before continuing; invalid data must not be accepted.
        if choice in ('1', '2'):
            # WHY: Build or obtain a dictionary that groups the relevant fields together.
            record = read_records()
            # WHY: Check this condition before continuing; invalid data must not be accepted.
            if not all(record.values()):
                # WHY: Show the result or status on screen.
                print('All fields are required'); continue
            # WHY: Try the operation; catch invalid inputs below instead of crashing.
            try:
                # WHY: Build or obtain a dictionary that groups the relevant fields together.
                packet = prepare_packet(record, keys)
                # WHY: Show the result or status on screen.
                print('AES encrypted report:', packet['ciphertext'])
                # WHY: Show the result or status on screen.
                print('RSA encrypted AES key:', packet['wrapped_key'])
                # WHY: Show the result or status on screen.
                print('SHA-512:', packet['hash'])
                # WHY: Show the result or status on screen.
                print('RSA-PSS signature:', packet['signature'])
                # WHY: Check this condition before continuing; invalid data must not be accepted.
                if choice == '1':
                    # WHY: Check this condition before continuing; invalid data must not be accepted.
                    # WHY: Check this condition before continuing; invalid data must not be accepted.
                    if accept_record(packet, keys): records.append(packet)
                else: tamper_demo(packet, keys)
            except (ValueError, TypeError, KeyError) as exc:
                # WHY: Show the result or status on screen.
                print('ERROR:', exc)
        # WHY: Handle this alternative menu choice.
        elif choice == '3':
            # WHY: Show the result or status on screen.
            print('Stored encrypted records:', len(records))
            # WHY: Repeat this operation for each item in the collection.
            # WHY: Repeat this operation for each item in the collection.
            for p in records: print(p['patient_id'], p['doctor_id'], p['ciphertext'][:40] + '...')
        else: print('Invalid choice')


if __name__ == '__main__':
    main()
