# ============================================================================
# BEGINNER EXAM CHANGE MAP — CLIENT.PY
# ============================================================================
# SAME FUNCTION NAMES IN BOTH PROJECTS. ONLY CHANGE THE CODE INSIDE THEM.
#
# read_records():
#   Always reads file.txt and returns records[] (list of dictionaries).
#   BANK fields: id, receiver, amount, branch, date
#   VOTE fields: id, candidate, constituency
#   HOSPITAL example: id, name, department, diagnosis, expense
#   Change field names and number of CSV columns ONLY HERE.
#
# get_setup():
#   Asks server for PUBLIC RSA/Paillier keys and timestamp ticket.
#   For RSA 2048 -> 4096 change RSA_BITS in SERVER.PY, not here.
#
# get_signing_keys():
#   ECDSA: ecc_make_keys(), ecc_sign(data, private)
#   ElGamal: elgamal_make_keys(), elgamal_sign(data, public, private)
#   RSA-PSS: rsa_make_keys(2048), rsa_sign_bytes(data, private)
#   Schnorr: schnorr_make_keys(), schnorr_sign(data, public, private)
#   NOTE: To switch to RSA-PSS/Schnorr, ALSO update serialization in
#   prepare_packet() AND the matching verification in server.py.
#
# prepare_packet(record):  THIS IS THE MOST IMPORTANT FUNCTION FOR EXAMS.
#   STEP 1: record dictionary -> to_bytes(record)
#   STEP 2: hash_bytes(data, HASH_NAME) -> md5/sha1/sha256/sha512
#   STEP 3: key_for(AES_BITS) + encrypt_data(data, aes_key, AES_MODE)
#           AES_BITS = 128/192/256, AES_MODE = ECB/CBC/CTR/GCM
#           DES: key_for('DES'), encrypt_data(data,key,'DES','CBC')
#           3DES: key_for('3DES'), encrypt_data(data,key,'3DES','CBC')
#           If changing cipher, update SERVER's decrypt_data(..., 'DES').
#   STEP 4: rsa_encrypt(aes_key, rsa_public) wraps short session key.
#           For Diffie-Hellman, a DIFFERENT key-agreement protocol is needed.
#   STEP 5: paillier_encrypt(number, pai_public)
#           BANK -> amount; VOTE -> one-hot vector [1,0,0] etc.
#   STEP 6: timestamp + hash + encrypted record + encrypted number(s)
#   STEP 7: sign packet with chosen signature algorithm.
#   WARNING: New signature algorithm must match SERVER verification.
#
# ask_server(): TCP sends/receives JSON. Usually DO NOT change.
# submit(): prepare_packet(record) -> send -> write client_report.txt.
# tamper_demo(): modifies ciphertext AFTER signing; server rejects.
# main(): Menu. Change labels and search prompts for your new scenario.
#
# IMPORTANT: NEVER blindly switch an algorithm only on one side.
# Both client and server must agree on cipher, hash, signature, packet format.
# ============================================================================

"""CLIENT: Read file.txt, prepare protected records, send to server.

MENU STEPS FOLLOW THE QUESTION. Run server.py FIRST in another terminal.
Change only the LAB EXAM SETTINGS below to adapt the SAME flow.
"""
import json
import socket
from pathlib import Path
from Crypto.PublicKey import RSA, ECC
from crypto_helpers import (
    to_bytes, hash_bytes, key_for, encrypt_data, rsa_encrypt,
    ecc_make_keys, ecc_sign, elgamal_make_keys, elgamal_sign,
    paillier_encrypt, send_json, recv_json
)

BASE = Path(__file__).resolve().parent
INPUT = BASE / 'file.txt'                # ALWAYS the same generic filename
REPORT = BASE / 'client_report.txt'
HOST, PORT = '127.0.0.1', 5055

# =====================================================================
# EXAM SETTINGS: THIS IS THE MAIN PLACE TO SWAP ALGORITHMS.
# BANK: sha256, 128, GCM, 2048, ECDSA, amount
# VOTE: sha512, 256, CBC, 4096, ElGamal, one-hot
# =====================================================================
HASH_NAME = 'sha512'
AES_BITS = 256
AES_MODE = 'CBC'
SIGN_NAME = 'ElGamal'
SCENARIO = 'VOTE'

setup = None
sign_public = None
sign_private = None

# STEP 1: Read rows from file.txt into a GENERIC list called records.
def read_records():
    records = []

    for line in INPUT.read_text(encoding='utf-8').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue

        parts = [value.strip() for value in line.split(',')]

        if SCENARIO == 'BANK':
            # account, receiver, amount, branch, date
            if len(parts) != 5:
                raise ValueError('Bank row must have 5 comma-separated values')
            record = {'id': parts[0], 'receiver': parts[1],
                      'amount': int(parts[2]), 'branch': parts[3],
                      'date': parts[4]}
        else:
            # ballot_id, candidate, constituency
            if len(parts) != 3:
                raise ValueError('Vote row must have 3 comma-separated values')
            record = {'id': parts[0], 'candidate': int(parts[1]),
                      'constituency': parts[2]}

        records.append(record)

    return records

# STEP 2: Get server PUBLIC keys and simulated trusted timestamp.
def get_setup():
    global setup
    setup = ask_server({'cmd': 'setup'})
    if not setup.get('ok'):
        raise ValueError(setup)
    print('Public keys and timestamp received')

# STEP 3: Generate ONE client signing identity (reuse for all records).
# The demo server registers this public key on first use; REAL systems
# require prior identity verification, not self-registration by packet.
def get_signing_keys():
    global sign_public, sign_private
    if sign_private is None:
        if SIGN_NAME == 'ECDSA':
            sign_public, sign_private = ecc_make_keys()
        else:
            sign_public, sign_private = elgamal_make_keys()
    return sign_public, sign_private

# STEP 4: This is the ENTIRE reusable CLIENT crypto pipeline.
def prepare_packet(record):
    if setup is None:
        get_setup()

    print('\nSTEP 1 - Original record:', record)

    # STEP 2: Convert record to bytes and calculate hash.
    data = to_bytes(record)
    digest = hash_bytes(data, HASH_NAME)
    print('STEP 2 -', HASH_NAME, 'hash:', digest)

    # STEP 3: Encrypt original record with AES.
    aes_key = key_for(AES_BITS)
    encrypted_record = encrypt_data(data, aes_key, AES_MODE)
    print('STEP 3 - AES-', AES_BITS, AES_MODE, 'encrypted')

    # STEP 4: RSA encrypt ONLY the small AES key, not whole record.
    rsa_public = RSA.import_key(setup['rsa_public_pem'].encode())
    encrypted_key = rsa_encrypt(aes_key, rsa_public)
    print('STEP 4 - AES key protected using RSA public key')

    # STEP 5: Encrypt numerical values with Paillier.
    pai_public = tuple(setup['paillier_public'])
    if SCENARIO == 'BANK':
        encrypted_numbers = [paillier_encrypt(record['amount'], pai_public)]
        print('STEP 5 - Encrypted amount:', record['amount'])
    else:
        # Candidate 1 -> [1,0,0], candidate 2 -> [0,1,0], etc.
        candidate = record['candidate']
        if candidate not in (1, 2, 3):
            raise ValueError('Candidate must be 1, 2, or 3')
        vector = [int(candidate == i) for i in (1, 2, 3)]
        encrypted_numbers = [paillier_encrypt(v, pai_public) for v in vector]
        print('STEP 5 - Encrypted one-hot vote:', vector)

    # STEP 6: Attach timestamp, ciphertext, hash, and public signing key.
    public, private = get_signing_keys()
    if SIGN_NAME == 'ECDSA':
        public_text = public.export_key(format='PEM')
    else:
        public_text = list(public)

    packet = {
        'record': encrypted_record,
        'rsa_key': encrypted_key,
        'hash': digest,
        'numbers': encrypted_numbers,
        'timestamp': setup['timestamp'],
        'sign_public': public_text,
        'id': record['id']
    }

    # STEP 7: Sign WHOLE packet except signature field itself.
    if SIGN_NAME == 'ECDSA':
        packet['signature'] = ecc_sign(to_bytes(packet), private)
    else:
        packet['signature'] = elgamal_sign(to_bytes(packet), public, private)
    print('STEP 6-7 -', SIGN_NAME, 'signature + timestamp attached')

    return packet

# STEP 8: Actual socket client: send one request, read one response.
def ask_server(request):
    with socket.create_connection((HOST, PORT), timeout=60) as conn:
        send_json(conn, request)
        return recv_json(conn)

# STEP 9: Submit ONE record and save server reply in TXT.
def submit(record):
    packet = prepare_packet(record)
    response = ask_server({'cmd': 'submit', 'packet': packet})
    with REPORT.open('a', encoding='utf-8') as f:
        f.write(json.dumps({'id': record['id'], 'result': response}) + '\n')
    print('SERVER REPLY:', response)
    return response

# STEP 10: Deliberately modify signed ciphertext. Must be rejected.
def tamper_demo():
    record = read_records()[0]
    packet = prepare_packet(record)
    old = packet['record']['ct']
    packet['record']['ct'] = ('00' if old[:2] != '00' else 'ff') + old[2:]
    print('TAMPER TEST:', ask_server({'cmd': 'submit', 'packet': packet}))

# MENU: one numbered option per task; identical for both projects.
def main():
    while True:
        print("""
========== E-VOTING PYQ CLIENT ==========
1. STEP 1 - Read file.txt
2. STEP 2 - Obtain server public keys and timestamp
3. STEP 3 - Protect and SEND first record
4. STEP 4 - Protect and SEND ALL records
5. STEP 5 - Search by branch / constituency
6. STEP 6 - Paillier encrypted aggregate
7. STEP 7 - View audit log
8. STEP 8 - Tamper test (must reject)
9. STEP 9 - Role permission demonstration
0. Exit
==========================================""")
        choice = input('Choose: ').strip()
        try:
            if choice == '1':
                for record in read_records():
                    print(record)
            elif choice == '2':
                get_setup()
            elif choice == '3':
                submit(read_records()[0])
            elif choice == '4':
                for record in read_records():
                    submit(record)
            elif choice == '5':
                term = input('Branch or constituency: ').strip()
                print(ask_server({'cmd': 'search', 'term': term, 'role': 'officer'}))
            elif choice == '6':
                print(ask_server({'cmd': 'tally', 'role': 'officer'}))
            elif choice == '7':
                print(ask_server({'cmd': 'audit', 'role': 'auditor'}))
            elif choice == '8':
                tamper_demo()
            elif choice == '9':
                print('Guest search:', ask_server({'cmd': 'search', 'term': 'Manipal', 'role': 'guest'}))
                print('Officer tally:', ask_server({'cmd': 'tally', 'role': 'officer'}))
            elif choice == '0':
                break
            else:
                print('Invalid choice')
        except Exception as error:
            print('ERROR:', error)

if __name__ == '__main__':
    main()
