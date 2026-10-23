# ============================================================================
# BEGINNER EXAM CHANGE MAP — SERVER.PY
# ============================================================================
# SAME FUNCTION NAMES IN BOTH PROJECTS.
#
# SERVER SETTINGS (just below imports):
#   HASH_NAME must equal client's HASH_NAME.
#   SIGN_NAME must equal client's SIGN_NAME.
#   RSA_BITS=2048 for BANK or 4096 for VOTE.
#   SCENARIO controls validation and searchable keyword labels.
#
# accept_record(packet): REVERSE THE CLIENT OPERATIONS
#   STEP 1: verify signature using a TRUSTED public key (demo uses packet key).
#           ECDSA -> ecc_verify(data, signature, public)
#           ElGamal -> elgamal_verify(data, signature, public)
#           RSA-PSS -> rsa_verify_bytes(data, signature, public)
#           Schnorr -> schnorr_verify(data, signature, public)
#   STEP 2: check_timestamp(ticket, secret, deadline)
#   STEP 3: rsa_decrypt(packet['rsa_key'], rsa_private) -> session key
#   STEP 4: decrypt_data(packet['record'], key) -> plaintext bytes
#           For DES/3DES: decrypt_data(packet['record'],key,'DES'/'3DES')
#           AES CBC/CTR/GCM are determined from packet metadata.
#   STEP 5: hash_bytes(data, HASH_NAME) == packet['hash']
#   STEP 6: json.loads(data), check fields, append encrypted packet to TXT
#   STEP 7: add_to_index(index, record_id, keywords, search_secret)
#
# tally(): Paillier-add encrypted numbers; decrypt only aggregated total.
#   BANK -> 1 encrypted amount per record.
#   VOTE -> 3 encrypted one-hot values per record.
#   NEW TASK -> change which encrypted columns are aggregated.
#
# handle(): map menu commands to setup / submit / search / tally / audit.
# main(): start socket server. Usually DO NOT change.
#
# LIMITATIONS: roles are client-claimed (NOT authenticated); signature public
# keys are not preregistered; no TLS; no threshold Paillier or secure voting.
# ============================================================================

"""SERVER: verifies records, decrypts AES, aggregates Paillier, searches.

Run FIRST: python server.py
Then open SECOND terminal: python client.py
All data and logs are stored in .txt files in the SAME folder.
"""
import json
import socket
from pathlib import Path
from datetime import datetime, timezone, timedelta
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
from crypto_helpers import (
    to_bytes, hash_bytes, decrypt_data, rsa_make_keys, rsa_decrypt,
    ecc_verify, elgamal_verify, paillier_make_keys, paillier_add,
    paillier_decrypt, issue_timestamp, check_timestamp,
    add_to_index, search_index, send_json, recv_json
)

BASE = Path(__file__).resolve().parent
HOST, PORT = '127.0.0.1', 5055
RECORDS_FILE = BASE / 'server_records.txt'
AUDIT_FILE = BASE / 'server_audit.txt'

# CHANGE THESE SETTINGS FOR A DIFFERENT QUESTION.
SCENARIO = 'VOTE'
HASH_NAME = 'sha512'
SIGN_NAME = 'ElGamal'
RSA_BITS = 4096

# STEP 0: Server creates PRIVATE keys and keeps them secret.
print('Generating RSA keys; please wait...')
rsa_public, rsa_private = rsa_make_keys(RSA_BITS)
pai_public, pai_private = paillier_make_keys()
timestamp_secret = get_random_bytes(32)
search_secret = get_random_bytes(32)
deadline = datetime.now(timezone.utc) + timedelta(hours=1)

# Records are generic. Index maps HMAC search tokens to record IDs.
records = []
index = {}
seen_ids = set()
registered_signers = {}  # demo registration; see security warning below

# Start empty, so keys from earlier runs never get mixed with new keys.
RECORDS_FILE.write_text('', encoding='utf-8')
AUDIT_FILE.write_text('', encoding='utf-8')

# STEP 1: Append ONE dictionary as JSON text to a .txt file.
def append_txt(path, value):
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(value) + '\n')

# STEP 2: Audit records are timestamped.
def audit(event, detail):
    append_txt(AUDIT_FILE, {
        'time': datetime.now(timezone.utc).isoformat(),
        'event': event, 'detail': detail
    })

# STEP 3: Role-based access control DEMO (no actual login system).
PERMISSIONS = {
    'voter': {'submit'}, 'customer': {'submit'},
    'officer': {'search', 'tally'}, 'auditor': {'audit'},
    'guest': set()
}

def allowed(role, action):
    return action in PERMISSIONS.get(role, set())

# STEP 4: Verify signature, timestamp, decrypt RSA/AES, compare hash.
def accept_record(packet):
    # Reconstruct EXACT signed packet: all fields except signature.
    unsigned = {key: value for key, value in packet.items()
                if key != 'signature'}

    # Signature verification uses sender public key.
    # WARNING: Self-registration is classroom-only, not secure identity proof.
    claimed_id = str(packet['id'])
    signer = packet['sign_public']
    if claimed_id in registered_signers and registered_signers[claimed_id] != signer:
        raise ValueError('Registered signer mismatch')

    if SIGN_NAME == 'ECDSA':
        signer_public = ECC.import_key(signer)
        valid = ecc_verify(to_bytes(unsigned), packet['signature'], signer_public)
    else:
        signer_public = tuple(signer)
        valid = elgamal_verify(to_bytes(unsigned), packet['signature'], signer_public)
    if not valid:
        raise ValueError('Signature INVALID')
    print('STEP 1 - Signature VERIFIED')

    # Server authenticates HMAC timestamp and checks deadline.
    if not check_timestamp(packet['timestamp'], timestamp_secret, deadline):
        raise ValueError('Timestamp INVALID / expired')
    print('STEP 2 - Timestamp VERIFIED')

    # RSA private key recovers original AES key.
    aes_key = rsa_decrypt(packet['rsa_key'], rsa_private)
    print('STEP 3 - RSA recovered AES key')

    # AES-CBC or AES-GCM decrypts using IV/nonce stored in packet.
    data = decrypt_data(packet['record'], aes_key)
    print('STEP 4 - AES decrypted:', data.decode())

    # Recompute hash over ORIGINAL decrypted bytes.
    if hash_bytes(data, HASH_NAME) != packet['hash']:
        raise ValueError('Hash mismatch')
    print('STEP 5 -', HASH_NAME, 'hash MATCHED')

    record = json.loads(data)
    record_id = str(record['id'])
    if record_id != claimed_id:
        raise ValueError('ID mismatch')
    if record_id in seen_ids:
        raise ValueError('Duplicate record ID')

    if SCENARIO == 'BANK':
        if record['amount'] < 0 or len(packet['numbers']) != 1:
            raise ValueError('Invalid encrypted amount')
        keywords = ['branch:' + record['branch'].lower(),
                    'date:' + record['date']]
    else:
        if record['candidate'] not in (1, 2, 3) or len(packet['numbers']) != 3:
            raise ValueError('Invalid vote structure')
        keywords = ['place:' + record['constituency'].lower(),
                    'date:' + packet['timestamp']['time'][:10]]

    # NOTE: Demo does NOT prove Paillier ciphertext matches plaintext value.
    # Real privacy-preserving systems need a zero-knowledge consistency proof.
    seen_ids.add(record_id)
    registered_signers[record_id] = signer
    records.append(packet)
    add_to_index(index, record_id, keywords, search_secret)
    append_txt(RECORDS_FILE, packet)
    audit('ACCEPT', {'id': record_id})
    print('STEP 6 - Stored in server_records.txt')
    return {'ok': True, 'id': record_id, 'signature': 'valid',
            'hash': 'valid', 'timestamp': 'valid'}

# STEP 5: Multiply ciphertexts, decrypt ONLY the aggregate.
def tally():
    if not records:
        return {'ok': True, 'total': 0 if SCENARIO == 'BANK' else [0, 0, 0]}

    if SCENARIO == 'BANK':
        ciphertexts = [packet['numbers'][0] for packet in records]
        encrypted_sum = paillier_add(ciphertexts, pai_public)
        total = paillier_decrypt(encrypted_sum, pai_public, pai_private)
        return {'ok': True, 'total': total, 'count': len(records),
                'note': 'Only encrypted sum was decrypted'}

    totals = []
    for position in range(3):
        ciphertexts = [packet['numbers'][position] for packet in records]
        encrypted_sum = paillier_add(ciphertexts, pai_public)
        totals.append(paillier_decrypt(encrypted_sum, pai_public, pai_private))
    return {'ok': True, 'totals_by_candidate': totals,
            'count': len(records), 'threshold_decryption': 'NOT IMPLEMENTED'}

# STEP 6: Route each client menu request to the right server function.
def handle(request):
    command = request.get('cmd')
    if command == 'setup':
        return {'ok': True, 'rsa_public_pem': rsa_public.export_key().decode(),
                'paillier_public': list(pai_public),
                'timestamp': issue_timestamp(timestamp_secret),
                'deadline': deadline.isoformat()}

    if command == 'submit':
        try:
            return accept_record(request['packet'])
        except Exception as error:
            audit('REJECT', str(error))
            return {'ok': False, 'error': str(error)}

    # IMPORTANT: Client-provided role is NOT authenticated. RBAC is a demo.
    role = request.get('role', 'guest')
    if not allowed(role, command):
        return {'ok': False, 'error': 'ACCESS DENIED'}

    if command == 'search':
        prefix = 'branch:' if SCENARIO == 'BANK' else 'place:'
        term = prefix + request['term'].strip().lower()
        return {'ok': True, 'ids': search_index(index, term, search_secret)}
    if command == 'tally':
        return tally()
    if command == 'audit':
        return {'ok': True, 'lines': AUDIT_FILE.read_text().splitlines()}
    return {'ok': False, 'error': 'Unknown command'}

# STEP 7: Start a REAL TCP server, one request per connection.
def main():
    print('SERVER RUNNING on 127.0.0.1:5055')
    print('Now run python client.py in a second terminal')
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(10)
        while True:
            connection, address = server.accept()
            with connection:
                try:
                    request = recv_json(connection)
                    response = handle(request)
                    send_json(connection, response)
                except Exception as error:
                    print('Connection error:', error)

if __name__ == '__main__':
    main()
