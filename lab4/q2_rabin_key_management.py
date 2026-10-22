"""
LAB 4 — REGULAR QUESTION 2: HEALTHCARE RABIN KEY MANAGEMENT

Implement a centralized service for hospitals/clinics:
- Configurable Rabin key generation (example: 1024 bits).
- Authorized distribution of public/private keys.
- Revocation and updating of keys.
- Automatic renewal after approximately 12 months.
- Encrypted private-key storage and audit logging.
- Privacy/access-control considerations and a Rabin/RSA trade-off comparison.

This is a small local menu/API demonstration. Role selection simulates login.
The .txt files below are created beside this script. This demonstrates technical
controls; a classroom program cannot certify actual regulatory compliance.
"""

from pathlib import Path
from datetime import datetime, timezone, timedelta
from time import perf_counter
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime

ROOT = Path(__file__).resolve().parent
# CHANGE renewal period if the question specifies another interval.
RENEWAL_DAYS = 365



# ---------- STORE THE SERVICE RECORDS ----------
def save_records(records):
    with (ROOT / 'rabin_records.txt').open('w') as file:
        json.dump(records, file, indent=4)



# ---------- LOAD RECORDS, STARTING WITH AN EMPTY FILE ON FIRST RUN ----------
def load_records():
    path = ROOT / 'rabin_records.txt'

    if not path.exists():
        save_records({})

    with path.open() as file:
        return json.load(file)



# ---------- APPEND AN AUDIT EVENT ----------
def log_event(action, hospital):
    timestamp = datetime.now(timezone.utc).isoformat()

    with (ROOT / 'rabin_audit.txt').open('a') as file:
        file.write(timestamp + ' | ' + action + ' | ' + hospital + '\n')



# ---------- GET THE SERVICE'S PRIVATE-STORAGE ENCRYPTION KEY ----------
# A local key file is enough for this lab; callers receive keys only through the API.
def storage_key():
    path = ROOT / 'rabin_storage_key.txt'

    if not path.exists():
        path.write_text(get_random_bytes(32).hex())

    return bytes.fromhex(path.read_text())



# ---------- RABIN KEY GENERATION ----------
# Both primes must be 3 mod 4 so square roots can be recovered efficiently.
def generate_rabin_keys(bits=1024):
    while True:
        p = getPrime(bits // 2)

        if p % 4 == 3:
            break

    while True:
        q = getPrime(bits // 2)

        if q % 4 == 3 and q != p:
            break

    return p * q, (p, q)



# ---------- ENCRYPT THE PRIVATE KEY BEFORE WRITING IT ----------
def protect_private_key(private_key):
    data = json.dumps(list(private_key)).encode('utf-8')
    cipher = AES.new(storage_key(), AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {'nonce': cipher.nonce.hex(), 'ciphertext': ciphertext.hex(), 'tag': tag.hex()}



# ---------- DECRYPT A PRIVATE KEY ONLY AFTER AUTHORIZATION ----------
def recover_private_key(packet):
    cipher = AES.new(storage_key(), AES.MODE_GCM, nonce=bytes.fromhex(packet['nonce']))
    data = cipher.decrypt_and_verify(bytes.fromhex(packet['ciphertext']), bytes.fromhex(packet['tag']))
    return tuple(json.loads(data.decode('utf-8')))



# ---------- GENERATE OR RENEW ONE HOSPITAL'S KEY PAIR ----------
def issue_keys(records, hospital, bits=1024):
    public_key, private_key = generate_rabin_keys(bits)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=RENEWAL_DAYS)
    records[hospital] = {
        'public': public_key,
        'private_encrypted': protect_private_key(private_key),
        'bits': bits,
        'active': True,
        'expires': expires.isoformat(),
    }
    save_records(records)
    log_event('GENERATE/RENEW', hospital)



# ---------- AUTOMATIC RENEWAL CHECK ----------
# Called on every menu cycle; expired active records are renewed automatically.
def renew_expired_keys(records):
    now = datetime.now(timezone.utc)

    for hospital, record in list(records.items()):
        expires = datetime.fromisoformat(record['expires'])

        if record['active'] and now >= expires:
            issue_keys(records, hospital, record['bits'])



# ---------- AUTHORIZED DISTRIBUTION API ----------
# A hospital can request only its own key pair. Admin can distribute any pair.
def request_keys(records, hospital, role, caller):
    if role != 'admin':
        if role != 'hospital' or caller != hospital:
            raise PermissionError('You cannot request another hospital\'s keys.')

    record = records[hospital]

    if not record['active']:
        raise PermissionError('Hospital key is revoked.')

    log_event('DISTRIBUTE to ' + caller, hospital)
    return record['public'], recover_private_key(record['private_encrypted'])



# ---------- RABIN ENCRYPTION AND FOUR DECRYPTION CANDIDATES ----------
# Unlike textbook RSA, ordinary Rabin decryption gives four possible roots.
def encrypt_rabin(message, n):
    return pow(message, 2, n)



# ---------- RECOVER THE FOUR POSSIBLE PLAINTEXT ROOTS ----------
def decrypt_rabin_candidates(ciphertext, private_key):
    p, q = private_key
    n = p * q
    root_p = pow(ciphertext, (p + 1) // 4, p)
    root_q = pow(ciphertext, (q + 1) // 4, q)
    first_part = root_p * q * pow(q, -1, p)
    second_part = root_q * p * pow(p, -1, q)
    root1 = (first_part + second_part) % n
    root2 = (first_part - second_part) % n
    return sorted(set([root1, (-root1) % n, root2, (-root2) % n]))



# ---------- TRADE-OFF COMPARISON ----------
# Both paths use raw integer arithmetic so the comparison's scope is clear.
def compare_rabin_rsa(bits=1024):
    message = 123
    start = perf_counter()
    n, private = generate_rabin_keys(bits)
    rabin_keygen = perf_counter() - start
    start = perf_counter()
    ciphertext = encrypt_rabin(message, n)
    rabin_encrypt = perf_counter() - start
    start = perf_counter()
    roots = decrypt_rabin_candidates(ciphertext, private)
    rabin_decrypt = perf_counter() - start

    start = perf_counter()
    key = RSA.generate(bits)
    rsa_keygen = perf_counter() - start
    start = perf_counter()
    encrypted = pow(message, key.e, key.n)
    rsa_encrypt = perf_counter() - start
    start = perf_counter()
    recovered = pow(encrypted, key.d, key.n)
    rsa_decrypt = perf_counter() - start

    print('Algorithm      Keygen(s)    Encrypt(s)    Decrypt(s)')
    print('Rabin:', rabin_keygen, rabin_encrypt, rabin_decrypt)
    print('RSA:  ', rsa_keygen, rsa_encrypt, rsa_decrypt)
    print('Rabin roots:', roots, '| original present:', message in roots)
    print('RSA recovered:', recovered)
    print('Rabin squares quickly but needs redundancy to select one of four roots.')
    print('RSA has a unique inverse for valid messages. Both rely on factorization.')



# ---------- ROLE-BASED KEY MANAGEMENT MENU ----------
# CHANGE the expiry field in rabin_records.txt to a past date to demonstrate renewal.
def main():
    records = load_records()
    role = 'admin'
    caller = 'admin'

    while True:
        renew_expired_keys(records)
        print('\nRole:', role, '| Caller:', caller)
        print('1 Switch role | 2 Generate/update | 3 Request keys | 4 Revoke')
        print('5 View audit | 6 Compare Rabin/RSA | 0 Exit')
        choice = input('Choice: ').strip()

        try:
            if choice == '0':
                break
            elif choice == '1':
                role = input('Role: admin/hospital/auditor: ').strip()
                caller = input('Caller ID (hospital name for hospital role): ').strip()
            elif choice == '2':
                if role != 'admin':
                    raise PermissionError('Only admin generates/updates keys.')

                hospital = input('Hospital/clinic name: ').strip()
                bits_text = input('Key bits [1024]: ').strip()
                bits = 1024

                if bits_text:
                    bits = int(bits_text)

                if bits < 512:
                    raise ValueError('Use at least 512 bits for this lab menu.')

                issue_keys(records, hospital, bits)
                print('Keys issued; private components encrypted in rabin_records.txt.')
            elif choice == '3':
                hospital = input('Hospital name: ').strip()
                public, private = request_keys(records, hospital, role, caller)
                print('Public n:', public)
                print('Authorized private (p,q):', private)
            elif choice == '4':
                if role != 'admin':
                    raise PermissionError('Only admin revokes keys.')

                hospital = input('Hospital to revoke: ').strip()
                records[hospital]['active'] = False
                save_records(records)
                log_event('REVOKE', hospital)
                print('Revoked. Use Generate/update to replace its keys.')
            elif choice == '5':
                if role not in ['admin', 'auditor']:
                    raise PermissionError('Only admin/auditor reads logs.')

                path = ROOT / 'rabin_audit.txt'

                if path.exists():
                    print(path.read_text())
            elif choice == '6':
                compare_rabin_rsa()
        except (ValueError, PermissionError, KeyError) as error:
            print('Cannot perform action:', error)



if __name__ == '__main__':
    main()
