"""
PYQ1 — INFORMATION SECURITY LAB: MENU-DRIVEN NATIONAL E-VOTING SYSTEM

QUESTION (from the supplied examination paper)
A national e-voting system lets citizens vote remotely. It must provide privacy,
verifiability, integrity, non-repudiation and aggregate computation on encrypted votes.

CLIENT REQUIREMENTS
1. Create an electronic ballot containing candidate selection and constituency ID.
2. Compute the SHA-512 hash of the ballot file contents.
3. Encrypt the ballot with AES-256 in CBC mode.
4. Encrypt the AES session key with the Election Commission RSA-4096 public key.
5. Sign the SHA-512 ballot hash using the voter's ElGamal private key.
6. Encrypt the numerical vote using Paillier for homomorphic tallying.
7. Obtain a trusted-authority timestamp to enforce the election deadline.

SERVER REQUIREMENTS
1. Decrypt the AES session key using its RSA private key.
2. Verify the voter signature and compare the ballot SHA-512 hash.
3. Validate the trusted timestamp and the voting period.
4. Aggregate encrypted votes WITHOUT decrypting individual Paillier ciphertexts.
5. Maintain a searchable encrypted index for constituency/time-range queries.
6. Decrypt ONLY the final encrypted totals, using threshold collaboration.

Write a MENU-DRIVEN program, apply ROLE-BASED ACCESS CONTROL, use suitable
storage, and show encryption/decryption, signatures, hashes, search and reports.

WHAT WE DO
- This file connects the small crypto functions in crypto_steps.py.
- .txt files contain readable JSON and are created HERE, beside this script.
- Client/server are separate functions/roles in one menu; no sockets are required
  because the paper specifies a client-server scenario but no network protocol.
- Role selection simulates login for the lab; it is not password authentication.
- A local timestamp-authority function signs time with its own separate RSA key.
- Two trustees supply actual Paillier partial decryptions of aggregate totals.

HOW TO ADAPT A BLENDED QUESTION
Replace the ballot fields with patient/report/transaction fields. Keep the order:
SERIALIZE -> HASH -> SIGN -> ENCRYPT -> STORE -> VERIFY -> PROCESS -> REPORT.
Change the named constants/marked lines only when the new question asks for it.
Do not add tampering prompts. Edit a marked received value/file yourself.

COUNTING NOTE
Adding IDs 1+2+3 cannot reveal how many votes each candidate received.
We encrypt the requested candidate ID AND an encrypted 0/1 count per candidate.
Those encrypted counts let Paillier compute the required candidate-wise tally.

LAB PRIVACY NOTE
The server temporarily decrypts the AES ballot to do the paper's hash comparison.
It never decrypts individual PAILLIER votes. This follows the demonstration flow;
it is not a claim that the server can never see plaintext ballot contents.
"""

from pathlib import Path
from datetime import datetime, timezone, timedelta
import json
import hashlib
import hmac
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import crypto_steps as crypto

# CHANGE THESE ONLY if the question changes the required algorithm sizes.
RSA_BITS = 4096
AES_BYTES = 32
ROOT = Path(__file__).resolve().parent

# RBAC: every menu action checks the current role before running its operation.
PERMISSIONS = {
    'admin': ['register', 'close'],
    'voter': ['cast'],
    'server': ['process', 'encrypted_tally', 'result'],
    'auditor': ['search'],
    'trustee1': ['partial'],
    'trustee2': ['partial'],
}



# ---------- WRITE / READ A TXT FILE IN THIS DIRECTORY ----------
# JSON is only a way to organize data INSIDE the .txt file; no database is needed.
def write_file(name, data):
    with (ROOT / name).open('w', encoding='utf-8') as file:
        json.dump(data, file, indent=4)



# ---------- READ THE SAVED DATA BACK FROM A TXT FILE ----------
def read_file(name):
    with (ROOT / name).open('r', encoding='utf-8') as file:
        return json.load(file)



# ---------- CANONICAL FILE CONTENTS FOR HASHING ----------
# Both sides must hash identical bytes. sort_keys avoids dictionary-order differences.
def ballot_bytes(ballot):
    text = json.dumps(ballot, sort_keys=True, separators=(',', ':'))
    return text.encode('utf-8')



# ---------- INITIALIZE THE ELECTION ONCE ----------
# All key files are .txt too. Existing files are reused after restarting the program.
# Public/private storage separation is represented by RBAC functions in this lab.
def setup_election():
    if (ROOT / 'settings.txt').exists():
        return

    print('First run: generating RSA-4096 and two-trustee Paillier keys...')
    election_private = RSA.generate(RSA_BITS)
    authority_private = RSA.generate(2048)
    n, share1, share2 = crypto.generate_threshold_keys()
    start = datetime.now(timezone.utc)
    deadline = start + timedelta(hours=24)
    # CHANGE THIS ONE TABLE to add/remove candidates or change their names.
    candidates = {'1': 'Candidate A', '2': 'Candidate B', '3': 'Candidate C'}

    write_file('settings.txt', {
        'start': start.isoformat(),
        'deadline': deadline.isoformat(),
        'open': True,
        # CHANGE candidate IDs/names here for another exam scenario.
        'candidates': candidates,
        'paillier_n': n,
    })
    write_file('election_keys.txt', {
        'private': election_private.export_key().decode('ascii'),
        'public': election_private.publickey().export_key().decode('ascii'),
        'search_key': get_random_bytes(32).hex(),
    })
    write_file('authority_keys.txt', {
        'private': authority_private.export_key().decode('ascii'),
        'public': authority_private.publickey().export_key().decode('ascii'),
    })
    write_file('trustee1.txt', {'share': share1})
    write_file('trustee2.txt', {'share': share2})
    write_file('users.txt', {
        'admin': 'admin', 'server': 'server', 'auditor': 'auditor',
        'trustee1': 'trustee1', 'trustee2': 'trustee2',
    })
    write_file('voters.txt', {})
    write_file('ballots.txt', [])
    write_file('search_index.txt', {})
    totals = {}

    for candidate in candidates:
        totals[candidate] = 1

    # Multiplicative identity 1 is the neutral element for an encrypted sum.
    write_file('encrypted_totals.txt', totals)
    write_file('partial_results.txt', {})
    write_file('results.txt', {})
    print('Created .txt files in', ROOT)
    print('Voting deadline:', deadline.isoformat())



# ---------- CHECK THE ROLE BEFORE AN OPERATION ----------
# CHANGE this table above if the question changes who may perform an operation.
def require_permission(username, action):
    users = read_file('users.txt')
    role = users.get(username)

    if action not in PERMISSIONS.get(role, []):
        raise PermissionError('This role cannot perform: ' + action)

    return role



# ---------- ADMIN: REGISTER A VOTER AND THEIR SIGNING KEY ----------
def register_voter(username, voter_id):
    require_permission(username, 'register')
    users = read_file('users.txt')
    voters = read_file('voters.txt')

    if not voter_id or voter_id in users:
        raise ValueError('Choose a new, nonempty voter ID.')

    public_key, private_key = crypto.generate_signature_keys()
    users[voter_id] = 'voter'
    voters[voter_id] = {'public_key': public_key, 'private_key': private_key}
    write_file('users.txt', users)
    write_file('voters.txt', voters)
    print('Registered voter:', voter_id)
    print('ElGamal public key:', public_key)



# ---------- TIMESTAMP AUTHORITY: ISSUE A SIGNED SUBMISSION TIME ----------
# The caller cannot supply a timestamp; the authority supplies and signs it.
def obtain_timestamp(digest):
    authority = read_file('authority_keys.txt')
    private_key = RSA.import_key(authority['private'])
    timestamp = datetime.now(timezone.utc).isoformat()
    signature = crypto.sign_timestamp(digest, timestamp, private_key)
    return timestamp, signature



# ---------- CLIENT: CREATE, HASH, SIGN AND ENCRYPT ONE BALLOT ----------
# This produces a pending packet in ballots.txt for the server role to process.
def cast_vote(username, constituency, candidate_id):
    require_permission(username, 'cast')
    settings = read_file('settings.txt')
    records = read_file('ballots.txt')
    voters = read_file('voters.txt')

    if not settings['open']:
        raise ValueError('Election is closed.')

    if candidate_id not in settings['candidates']:
        raise ValueError('Unknown candidate ID.')

    for record in records:
        if record['voter_id'] == username and record['status'] in ['pending', 'accepted']:
            raise ValueError('This voter already has a pending/accepted vote.')

    n = settings['paillier_n']
    encrypted_id = crypto.encrypt_vote(int(candidate_id), n)
    encrypted_counts = {}

    # ONE-HOT COUNTS: chosen candidate gets 1, all others get 0, all encrypted.
    for candidate in settings['candidates']:
        count = 0

        if candidate == candidate_id:
            count = 1

        encrypted_counts[candidate] = crypto.encrypt_vote(count, n)

    ballot = {
        'voter_id': username,
        'constituency': constituency,
        'candidate_id': candidate_id,
        'encrypted_id': encrypted_id,
        'encrypted_counts': encrypted_counts,
    }
    original = ballot_bytes(ballot)
    digest = crypto.hash_ballot(original)
    signature = crypto.sign_hash(digest, voters[username]['public_key'], voters[username]['private_key'])
    timestamp, time_signature = obtain_timestamp(digest)
    aes_key = get_random_bytes(AES_BYTES)
    iv, ciphertext = crypto.encrypt_ballot(original, aes_key)
    rsa_public = RSA.import_key(read_file('election_keys.txt')['public'])
    wrapped_key = crypto.wrap_aes_key(aes_key, rsa_public)

    # CHANGE HERE to simulate transmission tampering, keeping hash/signature unchanged.
    received_ciphertext = ciphertext
    # received_ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

    record = {
        'id': str(len(records) + 1),
        'voter_id': username,
        'hash': digest.hex(),
        'signature': signature,
        'timestamp': timestamp,
        'time_signature': time_signature.hex(),
        'iv': iv.hex(),
        'ciphertext': received_ciphertext.hex(),
        'wrapped_key': wrapped_key.hex(),
        'status': 'pending',
    }
    records.append(record)
    write_file('ballots.txt', records)
    print('Pending ballot ID:', record['id'])
    print('SHA-512:', record['hash'])
    print('AES-CBC ciphertext:', record['ciphertext'])
    print('RSA-wrapped AES key:', record['wrapped_key'])
    print('ElGamal signature:', signature)
    print('Paillier encrypted candidate ID:', encrypted_id)
    print('Paillier encrypted counts:', encrypted_counts)
    print('Authority timestamp:', timestamp)



# ---------- CREATE A SEARCH TOKEN ----------
# HMAC supports repeatable lookup without putting the constituency in the index.
def search_token(value):
    key = bytes.fromhex(read_file('election_keys.txt')['search_key'])
    token = hmac.new(key, value.encode('utf-8'), hashlib.sha256)
    return token.hexdigest()



# ---------- INDEX AN ACCEPTED BALLOT ----------
# The searchable index stores only IDs and timestamps, not plaintext choices.
def add_to_search_index(record, constituency):
    index = read_file('search_index.txt')
    token = search_token(constituency.lower())

    if token not in index:
        index[token] = []

    index[token].append({'id': record['id'], 'timestamp': record['timestamp']})
    write_file('search_index.txt', index)



# ---------- SERVER: VERIFY ONE RECEIVED PACKET ----------
# Unwrap key -> decrypt ballot -> compare hash -> verify voter and authority -> time.
def verify_received_ballot(record):
    settings = read_file('settings.txt')
    voters = read_file('voters.txt')
    rsa_private = RSA.import_key(read_file('election_keys.txt')['private'])
    aes_key = crypto.unwrap_aes_key(bytes.fromhex(record['wrapped_key']), rsa_private)
    received = crypto.decrypt_ballot(bytes.fromhex(record['ciphertext']), aes_key, bytes.fromhex(record['iv']))
    digest = crypto.hash_ballot(received)
    print('RSA unwrapped session key:', len(aes_key), 'bytes; AES-CBC ballot recovered.')
    print('Server recomputed SHA-512:', digest.hex())

    if digest.hex() != record['hash']:
        raise ValueError('SHA-512 mismatch: ballot changed.')

    public_key = voters[record['voter_id']]['public_key']

    if not crypto.verify_hash_signature(digest, record['signature'], public_key):
        raise ValueError('Voter signature invalid.')

    authority_public = RSA.import_key(read_file('authority_keys.txt')['public'])
    time_signature = bytes.fromhex(record['time_signature'])

    if not crypto.verify_timestamp(digest, record['timestamp'], time_signature, authority_public):
        raise ValueError('Timestamp authority signature invalid.')

    submitted = datetime.fromisoformat(record['timestamp'])
    start = datetime.fromisoformat(settings['start'])
    deadline = datetime.fromisoformat(settings['deadline'])

    if not start <= submitted <= deadline:
        raise ValueError('Vote outside the valid voting period.')

    ballot = json.loads(received.decode('utf-8'))

    if ballot['voter_id'] != record['voter_id']:
        raise ValueError('Voter ID mismatch.')

    return ballot



# ---------- SERVER: ACCEPT/REJECT PENDING BALLOTS AND UPDATE ENCRYPTED TOTALS ----------
# We multiply encrypted 0/1 values. We NEVER decrypt a Paillier vote here.
def process_pending_ballots(username):
    require_permission(username, 'process')
    settings = read_file('settings.txt')
    records = read_file('ballots.txt')
    totals = read_file('encrypted_totals.txt')

    if not settings['open']:
        raise ValueError('Election closed; totals are frozen.')

    for record in records:
        if record['status'] != 'pending':
            continue

        try:
            ballot = verify_received_ballot(record)

            for candidate in settings['candidates']:
                totals[candidate] = crypto.add_encrypted_votes(
                    totals[candidate], ballot['encrypted_counts'][candidate], settings['paillier_n'])

            record['status'] = 'accepted'
            add_to_search_index(record, ballot['constituency'])
            print('Accepted ballot', record['id'], ': hash, signature and timestamp verified.')
        except (ValueError, KeyError, TypeError) as error:
            record['status'] = 'rejected'
            record['reason'] = str(error)
            print('Rejected ballot', record['id'], ':', error)

    write_file('ballots.txt', records)
    write_file('encrypted_totals.txt', totals)



# ---------- AUDITOR: SEARCH CONSTITUENCY AND OPTIONAL TIME RANGE ----------
# Only matching IDs and signed times are displayed, never ballot contents.
def search_ballots(username, constituency, start_text='', end_text=''):
    require_permission(username, 'search')
    index = read_file('search_index.txt')
    matches = []

    if constituency:
        matches = index.get(search_token(constituency.lower()), [])
    else:
        # Empty constituency allows a time-range-only search across all tokens.
        for posting_list in index.values():
            matches.extend(posting_list)
    results = []

    for match in matches:
        submitted = datetime.fromisoformat(match['timestamp'])

        if start_text and submitted < datetime.fromisoformat(start_text):
            continue

        if end_text and submitted > datetime.fromisoformat(end_text):
            continue

        results.append(match)

    return results



# ---------- SERVER: DISPLAY ONLY ENCRYPTED TOTALS ----------
def show_encrypted_tally(username):
    require_permission(username, 'encrypted_tally')
    print(json.dumps(read_file('encrypted_totals.txt'), indent=4))



# ---------- ADMIN: END THE ELECTION ----------
# Process pending packets before closing; afterward no totals may change.
def close_election(username):
    require_permission(username, 'close')
    records = read_file('ballots.txt')

    for record in records:
        if record['status'] == 'pending':
            raise ValueError('Server must process pending ballots first.')

    settings = read_file('settings.txt')
    settings['open'] = False
    write_file('settings.txt', settings)
    print('Election closed. Each trustee may now partially decrypt the totals.')



# ---------- TRUSTEE: CREATE ONLY YOUR PARTIAL DECRYPTION ----------
# This action is blocked before election close. Raw shares are not sent to the server.
def submit_partial_results(username):
    role = require_permission(username, 'partial')
    settings = read_file('settings.txt')

    if settings['open']:
        raise ValueError('Close the election before partial decryption.')

    share = read_file(role + '.txt')['share']
    totals = read_file('encrypted_totals.txt')
    contributions = read_file('partial_results.txt')
    contributions[role] = {}

    for candidate, ciphertext in totals.items():
        contributions[role][candidate] = crypto.partial_decrypt(ciphertext, share, settings['paillier_n'])

    write_file('partial_results.txt', contributions)
    print(role, 'submitted partial results:', contributions[role])



# ---------- SERVER: COMBINE BOTH TRUSTEES AND REPORT FINAL COUNTS ----------
# The server has partial results, not either raw secret share.
def publish_result(username):
    require_permission(username, 'result')
    settings = read_file('settings.txt')
    partials = read_file('partial_results.txt')

    if settings['open']:
        raise ValueError('Election is still open.')

    if 'trustee1' not in partials or 'trustee2' not in partials:
        raise ValueError('Both trustee contributions are required.')

    results = {}

    for candidate, name in settings['candidates'].items():
        count = crypto.combine_partial_results(
            partials['trustee1'][candidate], partials['trustee2'][candidate], settings['paillier_n'])
        results[candidate] = {'name': name, 'votes': count}
        print(candidate, name, '->', count, 'votes')

    write_file('results.txt', results)



# ---------- RBAC MENU ----------
# To demonstrate both sides, switch user between voter/server/auditor/trustees.
# CHANGE the data inputs below for another scenario; crypto functions stay reusable.
def main():
    setup_election()
    username = 'admin'

    while True:
        users = read_file('users.txt')
        print('\nCurrent user:', username, '| Role:', users[username])
        print('1. Switch user (admin/server/auditor/trustee1/trustee2 or registered voter)')
        print('2. Register voter                 [admin]')
        print('3. Cast vote                      [voter]')
        print('4. Verify/process pending ballots [server]')
        print('5. Search constituency/time range [auditor]')
        print('6. Show encrypted tally           [server]')
        print('7. Close election                 [admin]')
        print('8. Submit partial decryption      [trustee1 / trustee2]')
        print('9. Publish final result           [server; needs both trustees]')
        print('0. Exit')
        choice = input('Choice: ').strip()

        try:
            if choice == '0':
                break
            elif choice == '1':
                selected = input('User ID: ').strip()

                if selected not in users:
                    raise ValueError('Unknown user. Admin must register voters first.')

                username = selected
            elif choice == '2':
                register_voter(username, input('New voter ID: ').strip())
            elif choice == '3':
                print('Candidates:', read_file('settings.txt')['candidates'])
                constituency = input('Constituency ID: ').strip()
                candidate = input('Candidate ID: ').strip()
                cast_vote(username, constituency, candidate)
            elif choice == '4':
                process_pending_ballots(username)
            elif choice == '5':
                constituency = input('Constituency ID [Enter=all for time-only search]: ').strip()
                print('Time format: 2026-10-23T10:00:00+00:00; Enter skips a boundary.')
                start = input('From time: ').strip()
                end = input('To time: ').strip()
                print('Matching ballot IDs/times:', search_ballots(username, constituency, start, end))
            elif choice == '6':
                show_encrypted_tally(username)
            elif choice == '7':
                close_election(username)
            elif choice == '8':
                submit_partial_results(username)
            elif choice == '9':
                publish_result(username)
            else:
                print('Choose a listed menu option.')
        except (ValueError, PermissionError, KeyError, TypeError) as error:
            print('Cannot perform action:', error)



if __name__ == '__main__':
    main()
