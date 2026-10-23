# ============================================================================
# EXAM SWAP GUIDE — CLIENT.PY (COMMENTED EXAMPLES; NO EXECUTION)
# ============================================================================
# Existing PYQ remains SHA-512 + AES-256-CBC + RSA-4096 + ElGamal + Paillier.
# To adapt a DIFFERENT question, import the helper you need and replace the
# matching step. Do NOT enable all alternatives simultaneously.
#
# HASH SWAP:
#   from crypto_helpers import hash_bytes
#   digest = hash_bytes(data, 'sha256')   # or 'md5', 'sha1', 'sha512'
#
# SYMMETRIC CIPHER SWAP (packet format includes mode and IV/nonce):
#   from crypto_helpers import key_for, encrypt_data
#   key = key_for('AES', 128)              # 128 / 192 / 256
#   packet = encrypt_data(data, key, 'AES', 'GCM')
#   key = key_for('DES')                   # DES: 8-byte key
#   packet = encrypt_data(data, key, 'DES', 'CBC')
#   key = key_for('3DES')                  # Triple DES
#   packet = encrypt_data(data, key, '3DES', 'CTR')
#   # AES modes: ECB / CBC / CTR / GCM; DES/3DES: ECB / CBC / CTR.
#   # ECB is insecure; CBC requires separate authentication.
#
# DIGITAL SIGNATURE SWAP:
#   from crypto_helpers import rsa_make_keys, rsa_sign_bytes
#   signer_pub, signer_priv = rsa_make_keys(2048)
#   signature_hex = rsa_sign_bytes(data, signer_priv)   # RSA-PSS/SHA512
#   from crypto_helpers import ecc_make_keys, ecc_sign
#   ecc_pub, ecc_priv = ecc_make_keys()
#   signature_hex = ecc_sign(data, ecc_priv)            # ECDSA/SHA256
#   from crypto_helpers import schnorr_make_keys, schnorr_sign
#   schnorr_pub, schnorr_priv = schnorr_make_keys()
#   signature = schnorr_sign(data, schnorr_pub, schnorr_priv)  # toy Schnorr
#
# CLASSICAL CIPHER SWAP (Lab 1; text instead of bytes):
#   from crypto_helpers import caesar_encrypt, affine_encrypt, vigenere_encrypt
#   encrypted_text = caesar_encrypt('HELLO', 3)
#   encrypted_text = affine_encrypt('HELLO', 5, 8)
#   encrypted_text = vigenere_encrypt('HELLO', 'KEY')
#
# HOMOMORPHIC: Paillier encrypt integers; use one_hot_vote() for candidates.
# FILE HASH: from crypto_helpers import write_hash_txt
#            write_hash_txt('ballots.txt', 'hashes.txt', 'sha512')
# ============================================================================

"""
CLIENT.PY - Voter's machine
Run AFTER server.py: python client.py
Menu follows PYQ client-side steps and then server-side results.
Input is ballots.txt in SAME folder, e.g. 2,Udupi
"""
import json, socket
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from crypto_helpers import (
    to_bytes, sha512, aes_encrypt, rsa_encrypt,
    elgamal_keys, elgamal_sign, paillier_encrypt,
    send_json, recv_json
)
BASE = Path(__file__).resolve().parent
INPUT = BASE / "ballots.txt"
REPORT = BASE / "client_report.txt"
HOST, PORT = "127.0.0.1", 5055
setup = None
next_id = 1

def ask_server(request):
    """Actual TCP client: send JSON request and read JSON response."""
    with socket.create_connection((HOST, PORT), timeout=20) as conn:
        send_json(conn, request)
        return recv_json(conn)

def read_ballots():
    """STEP 1: Read .txt lines in 'candidate,Constituency' format."""
    ballots = []
    for line in INPUT.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        candidate, place = line.split(",", 1)
        candidate = int(candidate.strip())
        if candidate not in (1, 2, 3):
            raise ValueError("Candidate must be 1, 2, or 3")
        ballots.append((candidate, place.strip()))
    return ballots

def get_setup():
    """STEP 2: Obtain EC public keys + timestamp ticket from server."""
    global setup
    setup = ask_server({"cmd": "setup"})
    print("EC public keys received. Deadline:", setup["deadline"])

# ================================================================
# CLIENT PYQ STEPS 1 TO 7: PREPARE ONE VOTER'S BALLOT
# This function returns a dictionary (packet) for the server.
# You can copy this whole function for similar hospital/bank PYQs.
# ================================================================
def prepare_packet(candidate, place, ballot_id):
    """STEP 3: Build ballot -> SHA512 -> AES -> RSA -> Paillier -> ElGamal."""
    if setup is None:
        get_setup()
    # STEP 1: Create a ballot (dictionary = data with named fields).
    # The three values are read from ballots.txt by read_ballots().
    ballot = {"id": ballot_id, "candidate": candidate, "constituency": place}

    print("\nSTEP 1: Ballot created:", ballot)
    # JSON is a way to turn the dictionary into text.
    # .encode() inside to_bytes turns text into bytes for encryption.
    data = to_bytes(ballot)
    # STEP 2: Hash = fingerprint. NOT encryption, cannot be decrypted.
    # SHA-512 gives a 128-character hexadecimal hash.
    digest = sha512(data)
    print("STEP 2: SHA-512 hash:", digest)
    # STEP 3: Generate random secret key for AES.
    # 256 bits / 8 = 32 bytes. For AES-128, use 16 bytes.
    aes_key = get_random_bytes(32)
    # AES-CBC encrypts the ballot; it also needs an IV (generated in helper).
    encrypted_ballot = aes_encrypt(data, aes_key)
    print("STEP 3: AES-CBC encrypted ballot:", encrypted_ballot)
    rsa_pub = RSA.import_key(setup["rsa_public_pem"].encode())
    # STEP 4: Encrypt the AES key with Election Commission PUBLIC RSA key.
    # The server will recover it using its PRIVATE RSA key.
    encrypted_key = rsa_encrypt(aes_key, rsa_pub)
    print("STEP 4: RSA-encrypted AES key (first 60 chars):", encrypted_key[:60])
    paillier_pub = tuple(setup["paillier_public"])
    # STEP 5: One-hot vote representation.
    # Candidate 1 -> [1,0,0]; candidate 2 -> [0,1,0]; candidate 3 -> [0,0,1].
    one_hot = [0, 0, 0]
    one_hot[candidate - 1] = 1
    print("STEP 5: One-hot vote:", one_hot)
    # Encrypt each number separately with Paillier public key.
    encrypted_vote = []
    for number in one_hot:
        encrypted_number = paillier_encrypt(number, paillier_pub)
        encrypted_vote.append(encrypted_number)
    print("STEP 5: Paillier encrypted all three vote positions")
    # Demo ElGamal keys, freshly generated for this ballot.
    # STEP 6: ElGamal public/private signing keys (educational example).
    sign_pub, sign_priv = elgamal_keys()
    packet = {"ballot": encrypted_ballot, "rsa_key": encrypted_key,
              "hash": digest, "vote": encrypted_vote,
              "timestamp": setup["timestamp"],
              "sign_public": list(sign_pub)}
    # Sign all the packet fields (including ciphertext and timestamp).
    # This detects tampering with the transmitted fields.
    packet["signature"] = elgamal_sign(to_bytes(packet), sign_pub, sign_priv)
    print("STEP 6: ElGamal signature created")
    print("STEP 7: Server-issued timestamp attached:", setup["timestamp"]["time"])
    return packet

def submit(candidate, place):
    """STEP 4: Send encrypted packet to Election Commission over TCP."""
    global next_id
    packet = prepare_packet(candidate, place, next_id)
    # STEP 8: Send packet using a TCP socket to server.py.
    response = ask_server({"cmd": "submit", "packet": packet})
    with REPORT.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"ballot_id": next_id, "result": response}) + "\n")
    print("Server reply:", response)
    next_id += 1
    return response

def tamper_demo():
    """STEP 7: Change ciphertext after signing; server must reject."""
    global next_id
    packet = prepare_packet(1, "Udupi", next_id)
    original = packet["ballot"]["ct"]
    packet["ballot"]["ct"] = ("00" if original[:2] != "00" else "ff") + original[2:]
    print("Tampered server reply:",
          ask_server({"cmd": "submit", "packet": packet}))
    next_id += 1

def main():
    while True:
        print("""
======== E-VOTING PYQ: CLIENT MENU ========
1. STEP 1 - Read ballots.txt (candidate, constituency)
2. STEP 2 - Get RSA/Paillier public keys + trusted timestamp
3. STEP 3-4 - Encrypt, hash, sign and SEND ONE ballot
4. STEP 3-4 - Encrypt, hash, sign and SEND ALL TXT ballots
5. STEP 5 - SERVER searchable index: search constituency
6. STEP 6 - SERVER Paillier encrypted tally
7. STEP 7 - SERVER audit log
8. STEP 8 - Tampering test (must be rejected)
0. Exit
==========================================
""")
        choice = input("Choose: ").strip()
        try:
            if choice == "1":
                print("Input file:", INPUT)
                for row in read_ballots(): print(row)
            elif choice == "2":
                get_setup()
            elif choice == "3":
                c = int(input("Candidate 1/2/3: "))
                place = input("Constituency: ")
                submit(c, place)
            elif choice == "4":
                for c, place in read_ballots(): submit(c, place)
            elif choice == "5":
                place = input("Constituency to search: ")
                print(ask_server({"cmd": "search", "place": place}))
            elif choice == "6":
                print(ask_server({"cmd": "tally"}))
            elif choice == "7":
                result = ask_server({"cmd": "audit"})
                print("\n".join(result.get("lines", [])))
            elif choice == "8":
                tamper_demo()
            elif choice == "0":
                break
            else:
                print("Invalid menu option")
        except Exception as exc:
            print("ERROR:", exc)

if __name__ == "__main__":
    main()
