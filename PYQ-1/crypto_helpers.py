"""
INFORMATION SECURITY LAB - EASY E-VOTING PYQ (EDUCATIONAL DEMO)

QUESTION SUMMARY (03-11-2025):
CLIENT: create ballot with candidate + constituency; SHA-512 hash; AES-256-CBC
encrypt ballot; RSA-4096 encrypt AES key; ElGamal sign SHA-512 hash;
Paillier encrypt vote; attach trusted timestamp.
SERVER: RSA decrypt AES key; verify hash + signature; check timestamp;
homomorphically tally without decrypting votes; searchable index by constituency
or time; final threshold decryption; RBAC; client-server; save reports.

IMPORTANT HONEST LIMITATIONS:
1) This classroom program DECRYPTS the AES ballot at the server, so the server
   can see individual votes. The PYQ's strong ballot secrecy is NOT achieved.
2) Timestamp authority is SIMULATED with HMAC, not a separate trusted service.
3) ElGamal signatures use small educational parameters, not production security.
4) SSE leaks search/access patterns and uses plaintext ballot IDs.
5) Paillier tally uses one private key. THRESHOLD DECRYPTION IS NOT IMPLEMENTED.
6) No voter identity registration, duplicate-vote prevention, ZK validity proofs,
   persistent keys or production-grade transport authentication.

INSTALL: python -m pip install pycryptodome
RUN:     python evoting_easy.py
CLIENT-SERVER: menu option 1 runs both sides using localhost sockets.
"""

import json, hashlib, hmac, secrets, socket, struct, threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from math import gcd, lcm
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse

OUT = Path("evoting_outputs")
OUT.mkdir(exist_ok=True)

# --------------------- GENERAL HELPERS ---------------------
def to_bytes(obj):
    """Convert dictionary to reproducible UTF-8 bytes, ready for hashing/signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

def save(name, value):
    """Write JSON/text output to a file; useful for the exam record."""
    path = OUT / name
    path.write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")
    print("Saved:", path)

def sha512(data):
    """SHA-512: bytes -> 128-character hexadecimal fingerprint."""
    return hashlib.sha512(data).hexdigest()

# --------------------- LAB 2: AES-256-CBC ---------------------
def aes_encrypt(data, key):
    """Encrypt bytes using 32-byte AES-256 key and fresh 16-byte IV."""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(data, 16))
    return {"iv": iv.hex(), "ct": ct.hex()}

def aes_decrypt(packet, key):
    """Reverse AES-CBC using original IV; unpad recovered plaintext."""
    iv = bytes.fromhex(packet["iv"])
    ct = bytes.fromhex(packet["ct"])
    return unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct), 16)

# --------------------- LAB 3: RSA-4096 ---------------------
def rsa_keys():
    """Generate Election Commission RSA public/private key pair."""
    private = RSA.generate(4096)
    return private.publickey(), private

def rsa_encrypt(data, public):
    """Encrypt AES session key using EC's PUBLIC key (OAEP)."""
    return PKCS1_OAEP.new(public).encrypt(data).hex()

def rsa_decrypt(cipher_hex, private):
    """Recover AES key using EC's PRIVATE key."""
    return PKCS1_OAEP.new(private).decrypt(bytes.fromhex(cipher_hex))

# --------------------- LAB 6: ELGAMAL SIGNATURE ---------------------
def elgamal_keys():
    """Create small educational ElGamal signature keys (p,g,y), private x."""
    p = getPrime(256)
    g = 2
    x = secrets.randbelow(p - 3) + 2
    y = pow(g, x, p)
    return (p, g, y), x

def elgamal_sign(data, public, private):
    """Sign SHA-512 integer: r=g^k mod p; s=(H-x*r)*k^-1 mod (p-1)."""
    p, g, y = public
    h = int.from_bytes(hashlib.sha512(data).digest(), "big") % (p - 1)
    while True:
        k = secrets.randbelow(p - 3) + 2
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - private * r) * inverse(k, p - 1)) % (p - 1)
    return [r, s]

def elgamal_verify(data, signature, public):
    """Verify g^H == y^r * r^s (mod p); returns True/False."""
    p, g, y = public
    r, s = signature
    if not (0 < r < p and 0 <= s < p - 1):
        return False
    h = int.from_bytes(hashlib.sha512(data).digest(), "big") % (p - 1)
    return pow(g, h, p) == (pow(y, r, p) * pow(r, s, p)) % p

# --------------------- LAB 7: PAILLIER ---------------------
def paillier_keys():
    """Generate educational Paillier keys: public (n,g), private (lambda,mu)."""
    p, q = getPrime(256), getPrime(256)
    while p == q:
        q = getPrime(256)
    n = p * q
    g = n + 1
    lam = lcm(p - 1, q - 1)
    mu = inverse(lam, n)
    return (n, g), (lam, mu)

def paillier_encrypt(m, public):
    """Encrypt integer 0 <= m < n with random r."""
    n, g = public
    if not 0 <= m < n:
        raise ValueError("Number outside Paillier range")
    while True:
        r = secrets.randbelow(n - 1) + 1
        if gcd(r, n) == 1:
            break
    return (pow(g, m, n*n) * pow(r, n, n*n)) % (n*n)

def paillier_add(ciphertexts, public):
    """Multiply ciphertexts mod n² to ADD their plaintext values."""
    n, g = public
    total = 1
    for c in ciphertexts:
        total = (total * c) % (n*n)
    return total

def paillier_decrypt(c, public, private):
    """Decrypt aggregate only: L(c^lambda mod n²)*mu mod n."""
    n, g = public
    lam, mu = private
    u = pow(c, lam, n*n)
    return (((u - 1) // n) * mu) % n

# --------------------- LAB 8: SIMPLE SEARCHABLE INDEX ---------------------
def search_token(word, search_key):
    """HMAC-SHA256 produces the same token for the same normalized keyword."""
    return hmac.new(search_key, word.lower().encode(), hashlib.sha256).hexdigest()

def add_to_index(index, ballot_id, constituency, date, search_key):
    """Map protected search tokens to ballot IDs (educational SSE)."""
    for term in ("place:" + constituency.lower(), "date:" + date):
        index.setdefault(search_token(term, search_key), []).append(ballot_id)

def search_index(index, term, search_key):
    """Search without putting the plaintext keyword directly in index keys."""
    return index.get(search_token(term, search_key), [])

# --------------------- TIMESTAMP AND ROLE PERMISSIONS ---------------------
def issue_timestamp(authority_secret):
    """SIMULATED trusted authority signs its current UTC time using HMAC."""
    stamp = datetime.now(timezone.utc).isoformat()
    mac = hmac.new(authority_secret, stamp.encode(), hashlib.sha256).hexdigest()
    return {"time": stamp, "mac": mac}

def check_timestamp(ticket, authority_secret, deadline):
    """Verify HMAC + reject timestamps after election deadline or far in future."""
    stamp = ticket["time"]
    expected = hmac.new(authority_secret, stamp.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, ticket["mac"]):
        return False
    t = datetime.fromisoformat(stamp)
    now = datetime.now(timezone.utc)
    return t <= deadline and t <= now + timedelta(seconds=30)

PERMISSIONS = {
    "voter": {"submit"},
    "officer": {"submit", "search", "tally"},
    "auditor": {"audit"},
}
def allowed(role, action):
    """Role-based access: action must belong to role's permission set."""
    return action in PERMISSIONS.get(role, set())

# --------------------- CLIENT: PREPARE ONE BALLOT ---------------------
def make_ballot(ballot_id, candidate, constituency, keys):
    """Run every CLIENT requirement and return JSON-compatible packet."""
    # 1. Make the plaintext ballot. The server can see this after AES decrypt.
    ballot = {"id": ballot_id, "candidate": candidate, "constituency": constituency}
    raw = to_bytes(ballot)

    # 2. SHA-512 fingerprint; save hash in the packet.
    digest = sha512(raw)

    # 3. AES-256-CBC encrypt ballot; RSA-4096 wrap AES key.
    aes_key = get_random_bytes(32)
    encrypted_ballot = aes_encrypt(raw, aes_key)
    wrapped_key = rsa_encrypt(aes_key, keys["rsa_public"])

    # 4. Paillier: one-hot vote vector, e.g. candidate 2 -> [0,1,0].
    #    This is essential for counting votes per candidate.
    vector = [int(i == candidate - 1) for i in range(3)]
    encrypted_vote = [paillier_encrypt(v, keys["paillier_public"]) for v in vector]

    # 5. Timestamp authority ticket (simulated).
    ticket = issue_timestamp(keys["timestamp_secret"])

    # 6. Sign the ENTIRE submitted package, including SHA-512 and timestamp.
    packet = {
        "ballot": encrypted_ballot, "rsa_key": wrapped_key,
        "hash": digest, "vote": encrypted_vote, "timestamp": ticket,
        "voter_id": "voter_" + str(ballot_id)
    }
    packet["signature"] = elgamal_sign(to_bytes(packet), keys["sign_public"], keys["sign_private"])
    return packet

# --------------------- SERVER: VERIFY AND ACCEPT ---------------------
def verify_ballot(packet, keys, deadline):
    """SERVER: check role, timestamp, signature, decrypt AES, compare SHA-512."""
    if not allowed("voter", "submit"):
        raise ValueError("Role denied")
    if not check_timestamp(packet["timestamp"], keys["timestamp_secret"], deadline):
        raise ValueError("Timestamp invalid")
    unsigned = {k:v for k,v in packet.items() if k != "signature"}
    if not elgamal_verify(to_bytes(unsigned), packet["signature"], keys["sign_public"]):
        raise ValueError("ElGamal signature invalid")
    aes_key = rsa_decrypt(packet["rsa_key"], keys["rsa_private"])
    raw = aes_decrypt(packet["ballot"], aes_key)
    if sha512(raw) != packet["hash"]:
        raise ValueError("SHA-512 mismatch")
    ballot = json.loads(raw)
    if ballot["candidate"] not in (1,2,3):
        raise ValueError("Invalid candidate")
    if len(packet["vote"]) != 3:
        raise ValueError("Invalid encrypted vote vector length")
    # IMPORTANT: this does NOT prove encrypted vector matches plaintext candidate.
    return ballot

# --------------------- SIMPLE JSON OVER TCP ---------------------
def send_json(sock, data):
    """Send 4-byte message length followed by UTF-8 JSON bytes."""
    raw = to_bytes(data)
    sock.sendall(struct.pack("!I", len(raw)) + raw)

def read_exact(sock, count):
    """TCP recv may return partial bytes: repeat until requested size arrives."""
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        if not part:
            raise ConnectionError("Connection closed")
        result += part
    return result

def recv_json(sock):
    """Receive complete length-prefixed JSON message."""
    count = struct.unpack("!I", read_exact(sock, 4))[0]
    if count > 2_000_000:
        raise ValueError("Packet too large")
    return json.loads(read_exact(sock, count))

# --------------------- RUN THE COMPLETE EXAM DEMO ---------------------
def demo(use_sockets=False):
    """Execute 5 ballots, search, tally, audit, and optional localhost TCP."""
    print("\nGENERATING KEYS (RSA-4096 may take a few seconds)...")
    rsa_pub, rsa_priv = rsa_keys()
    sign_pub, sign_priv = elgamal_keys()
    pai_pub, pai_priv = paillier_keys()
    keys = {
        "rsa_public": rsa_pub, "rsa_private": rsa_priv,
        "sign_public": sign_pub, "sign_private": sign_priv,
        "paillier_public": pai_pub, "paillier_private": pai_priv,
        "timestamp_secret": get_random_bytes(32)
    }
    deadline = datetime.now(timezone.utc) + timedelta(minutes=10)
    search_key = get_random_bytes(32)
    index, accepted, audit = {}, [], []

    # Fixed example: candidate totals [2,2,1], all from Udupi.
    choices = [1, 2, 2, 3, 1]
    packets = [make_ballot(i+1, c, "Udupi", keys) for i,c in enumerate(choices)]

    def receive_and_process(packet):
        try:
            ballot = verify_ballot(packet, keys, deadline)
            accepted.append(packet)
            date = packet["timestamp"]["time"][:10]
            add_to_index(index, ballot["id"], ballot["constituency"], date, search_key)
            audit.append({"event":"accepted", "ballot_id":ballot["id"], "date":date})
            return {"ok": True, "ballot_id": ballot["id"]}
        except Exception as e:
            audit.append({"event":"rejected", "reason":str(e)})
            return {"ok": False, "reason":str(e)}

    if use_sockets:
        # A local server thread receives each packet via actual TCP sockets.
        ready = threading.Event()
        def server():
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 5055))
                listener.listen(5)
                ready.set()
                for _ in packets:
                    conn, _ = listener.accept()
                    with conn:
                        incoming = recv_json(conn)
                        send_json(conn, receive_and_process(incoming))
        worker = threading.Thread(target=server)
        worker.start()
        ready.wait()
        for packet in packets:
            with socket.create_connection(("127.0.0.1", 5055)) as client:
                send_json(client, packet)
                print("SERVER REPLY:", recv_json(client))
        worker.join()
    else:
        for packet in packets:
            print("SERVER REPLY:", receive_and_process(packet))

    # Paillier aggregation: server combines encrypted votes, not plaintext votes.
    if allowed("officer", "tally"):
        encrypted_totals = [
            paillier_add([p["vote"][i] for p in accepted], pai_pub)
            for i in range(3)
        ]
        totals = [paillier_decrypt(c, pai_pub, pai_priv) for c in encrypted_totals]
        print("FINAL CANDIDATE TOTALS:", totals)

    if allowed("officer", "search"):
        print("SEARCH place:udupi ->", search_index(index, "place:udupi", search_key))

    # Tamper test: modify signed ciphertext without updating signature.
    changed = json.loads(json.dumps(packets[0]))
    changed["ballot"]["ct"] = "00" + changed["ballot"]["ct"][2:]
    print("TAMPERING TEST:", receive_and_process(changed))

    save("audit.json", audit)
    save("ballot_hashes.txt", [p["hash"] for p in accepted])
    save("encrypted_ballots.json", accepted)
    save("results.json", {"totals":totals, "accepted":len(accepted)})

    print("\nLIMITATIONS: no true threshold decryption, trusted external TSA,")
    print("zero-knowledge ballot proof, or voter privacy against server.")

# --------------------- MENU ---------------------
def main():
    while True:
        print("\n========== E-VOTING PYQ MENU ==========")
        print("1. Full PYQ demo (one program)")
        print("2. Full PYQ demo with real localhost TCP sockets")
        print("3. Explain algorithm selection")
        print("0. Exit")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            demo(False)
        elif choice == "2":
            demo(True)
        elif choice == "3":
            print("SHA512=hash; AES=CBC ballot; RSA=wrap AES key;")
            print("ElGamal=signature; Paillier=encrypted sum;")
            print("HMAC=SSE tokens and simulated timestamp; RBAC=permissions;")
            print("Sockets=send/receive JSON; threshold=NOT implemented.")
        elif choice == "0":
            break
        else:
            print("Choose 0, 1, 2, or 3.")

if __name__ == "__main__":
    main()


# ============================================================================
# COMPLETE LAB 1–8 LIBRARY — ADDITIONAL EXERCISES FROM THE UPLOADED MANUALS
# ============================================================================
# These labN_* functions are additional exercise-level helpers.
# The beginner-friendly names below are the preferred imports for client/server.
# Original e-voting helpers above remain UNCHANGED for compatibility.
# Some functions are TOY mathematics demonstrations (not production security).
#
# LAB 1: Caesar/additive, multiplicative, affine, Vigenere, autokey,
#        Playfair, Hill, transposition, cryptanalysis/brute force.
# LAB 2: DES, 3DES, AES-128/192/256, ECB/CBC/CTR/GCM, timings.
# LAB 3: RSA, ElGamal, ECC ECDH hybrid, Diffie-Hellman, benchmarks.
# LAB 4: Rabin, key registry, RBAC, weak RSA factoring.
# LAB 5: custom 5381 hash, MD5, SHA-1/256/512, files, sockets.
# LAB 6: RSA-PSS, ElGamal and Schnorr digital signatures.
# LAB 7: Paillier, textbook RSA/ElGamal homomorphism, benchmarks.
# LAB 8: AES searchable index, Paillier-encrypted IDs, GPG/Snort commands.
# ============================================================================
import math, time, re, shutil, subprocess, threading
from secrets import randbelow
from Crypto.Cipher import DES, DES3
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256, SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.Signature import pss, DSS
from Crypto.Util.number import isPrime
ROOT = Path(__file__).resolve().parent
(ROOT / 'data').mkdir(exist_ok=True)
OUT = ROOT / 'outputs'
OUT.mkdir(exist_ok=True)
if not (ROOT / 'data' / 'input.txt').exists():
    (ROOT / 'data' / 'input.txt').write_text('Information Security Lab sample\n', encoding='utf-8')

def save_text(name, value):
    """Write an exam result to outputs/<name>."""
    target = OUT / name
    target.write_text(str(value), encoding='utf-8')
    return target

def load_text(name):
    """Read input TXT from data/<name>."""
    return (ROOT / 'data' / name).read_text(encoding='utf-8')

def show(title, value):
    print(title, value)

def benchmark(fn, repeat=10):
    start = time.perf_counter()
    for _ in range(repeat): fn()
    return (time.perf_counter()-start)/repeat
def lab1_clean(s):
    """Keep letters A–Z and remove spaces/punctuation as manual instructs."""
    return ''.join((c for c in s.upper() if 'A' <= c <= 'Z'))


def lab1_affine(text, a=1, b=0, decrypt=False):
    """Encrypt y=(a*x+b)%26; decrypt x=a^-1*(y-b)%26."""
    if gcd(a, 26) != 1:
        raise ValueError('a must be coprime to 26')
    inv = pow(a, -1, 26)
    return ''.join((chr(65 + (inv * (ord(c) - 65 - b) % 26 if decrypt else (a * (ord(c) - 65) + b) % 26)) for c in lab1_clean(text)))


def lab1_vigenere(text, key, decrypt=False):
    """Use successive letters of repeating keyword as shifts."""
    t, k = (lab1_clean(text), lab1_clean(key))
    return ''.join((chr(65 + (ord(c) - 65 + (-1 if decrypt else 1) * (ord(k[i % len(k)]) - 65)) % 26) for i, c in enumerate(t)))


def lab1_autokey(text, seed=7, decrypt=False):
    """Start with numerical seed; extend key using original plaintext letters."""
    ks = [seed]
    result = []
    for c in lab1_clean(text):
        x = ord(c) - 65
        k = ks[len(result)]
        p = (x - k) % 26 if decrypt else x
        v = p if decrypt else (x + k) % 26
        result.append(chr(65 + v))
        ks.append(p)
    return ''.join(result)


def lab1_playfair_square(key):
    """Build 5x5 Playfair square, combining I/J."""
    letters = ''
    for c in lab1_clean(key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ').replace('J', 'I'):
        if c not in letters:
            letters += c
    return letters


def lab1_playfair_pairs(text):
    """Split plaintext into digraphs, inserting X between repeated letters."""
    t = lab1_clean(text).replace('J', 'I')
    pairs = []
    i = 0
    while i < len(t):
        a = t[i]
        b = t[i + 1] if i + 1 < len(t) else 'X'
        if a == b:
            b = 'X' if a != 'X' else 'Q'
            i += 1
        else:
            i += 2
        pairs.append((a, b))
    return pairs


def lab1_playfair(text, key='GUIDANCE', decrypt=False):
    """Apply Playfair same-row, same-column, rectangle substitution rules."""
    sq = lab1_playfair_square(key)
    pairs = [(lab1_clean(text).replace('J', 'I')[i], lab1_clean(text).replace('J', 'I')[i + 1]) for i in range(0, len(lab1_clean(text)), 2)] if decrypt else lab1_playfair_pairs(text)
    out = ''
    step = -1 if decrypt else 1
    for a, b in pairs:
        ia, ib = (sq.index(a), sq.index(b))
        ra, ca = divmod(ia, 5)
        rb, cb = divmod(ib, 5)
        if ra == rb:
            out += sq[ra * 5 + (ca + step) % 5] + sq[rb * 5 + (cb + step) % 5]
        elif ca == cb:
            out += sq[(ra + step) % 5 * 5 + ca] + sq[(rb + step) % 5 * 5 + cb]
        else:
            out += sq[ra * 5 + cb] + sq[rb * 5 + ca]
    return out


def lab1_hill(text, key=((3, 3), (2, 7)), decrypt=False):
    """2x2 Hill cipher: multiply each 2-letter vector by matrix modulo 26."""
    a, b = key[0]
    c, d = key[1]
    det = (a * d - b * c) % 26
    if gcd(det, 26) != 1:
        raise ValueError('Key matrix not invertible modulo 26')
    if decrypt:
        z = pow(det, -1, 26)
        a, b, c, d = (d * z % 26, -b * z % 26, -c * z % 26, a * z % 26)
    t = lab1_clean(text)
    if len(t) % 2:
        t += 'X'
    out = ''
    for i in range(0, len(t), 2):
        x, y = (ord(t[i]) - 65, ord(t[i + 1]) - 65)
        out += chr(65 + (a * x + b * y) % 26) + chr(65 + (c * x + d * y) % 26)
    return out


def lab1_transposition(text, permutation=(2, 0, 1), decrypt=False):
    """Rearrange fixed-size blocks using permutation indices."""
    t = lab1_clean(text)
    n = len(permutation)
    t += 'X' * (-len(t) % n)
    out = ''
    for i in range(0, len(t), n):
        block = t[i:i + n]
        new = [''] * n
        if decrypt:
            for j, k in enumerate(permutation):
                new[k] = block[j]
        else:
            new = [block[k] for k in permutation]
        out += ''.join(new)
    return out


def lab1_demonstrate(label, text, enc, dec):
    """Print plaintext, ciphertext, and recovered text; write report."""
    c = enc(text)
    p = dec(c)
    report = f'{label}\nPlaintext: {text}\nCiphertext: {c}\nDecrypted: {p}\n'
    print(report)
    save_text('lab1_' + label.replace(' ', '_') + '.txt', report)


def lab1_brute_affine():
    """Try all 312 valid affine keys; known AB->GL gives a=5,b=6."""
    text = 'XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS'
    lines = []
    for a in range(26):
        if gcd(a, 26) == 1:
            for b in range(26):
                lines.append(f'a={a:2}, b={b:2}: {lab1_affine(text, a, b, True)}')
    save_text('lab1_affine_bruteforce.txt', '\n'.join(lines))
    print('Known plaintext AB -> GL gives b=6 and a=5. Result:', lab1_affine(text, 5, 6, True))


def lab2_cipher_key(algorithm, bits=256):
    """Generate correct key length; 3DES keys must have proper parity."""
    if algorithm == 'DES':
        return get_random_bytes(8)
    if algorithm == '3DES':
        while True:
            try:
                return DES3.adjust_key_parity(get_random_bytes(24))
            except ValueError:
                pass
    return get_random_bytes(bits // 8)


def lab2_encrypt(algorithm, message, key, mode='CBC'):
    """Encrypt bytes; store IV/nonce together with ciphertext; pad block modes."""
    cls = {'AES': AES, 'DES': DES, '3DES': DES3}[algorithm]
    block = cls.block_size
    if mode == 'ECB':
        c = cls.new(key, cls.MODE_ECB)
        return {'mode': mode, 'ct': c.encrypt(pad(message, block)).hex()}
    if mode == 'CBC':
        c = cls.new(key, cls.MODE_CBC)
        return {'mode': mode, 'iv': c.iv.hex(), 'ct': c.encrypt(pad(message, block)).hex()}
    if mode == 'CTR':
        c = cls.new(key, cls.MODE_CTR)
        return {'mode': mode, 'nonce': c.nonce.hex(), 'ct': c.encrypt(message).hex()}
    if mode == 'GCM' and algorithm == 'AES':
        c = AES.new(key, AES.MODE_GCM)
        ct, tag = c.encrypt_and_digest(message)
        return {'mode': mode, 'nonce': c.nonce.hex(), 'ct': ct.hex(), 'tag': tag.hex()}
    raise ValueError('Unsupported mode')


def lab2_decrypt(algorithm, packet, key):
    """Recreate cipher from stored parameters; unpad ECB/CBC; verify GCM tag."""
    cls = {'AES': AES, 'DES': DES, '3DES': DES3}[algorithm]
    mode = packet['mode']
    ct = bytes.fromhex(packet['ct'])
    if mode == 'ECB':
        return unpad(cls.new(key, cls.MODE_ECB).decrypt(ct), cls.block_size)
    if mode == 'CBC':
        return unpad(cls.new(key, cls.MODE_CBC, iv=bytes.fromhex(packet['iv'])).decrypt(ct), cls.block_size)
    if mode == 'CTR':
        return cls.new(key, cls.MODE_CTR, nonce=bytes.fromhex(packet['nonce'])).decrypt(ct)
    if mode == 'GCM':
        return AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(packet['nonce'])).decrypt_and_verify(ct, bytes.fromhex(packet['tag']))
    raise ValueError('Unsupported mode')


def lab2_demo(algorithm='AES', bits=256, mode='CBC', message='Confidential Data', key=None):
    """Perform one manual-style round trip and write outputs to TXT."""
    key = key or lab2_cipher_key(algorithm, bits)
    packet = lab2_encrypt(algorithm, message.encode(), key, mode)
    result = lab2_decrypt(algorithm, packet, key).decode()
    report = f'{algorithm}-{bits} {mode}\nMessage: {message}\nKey: {key.hex()}\nPacket: {packet}\nRecovered: {result}\n'
    print(report)
    save_text('lab2_' + algorithm + '_' + mode + '.txt', report)


def lab2_compare():
    """Compare encryption times on the same plaintext; numbers vary by machine."""
    lines = []
    data = b'Performance Testing of Encryption Algorithms'
    for algorithm, bits in [('DES', 64), ('AES', 128), ('AES', 192), ('AES', 256), ('3DES', 192)]:
        for mode in ('ECB', 'CBC', 'CTR'):
            key = lab2_cipher_key(algorithm, bits)
            t = benchmark(lambda: lab2_encrypt(algorithm, data, key, mode), 100)
            line = f'{algorithm}-{bits} {mode}: {t * 1000:.4f} ms'
            print(line)
            lines.append(line)
    save_text('lab2_benchmarks.txt', '\n'.join(lines))


def lab3_rsa_keys(bits=2048):
    """Generate RSA private/public keys."""
    private = RSA.generate(bits)
    return (private, private.publickey())


def lab3_rsa_encrypt(message, public):
    """RSA-OAEP encrypts short data; long files require AES hybrid encryption."""
    return PKCS1_OAEP.new(public, hashAlgo=SHA256).encrypt(message)


def lab3_rsa_decrypt(ciphertext, private):
    """RSA-OAEP decrypts using recipient's private key."""
    return PKCS1_OAEP.new(private, hashAlgo=SHA256).decrypt(ciphertext)


def lab3_aes_encrypt(message, key):
    """AES-GCM encrypts variable-size messages with authentication."""
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(message)
    return (c.nonce, tag, ct)


def lab3_aes_decrypt(packet, key):
    """Verify GCM tag and recover original bytes."""
    nonce, tag, ct = packet
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


def lab3_rsa_hybrid(message):
    """Generate AES key, encrypt file with AES, wrap AES key using RSA."""
    priv, pub = lab3_rsa_keys()
    key = get_random_bytes(32)
    ct = lab3_aes_encrypt(message, key)
    wrapped = lab3_rsa_encrypt(key, pub)
    return lab3_aes_decrypt(ct, lab3_rsa_decrypt(wrapped, priv))


def lab3_ecc_hybrid(message):
    """ECDH derives shared AES key; use AES-GCM to encrypt arbitrary bytes."""
    recipient = ECC.generate(curve='P-256')
    ephemeral = ECC.generate(curve='P-256')
    shared = recipient.pointQ * int(ephemeral.d)
    sender_key = HKDF(int(shared.x).to_bytes(32, 'big'), 32, b'lab3-salt', SHA256, context=b'file')
    packet = lab3_aes_encrypt(message, sender_key)
    other = ephemeral.pointQ * int(recipient.d)
    receiver_key = HKDF(int(other.x).to_bytes(32, 'big'), 32, b'lab3-salt', SHA256, context=b'file')
    return lab3_aes_decrypt(packet, receiver_key)


def lab3_elgamal_keys():
    """Educational ElGamal group; uses a 512-bit prime, not production parameters."""
    p = getPrime(512)
    g = 2
    x = randbelow(p - 2) + 1
    y = pow(g, x, p)
    return ((p, g, y), x)


def lab3_elgamal_encrypt_number(m, pub):
    """Encrypt one integer m as pair (a,b) with fresh random exponent."""
    p, g, y = pub
    k = randbelow(p - 2) + 1
    return (pow(g, k, p), m * pow(y, k, p) % p)


def lab3_elgamal_decrypt_number(pair, pub, private):
    """Recover integer by dividing out shared group element modulo p."""
    p, _, _ = pub
    a, b = pair
    return b * pow(pow(a, private, p), -1, p) % p


def lab3_elgamal_text(message):
    """Encrypt UTF-8 one byte at a time using textbook ElGamal (slow teaching demo)."""
    pub, priv = lab3_elgamal_keys()
    ct = [lab3_elgamal_encrypt_number(b, pub) for b in message]
    return bytes((lab3_elgamal_decrypt_number(pair, pub, priv) for pair in ct))


def lab3_dh_demo():
    """Both peers calculate same shared secret without transmitting private exponents."""
    p = 23
    g = 5
    a = 6
    b = 15
    A = pow(g, a, p)
    B = pow(g, b, p)
    print('Alice shared:', pow(B, a, p), 'Bob shared:', pow(A, b, p))


def lab3_rsa_small_demo():
    """Toy RSA from manual n=323 e=5 d=173; encrypt bytes individually modulo n."""
    msg = b'Cryptographic Protocols'
    c = [pow(b, 5, 323) for b in msg]
    recovered = bytes((pow(x, 173, 323) for x in c))
    print('Cipher integers:', c, '\nRecovered:', recovered.decode())


def lab3_timing():
    """Compare hybrid RSA and ECC file round-trip; avoid direct RSA on large files."""
    for size in (1024, 10240, 1024 * 1024):
        data = get_random_bytes(size)
        for label, fn in [('RSA+AES', lab3_rsa_hybrid), ('ECC+AES', lab3_ecc_hybrid)]:
            t = benchmark(lambda: fn(data), 1)
            print(size, label, f'{t:.4f}s')


def lab4_audit(event, details):
    """Create a timestamped audit entry for key and permission events."""
    return {'time': datetime.now(timezone.utc).isoformat(), 'event': event, 'details': details}


def lab4_key_registry():
    """Demonstrate key generation, public distribution, revocation and renewal."""
    registry = {}
    events = []
    for name in ('Finance', 'HR', 'Supply'):
        private = RSA.generate(2048)
        registry[name] = {'private': private, 'public': private.publickey(), 'revoked': False, 'created': datetime.now(timezone.utc)}
        events.append(lab4_audit('generate', name))
    print('Public keys:', list(registry))
    print('HR public modulus bits:', registry['HR']['public'].size_in_bits())
    registry['HR']['revoked'] = True
    events.append(lab4_audit('revoke', 'HR'))
    registry['HR']['private'] = RSA.generate(2048)
    registry['HR']['public'] = registry['HR']['private'].publickey()
    registry['HR']['revoked'] = False
    events.append(lab4_audit('renew', 'HR'))
    print('HR renewed:', not registry['HR']['revoked'])
    save_text('lab4_key_audit.txt', json.dumps(events, indent=2))


def lab4_allowed(role, action):
    """Allow only operations explicitly assigned to a role."""
    permissions = {'admin': {'create', 'revoke', 'renew', 'read'}, 'doctor': {'read'}, 'guest': set()}
    return action in permissions.get(role, set())


def lab4_rbac_demo():
    """Demonstrate allowed and rejected requests."""
    for role in ('admin', 'doctor', 'guest'):
        for action in ('read', 'revoke'):
            print(role, action, lab4_allowed(role, action))


def lab4_rabin_keys(bits=512):
    """Generate Blum primes p,q congruent to 3 modulo 4."""

    def prime():
        while True:
            x = getPrime(bits)
            if x % 4 == 3:
                return x
    p = prime()
    q = prime()
    while p == q:
        q = prime()
    return (p, q, p * q)


def lab4_rabin_encrypt(m, n):
    """Textbook Rabin encryption c=m² mod n; toy integer demonstration."""
    return pow(m, 2, n)


def lab4_rabin_roots(c, p, q):
    """Rabin decryption produces four possible square roots; encoding selects the right one."""
    n = p * q
    a = pow(c, (p + 1) // 4, p)
    b = pow(c, (q + 1) // 4, q)
    invq = pow(q, -1, p)
    invp = pow(p, -1, q)
    x = (a * q * invq + b * p * invp) % n
    y = (a * q * invq - b * p * invp) % n
    return sorted({x, -x % n, y, -y % n})


def lab4_rabin_demo():
    """Show why Rabin decryption needs redundancy to identify intended plaintext."""
    p, q, n = lab4_rabin_keys(256)
    m = 12345
    c = lab4_rabin_encrypt(m, n)
    roots = lab4_rabin_roots(c, p, q)
    print('Ciphertext:', c, '\nFour roots:', roots, '\nOriginal present:', m in roots)


def lab4_weak_rsa():
    """Factor a deliberately tiny RSA modulus by trial division; educational attack."""
    p, q = (17, 19)
    n = p * q
    e = 5
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    recovered = next((i for i in range(2, math.isqrt(n) + 1) if n % i == 0))
    print('Weak n:', n, 'Factors:', recovered, n // recovered, 'Recovered d:', d)


def lab5_custom_hash(text):
    """Start at 5381; multiply by 33 and add character code, mask to 32 bits."""
    h = 5381
    for c in text:
        h = h * 33 + ord(c) & 4294967295
    return h


def lab5_hash_bytes(data, algorithm='sha512'):
    """Compute digest of bytes and return hexadecimal text."""
    return hashlib.new(algorithm, data).hexdigest()


def lab5_hash_file(path, algorithm='sha512'):
    """Read binary file and calculate its hash."""
    with open(path, 'rb') as f:
        return lab5_hash_bytes(f.read(), algorithm)


def lab5_file_demo():
    """Read input.txt, save hash to TXT, verify, then demonstrate modification."""
    data = load_text('input.txt').encode()
    original = lab5_hash_bytes(data)
    save_text('lab5_sha512_hash.txt', original + '\n')
    print('SHA512:', original, '\nValid:', original == lab5_hash_bytes(data), '\nTampered valid:', original == lab5_hash_bytes(data + b'!'))


def lab5_compare():
    """Hash 75 random strings and count repeated digests; no collisions expected."""
    data = [secrets.token_hex(20).encode() for _ in range(75)]
    for name in ('md5', 'sha1', 'sha256', 'sha512'):
        digests = [lab5_hash_bytes(x, name) for x in data]
        print(name, 'time per batch:', round(benchmark(lambda: [lab5_hash_bytes(x, name) for x in data], 10) * 1000, 4), 'ms', 'collisions:', len(digests) - len(set(digests)))


def lab5_socket_demo():
    """Run local TCP server thread: receive multi-part bytes, return SHA256 hash."""
    payload = b'Information Security Lab multipart message'

    def server():
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', 0))
            s.listen(1)
            port[0] = s.getsockname()[1]
            ready.set()
            conn, _ = s.accept()
            with conn:
                chunks = []
                while True:
                    b = conn.recv(4096)
                    if not b:
                        break
                    chunks.append(b)
                conn.sendall(lab5_hash_bytes(b''.join(chunks), 'sha256').encode())
    ready = threading.Event()
    port = [0]
    t = threading.Thread(target=server, daemon=True)
    t.start()
    ready.wait()
    with socket.create_connection(('127.0.0.1', port[0])) as s:
        for part in (payload[:10], payload[10:20], payload[20:]):
            s.sendall(part)
        s.shutdown(socket.SHUT_WR)
        remote = s.recv(200).decode()
    t.join()
    print('Local hash:', lab5_hash_bytes(payload, 'sha256'), '\nServer hash:', remote, '\nIntegrity:', remote == lab5_hash_bytes(payload, 'sha256'))


def lab6_rsa_sign(data, private):
    """SHA512 digest then RSA-PSS sign with private key."""
    return pss.new(private).sign(SHA512.new(data))


def lab6_rsa_verify(data, sig, public):
    """Verify signature with sender public key; return True/False."""
    try:
        pss.new(public).verify(SHA512.new(data), sig)
        return True
    except (ValueError, TypeError):
        return False


def lab6_elgamal_keys():
    """Small prime parameters for textbook demonstration ONLY."""
    p, g, x = (467, 2, 127)
    return ((p, g, pow(g, x, p)), x)


def lab6_elgamal_sign(data, private, pub):
    """Textbook ElGamal signature r=g^k mod p, s=k^-1(H-xr) mod(p-1)."""
    p, g, _ = pub
    h = int.from_bytes(hashlib.sha512(data).digest(), 'big')
    while True:
        k = secrets.randbelow(p - 2) + 1
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = pow(k, -1, p - 1) * (h - private * r) % (p - 1)
    return (r, s)


def lab6_elgamal_verify(data, sig, pub):
    """Check g^H = y^r*r^s modulo p."""
    p, g, y = pub
    r, s = sig
    if not 1 <= r < p or not 0 <= s < p - 1:
        return False
    h = int.from_bytes(hashlib.sha512(data).digest(), 'big')
    return pow(g, h, p) == pow(y, r, p) * pow(r, s, p) % p


def lab6_schnorr_keys():
    """Tiny Schnorr subgroup: p=23, q=11, generator g=2 of order 11."""
    p, q, g = (23, 11, 2)
    x = secrets.randbelow(q - 1) + 1
    y = pow(g, x, p)
    return ((p, q, g, y), x)


def lab6_schnorr_sign(data, private, pub):
    """Schnorr: commitment R=g^k, challenge H(R||message), response s=k+e*x."""
    p, q, g, y = pub
    k = secrets.randbelow(q - 1) + 1
    R = pow(g, k, p)
    e = int.from_bytes(hashlib.sha256(str(R).encode() + data).digest(), 'big') % q
    return (R, (k + e * private) % q)


def lab6_schnorr_verify(data, sig, pub):
    """Verify g^s = R*y^e modulo p."""
    p, q, g, y = pub
    R, s = sig
    e = int.from_bytes(hashlib.sha256(str(R).encode() + data).digest(), 'big') % q
    return pow(g, s, p) == R * pow(y, e, p) % p


def lab6_demo(which):
    """Sign, verify and tamper-test one message using selected algorithm."""
    data = load_text('input.txt').encode()
    if which == 'RSA':
        private = RSA.generate(2048)
        sig = lab6_rsa_sign(data, private)
        verify = lambda x: lab6_rsa_verify(x, sig, private.publickey())
    elif which == 'ElGamal':
        pub, priv = lab6_elgamal_keys()
        sig = lab6_elgamal_sign(data, priv, pub)
        verify = lambda x: lab6_elgamal_verify(x, sig, pub)
    else:
        pub, priv = lab6_schnorr_keys()
        sig = lab6_schnorr_sign(data, priv, pub)
        verify = lambda x: lab6_schnorr_verify(x, sig, pub)
    print('Signature:', sig.hex() if isinstance(sig, bytes) else sig, '\nValid:', verify(data), '\nTampered valid:', verify(data + b'changed'))
    save_text('lab6_' + which + '_signature.txt', str(sig))


def lab7_keygen(bits=512):
    """Paillier public (n,g), private (lambda,mu), g=n+1."""
    while True:
        p, q = (getPrime(bits // 2), getPrime(bits // 2))
        if p != q:
            n = p * q
            lam = math.lcm(p - 1, q - 1)
            if math.gcd(lam, n) == 1:
                return ((n, n + 1), (lam, pow(lam, -1, n)))


def lab7_encrypt(pub, m):
    """Paillier E(m)=g^m*r^n mod n² with fresh invertible randomness."""
    n, g = pub
    if not 0 <= m < n:
        raise ValueError('Message must be in [0,n)')
    while True:
        r = secrets.randbelow(n - 1) + 1
        if math.gcd(r, n) == 1:
            break
    return pow(g, m, n * n) * pow(r, n, n * n) % (n * n)


def lab7_decrypt(pub, priv, c):
    """Paillier D(c)=L(c^lambda mod n²)*mu mod n."""
    n, _ = pub
    lam, mu = priv
    u = pow(c, lam, n * n)
    return (u - 1) // n * mu % n


def lab7_add(pub, *ciphertexts):
    """Multiply ciphertexts modulo n² to add encrypted plaintexts."""
    n, _ = pub
    total = 1
    for c in ciphertexts:
        total = total * c % (n * n)
    return total


def lab7_multiply_constant(pub, c, k):
    """Raise Paillier ciphertext to known integer k to multiply plaintext by k."""
    n, _ = pub
    return pow(c, k, n * n)


def lab7_paillier_demo():
    """Manual Exercise 1: encrypt 15 and 25, add encrypted values, decrypt 40."""
    pub, priv = lab7_keygen()
    a = lab7_encrypt(pub, 15)
    b = lab7_encrypt(pub, 25)
    c = lab7_add(pub, a, b)
    print('E15:', a, '\nE25:', b, '\nEncrypted sum:', c, '\nDecrypted sum:', lab7_decrypt(pub, priv, c))


def lab7_rsa_multiply():
    """Textbook RSA multiplication (insecure by design), example 7*3=21."""
    p, q = (17, 19)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 5
    d = pow(e, -1, phi)
    c1, c2 = (pow(7, e, n), pow(3, e, n))
    c = c1 * c2 % n
    print('Ciphertexts:', c1, c2, 'Product ciphertext:', c, 'Recovered:', pow(c, d, n))


def lab7_elgamal_multiply():
    """Multiply ciphertext PAIRS component-wise to multiply encrypted messages."""
    p = 467
    g = 2
    x = 127
    y = pow(g, x, p)

    def enc(m):
        k = secrets.randbelow(p - 2) + 1
        return (pow(g, k, p), m * pow(y, k, p) % p)

    def dec(c):
        a, b = c
        return b * pow(pow(a, x, p), -1, p) % p
    a, b = (enc(7), enc(3))
    c = (a[0] * b[0] % p, a[1] * b[1] % p)
    print('E7:', a, 'E3:', b, 'Product ciphertext:', c, 'Decrypted:', dec(c))


def lab7_sharing():
    """Two hospitals send encrypted counts; only aggregate is decrypted."""
    pub, priv = lab7_keygen()
    c = lab7_add(pub, lab7_encrypt(pub, 150), lab7_encrypt(pub, 230))
    print('Encrypted total:', c, '\nDecrypted total:', lab7_decrypt(pub, priv, c))


def lab7_benchmark_demo():
    """Measure Paillier encryption and homomorphic addition; keygen excluded."""
    pub, priv = lab7_keygen()
    a, b = (lab7_encrypt(pub, 15), lab7_encrypt(pub, 25))
    print('Paillier encrypt ms:', benchmark(lambda: lab7_encrypt(pub, 15), 10) * 1000)
    print('Paillier add ms:', benchmark(lambda: lab7_add(pub, a, b), 100) * 1000)
    print('Paillier decrypt ms:', benchmark(lambda: lab7_decrypt(pub, priv, a), 20) * 1000)


def lab8_words(text):
    """Lowercase and split into searchable words."""
    return set(re.findall('[a-z0-9]+', text.lower()))


def lab8_token(word, key):
    """Stable secret-keyed HMAC-SHA256 keyword token."""
    return hmac.new(key, word.lower().encode(), hashlib.sha256).hexdigest()


def lab8_encrypt_document(data, key):
    """AES-GCM encrypt a document; return nonce/tag/ciphertext hex."""
    c = AES.new(key, AES.MODE_GCM)
    ct, tag = c.encrypt_and_digest(data.encode())
    return {'nonce': c.nonce.hex(), 'tag': tag.hex(), 'ct': ct.hex()}


def lab8_decrypt_document(packet, key):
    """Authenticate AES-GCM tag then decrypt document."""
    c = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(packet['nonce']))
    return c.decrypt_and_verify(bytes.fromhex(packet['ct']), bytes.fromhex(packet['tag'])).decode()


def lab8_documents():
    """Ten-document corpus satisfying the manual's dataset requirement."""
    return {1: 'python cryptography security', 2: 'java programming security', 3: 'python machine learning', 4: 'network security firewall', 5: 'database encryption privacy', 6: 'python encryption algorithms', 7: 'machine learning models', 8: 'firewall network monitoring', 9: 'privacy secure database', 10: 'cryptography python network'}


def lab8_build_index(docs, key, paillier_pub=None):
    """Map HMAC(keyword) to encrypted ID if Paillier key provided, else plain ID."""
    index = {}
    for doc_id, text in docs.items():
        for word in lab8_words(text):
            index.setdefault(lab8_token(word, key), []).append(lab7_encrypt(paillier_pub, doc_id) if paillier_pub else doc_id)
    return index


def lab8_sse_demo():
    """Encrypt 10 documents with AES-GCM, HMAC-index words, retrieve/decrypt matches."""
    docs = lab8_documents()
    aes = get_random_bytes(32)
    search = get_random_bytes(32)
    encrypted = {i: lab8_encrypt_document(text, aes) for i, text in docs.items()}
    index = lab8_build_index(docs, search)
    ids = sorted(index.get(lab8_token('python', search), []))
    for i in ids:
        print(i, lab8_decrypt_document(encrypted[i], aes))
    save_text('lab8_sse_matches.txt', '\n'.join((f'{i}: {lab8_decrypt_document(encrypted[i], aes)}' for i in ids)))


def lab8_paillier_index_demo():
    """HMAC searchable token with Paillier-encrypted document IDs (hybrid, NOT true PKSE)."""
    pub, priv = lab7_keygen()
    search = get_random_bytes(32)
    index = lab8_build_index(lab8_documents(), search, pub)
    ids = sorted((lab7_decrypt(pub, priv, c) for c in index.get(lab8_token('python', search), [])))
    print('Recovered document IDs:', ids)


def lab8_gpg_demo():
    """Show GnuPG commands; do not generate/export private keys automatically."""
    print('gpg --full-generate-key\ngpg --list-keys\ngpg --encrypt --recipient YOUR_KEY_ID --output report.gpg data/input.txt\ngpg --decrypt --output recovered.txt report.gpg\ngpg --detach-sign --output report.sig data/input.txt\ngpg --verify report.sig data/input.txt')
    print('GPG installed:', bool(shutil.which('gpg')))


def lab8_snort_demo():
    """Write a safe ICMP alert rule for a local authorized Snort lab."""
    rule = 'alert icmp any any -> any any (msg:"Lab ICMP detected"; sid:1000001; rev:1;)'
    save_text('lab8_snort_local.rules', rule + '\n')
    print('Snort installed:', bool(shutil.which('snort')), '\nSnort2 example: sudo snort -T -c /etc/snort/snort.conf')



# ============================================================================
# BEGINNER API: SAME ENCRYPT/DECRYPT PATTERN FOR AES / DES / 3DES
# ============================================================================
# INPUT: plaintext must be BYTES: b"HELLO" or "HELLO".encode()
# OUTPUT: dictionary with ct + mode + IV/nonce/tag as needed.
# To decrypt, use SAME key and the returned dictionary.
# AES key: 16 bytes=128, 24=192, 32=256.
# DES key: 8 bytes; 3DES key: 16 or 24 bytes (use key_for()).
# Modes: ECB (no IV, unsafe), CBC (IV + padding), CTR (nonce),
# GCM (AES ONLY; nonce+tag authenticates ciphertext).
#
# CLIENT EXAMPLE:
#   key = key_for('AES', 256)
#   encrypted = encrypt_data(b'HELLO', key, 'AES', 'CBC')
# SERVER EXAMPLE:
#   original = decrypt_data(encrypted, key, 'AES')
# SWAP AES -> DES: key_for('DES'), encrypt_data(data,key,'DES','CBC')
# SWAP CBC -> GCM: encrypt_data(data,key,'AES','GCM')

def key_for(algorithm='AES', bits=256):
    """Generate suitable symmetric key for AES, DES or 3DES."""
    return lab2_cipher_key(algorithm.upper(), bits)

def encrypt_data(data, key, algorithm='AES', mode='CBC'):
    """One encryption function for AES-128/192/256, DES and 3DES."""
    return lab2_encrypt(algorithm.upper(), data, key, mode.upper())

def decrypt_data(packet, key, algorithm='AES'):
    """Reverse encrypt_data(); mode/IV/nonce are inside packet."""
    return lab2_decrypt(algorithm.upper(), packet, key)

def aes_128_encrypt(data, key=None, mode='CBC'):
    """Return (packet, key); key is 16 bytes (AES-128)."""
    key = key if key is not None else key_for('AES',128)
    if len(key) != 16: raise ValueError('AES-128 requires 16 bytes')
    return encrypt_data(data,key,'AES',mode),key

def aes_192_encrypt(data, key=None, mode='CBC'):
    """Return (packet, key); key is 24 bytes (AES-192)."""
    key = key if key is not None else key_for('AES',192)
    if len(key) != 24: raise ValueError('AES-192 requires 24 bytes')
    return encrypt_data(data,key,'AES',mode),key

def aes_256_encrypt(data, key=None, mode='CBC'):
    """Return (packet, key); key is 32 bytes (AES-256)."""
    key = key if key is not None else key_for('AES',256)
    if len(key) != 32: raise ValueError('AES-256 requires 32 bytes')
    return encrypt_data(data,key,'AES',mode),key

def des_encrypt(data, key=None, mode='CBC'):
    """Return (packet,key) for DES; INSECURE legacy teaching cipher."""
    key = key if key is not None else key_for('DES')
    return encrypt_data(data,key,'DES',mode),key

def triple_des_encrypt(data, key=None, mode='CBC'):
    """Return (packet,key) for 3DES; legacy, use only for coursework."""
    key = key if key is not None else key_for('3DES')
    return encrypt_data(data,key,'3DES',mode),key

# ============================================================================
# LAB 1: CLASSICAL CIPHERS — plaintext is TEXT, not bytes.
# ============================================================================
def caesar_encrypt(text, shift=3):
    """Shift A-Z by shift positions; Caesar = additive cipher."""
    return lab1_affine(text,1,shift)

def caesar_decrypt(text, shift=3):
    return lab1_affine(text,1,shift,True)

def multiplicative_encrypt(text, key=5):
    """Multiply alphabet indices modulo 26; key must be coprime to 26."""
    return lab1_affine(text,key,0)

def multiplicative_decrypt(text, key=5):
    return lab1_affine(text,key,0,True)

def affine_encrypt(text,a=5,b=8):
    """E(x)=(a*x+b)%26; gcd(a,26) must be 1."""
    return lab1_affine(text,a,b)

def affine_decrypt(text,a=5,b=8):
    return lab1_affine(text,a,b,True)

def vigenere_encrypt(text,key='KEY'):
    return lab1_vigenere(text,key)

def vigenere_decrypt(text,key='KEY'):
    return lab1_vigenere(text,key,True)

def autokey_encrypt(text,seed=7):
    return lab1_autokey(text,seed)

def autokey_decrypt(text,seed=7):
    return lab1_autokey(text,seed,True)

def playfair_encrypt(text,key='GUIDANCE'):
    return lab1_playfair(text,key)

def playfair_decrypt(text,key='GUIDANCE'):
    return lab1_playfair(text,key,True)

def hill_encrypt(text,key=((3,3),(2,7))):
    return lab1_hill(text,key)

def hill_decrypt(text,key=((3,3),(2,7))):
    return lab1_hill(text,key,True)

def transposition_encrypt(text,permutation=(2,0,1)):
    return lab1_transposition(text,permutation)

def transposition_decrypt(text,permutation=(2,0,1)):
    return lab1_transposition(text,permutation,True)

# ============================================================================
# LAB 5: HASHING — hashes are NOT encryption; there is no decrypt hash.
# ============================================================================
def hash_bytes(data, algorithm='sha512'):
    """Accept bytes; choose md5, sha1, sha256, sha512 or another hashlib name."""
    return hashlib.new(algorithm.lower().replace('-',''), data).hexdigest()

def hash_text(text, algorithm='sha512'):
    return hash_bytes(text.encode(),algorithm)

def hash_txt_file(filename, algorithm='sha512'):
    """Read entire file as bytes and return hash; filename may be absolute."""
    return hash_bytes(Path(filename).read_bytes(),algorithm)

def write_hash_txt(input_file, output_file='hashes.txt', algorithm='sha512'):
    """Read input TXT, hash it, write digest to output TXT."""
    digest = hash_txt_file(input_file,algorithm)
    Path(output_file).write_text(digest+'\n',encoding='utf-8')
    return digest

def verify_hash(data, expected_hex, algorithm='sha512'):
    """Recalculate and compare hex digests; expected digest must be trusted."""
    return hmac.compare_digest(hash_bytes(data,algorithm),expected_hex)

def custom_hash_5381(text):
    return lab5_custom_hash(text)

# ============================================================================
# LAB 3: PUBLIC KEY — RSA, ElGamal, ECC, DH, Rabin.
# ============================================================================
def rsa_make_keys(bits=2048):
    """Return (public,private), consistent with e-voting rsa_keys()."""
    private = RSA.generate(bits)
    return private.publickey(),private

def rsa_encrypt_bytes(data, public):
    """RSA-OAEP; ONLY short data, e.g. AES key; returns HEX string."""
    return lab3_rsa_encrypt(data,public).hex()

def rsa_decrypt_bytes(cipher_hex, private):
    return lab3_rsa_decrypt(bytes.fromhex(cipher_hex),private)

def ecc_make_keys(curve='P-256'):
    """Generate ECC key pair. Use for ECDSA or ECDH."""
    private=ECC.generate(curve=curve)
    return private.public_key(),private

def ecc_sign(data, private):
    """ECDSA + SHA-256 signature, returns hex. Different from ECDH!"""
    digest=SHA256.new(data)
    return DSS.new(private,'fips-186-3').sign(digest).hex()

def ecc_verify(data, signature_hex, public):
    """Return False on altered message or signature."""
    try:
        DSS.new(public,'fips-186-3').verify(SHA256.new(data),bytes.fromhex(signature_hex))
        return True
    except (ValueError,TypeError):
        return False

def ecc_encrypt_demo(data):
    """ECDH-derived AES-GCM hybrid demo; returns recovered plaintext."""
    return lab3_ecc_hybrid(data)

def diffie_hellman_demo():
    """Toy DH shared-secret agreement; returns master exercise output."""
    return lab3_dh_demo()

def rabin_make_keys(bits=512):
    return lab4_rabin_keys(bits)

def rabin_encrypt_number(m,n):
    return lab4_rabin_encrypt(m,n)

def rabin_decrypt_roots(c,p,q):
    """Rabin decryption yields FOUR candidate square roots, not one."""
    return lab4_rabin_roots(c,p,q)

# ============================================================================
# LAB 6: SIGNATURES — sign with PRIVATE, verify with PUBLIC.
# ============================================================================
def rsa_sign_bytes(data,private):
    """RSA-PSS with SHA-512; returns HEX string."""
    return lab6_rsa_sign(data,private).hex()

def rsa_verify_bytes(data,signature_hex,public):
    return lab6_rsa_verify(data,bytes.fromhex(signature_hex),public)

def schnorr_make_keys():
    """Tiny toy Schnorr group, only for formula demonstration."""
    return lab6_schnorr_keys()

def schnorr_sign(data,public,private):
    return list(lab6_schnorr_sign(data,private,public))

def schnorr_verify(data,signature,public):
    return lab6_schnorr_verify(data,signature,public)

# ============================================================================
# LAB 7: HOMOMORPHIC — Paillier ADD; textbook RSA/ElGamal MULTIPLY.
# ============================================================================
def paillier_add_constant(ciphertext,constant,public):
    """Paillier E(m)^k -> E(k*m); supports nonnegative integer k."""
    return lab7_multiply_constant(public,ciphertext,constant)

def paillier_sum(encrypted_values,public):
    """Alias for e-voting paillier_add(list,public)."""
    return paillier_add(encrypted_values,public)

def one_hot_vote(candidate,candidate_count=3):
    """Candidate numbering starts at 1. e.g. 2 -> [0,1,0]."""
    if not 1 <= candidate <= candidate_count: raise ValueError('Invalid candidate')
    values=[0]*candidate_count
    values[candidate-1]=1
    return values

# ============================================================================
# LAB 8: SSE — keyword search tokens + encrypted document contents.
# ============================================================================
def encrypt_document(text,aes_key):
    """AES-GCM encrypt UTF-8 document. Returns nonce/tag/ct dictionary."""
    return lab8_encrypt_document(text,aes_key)

def decrypt_document(packet,aes_key):
    return lab8_decrypt_document(packet,aes_key)

def build_search_index(documents,search_key):
    """documents = {1:'python security',2:'network security'}; returns index."""
    return lab8_build_index(documents,search_key)

def search_documents(index,keyword,search_key):
    return index.get(lab8_token(keyword,search_key),[])

def build_paillier_id_index(documents,search_key,paillier_public):
    """Toy HMAC lookup + Paillier-encrypted IDs; NOT genuine PEKS/PKSE."""
    return lab8_build_index(documents,search_key,paillier_public)

# ============================================================================
# FILES + TIMING — useful in any blended exam question.
# ============================================================================
def read_txt(path):
    return Path(path).read_text(encoding='utf-8')

def write_txt(path,text):
    Path(path).write_text(str(text),encoding='utf-8')

def compare_time(function,*args):
    """Return (function result, elapsed seconds)."""
    start=time.perf_counter()
    result=function(*args)
    return result,time.perf_counter()-start
