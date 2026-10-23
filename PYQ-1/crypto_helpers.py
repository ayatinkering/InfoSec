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
