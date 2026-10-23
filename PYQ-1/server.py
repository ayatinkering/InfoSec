"""
SERVER.PY - Election Commission
Run FIRST: python server.py
Each command is handled by the server, not by the client.
Stored ballots/audit use TXT files in the SAME FOLDER.
"""
import json, socket, struct
from pathlib import Path
from datetime import datetime, timezone, timedelta
from crypto_helpers import (
    rsa_keys, elgamal_verify, paillier_keys, paillier_add,
    paillier_decrypt, aes_decrypt, rsa_decrypt, sha512,
    issue_timestamp, check_timestamp, search_token,
    add_to_index, search_index, allowed, to_bytes,
    send_json, recv_json
)
HOST, PORT = "127.0.0.1", 5055
BASE = Path(__file__).resolve().parent
RECORDS = BASE / "server_records.txt"
AUDIT = BASE / "server_audit.txt"

# STEP 0: Election Commission generates its OWN keys.
rsa_pub, rsa_priv = rsa_keys()
pai_pub, pai_priv = paillier_keys()
from Crypto.Random import get_random_bytes
timestamp_secret = get_random_bytes(32)
search_key = get_random_bytes(32)
deadline = datetime.now(timezone.utc) + timedelta(hours=1)
records, index, seen_ids = [], {}, set()

# Start fresh each run; do not accidentally mix ballots encrypted with old keys.
RECORDS.write_text("", encoding="utf-8")
AUDIT.write_text("", encoding="utf-8")

def append_txt(path, obj):
    """Write one JSON dictionary per line into a .txt file."""
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")

def audit(event, detail):
    """STEP 8: Record an audit event with server UTC time."""
    entry = {"time": datetime.now(timezone.utc).isoformat(),
             "event": event, "detail": detail}
    append_txt(AUDIT, entry)

# ================================================================
# SERVER PYQ STEPS 9 TO 14: CHECK AND STORE THE BALLOT
# Each validation failure raises ValueError and rejects the ballot.
# ================================================================
def accept_ballot(packet):
    """STEP 4: Verify signature/timestamp, decrypt AES, check SHA-512, store."""
    # DEMO ONLY: sign_public comes from client, NOT trusted registration.
    unsigned = {k: v for k, v in packet.items() if k != "signature"}
    sign_pub = tuple(packet["sign_public"])
    # STEP 9: ElGamal verification = check signature was not changed.
    if not elgamal_verify(to_bytes(unsigned), packet["signature"], sign_pub):
        raise ValueError("ElGamal signature FAILED")
    print("STEP 9: ElGamal signature VALID")
    # STEP 10: Timestamp must be authentic and before deadline.
    if not check_timestamp(packet["timestamp"], timestamp_secret, deadline):
        raise ValueError("Timestamp invalid")
    print("STEP 10: Timestamp VALID")
    # STEP 11: RSA PRIVATE key recovers AES session key.
    aes_key = rsa_decrypt(packet["rsa_key"], rsa_priv)
    print("STEP 11: RSA decrypted AES key")
    # STEP 12: AES decrypts ballot using recovered key + original IV.
    plaintext = aes_decrypt(packet["ballot"], aes_key)
    print("STEP 12: AES decrypted ballot:", plaintext.decode())
    # STEP 13: SHA-512: recompute and compare to signed original hash.
    if sha512(plaintext) != packet["hash"]:
        raise ValueError("SHA-512 mismatch")
    print("STEP 13: SHA-512 hash MATCHED")
    # Convert decrypted JSON text back into Python dictionary.
    ballot = json.loads(plaintext)
    ballot_id = ballot["id"]
    if ballot_id in seen_ids:
        raise ValueError("Duplicate ballot ID")
    if ballot["candidate"] not in (1, 2, 3):
        raise ValueError("Candidate must be 1, 2, or 3")
    if len(packet["vote"]) != 3:
        raise ValueError("Vote ciphertext vector must have 3 values")
    # Cannot verify ciphertext votes equal plaintext choice without a ZK proof.
    seen_ids.add(ballot_id)
    records.append(packet)
    add_to_index(index, ballot_id, ballot["constituency"],
                 packet["timestamp"]["time"][:10], search_key)
    # STEP 14: Write encrypted packet into server_records.txt.
    # Keep audit log in server_audit.txt.
    append_txt(RECORDS, packet)
    audit("ACCEPT", {"id": ballot_id, "constituency": ballot["constituency"]})
    return {"ok": True, "id": ballot_id, "hash_valid": True,
            "signature_valid": True, "timestamp_valid": True}

# STEP 15: Paillier homomorphic addition: add ciphertexts, decrypt TOTAL only.
def tally():
    """STEP 6: Multiply Paillier ciphertexts; decrypt aggregate only."""
    if not records:
        return {"ok": True, "totals": [0, 0, 0]}
    encrypted_totals = []
    for candidate_position in range(3):
        # Collect one encrypted column from all accepted ballots.
        encrypted_column = []
        for packet in records:
            encrypted_column.append(packet["vote"][candidate_position])
        # Add without decrypting individual vote ciphertexts.
        encrypted_sum = paillier_add(encrypted_column, pai_pub)
        encrypted_totals.append(encrypted_sum)
    return {"ok": True, "totals": [
        paillier_decrypt(c, pai_pub, pai_priv) for c in encrypted_totals
    ], "ballots": len(records), "threshold": "NOT IMPLEMENTED"}

def handle(req):
    """Choose the relevant PYQ step from the client's menu request."""
    cmd = req.get("cmd")
    if cmd == "setup":
        return {"ok": True, "rsa_public_pem": rsa_pub.export_key().decode(),
                "paillier_public": list(pai_pub),
                "deadline": deadline.isoformat(),
                "timestamp": issue_timestamp(timestamp_secret)}
    if cmd == "submit":
        try:
            return accept_ballot(req["packet"])
        except Exception as exc:
            audit("REJECT", str(exc))
            return {"ok": False, "error": str(exc)}
    # Classroom demonstration only: no authenticated RBAC identity.
    if cmd == "search":
        if not allowed("officer", "search"):
            return {"ok": False, "error": "Access denied"}
        term = "place:" + req["place"].strip().lower()
        return {"ok": True, "ids": search_index(index, term, search_key)}
    if cmd == "tally":
        if not allowed("officer", "tally"):
            return {"ok": False, "error": "Access denied"}
        return tally()
    if cmd == "audit":
        return {"ok": True, "lines": AUDIT.read_text().splitlines()}
    return {"ok": False, "error": "Unknown command"}

def main():
    print("SERVER STARTED: localhost:5055")
    print("Waiting for client... Press Ctrl+C to stop.")
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(10)
        while True:
            conn, addr = server.accept()
            with conn:
                try:
                    request = recv_json(conn)
                    send_json(conn, handle(request))
                except Exception as exc:
                    print("Connection error:", exc)

if __name__ == "__main__":
    main()
