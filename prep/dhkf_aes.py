'''
A multinational company has Finance, HR, and Supply Chain departments. Each department must exchange sensitive documents securely, and the administrator must manage cryptographic keys centrally.

Implement a Python application with the following features:

1. Create user accounts for the three departments and an administrator.
2. Establish a shared secret between communicating departments using Diffie–Hellman.
3. Use the shared secret to derive a symmetric encryption key.
4. Encrypt department documents using AES.
5. Use RSA digital signatures or another suitable signature scheme to authenticate document senders.
6. Implement role-based access control to prevent unauthorized departments from accessing restricted documents.
7. Support key expiry, renewal, revocation, and replacement.
8. Maintain logs for key creation, key use, revocation, and unauthorized access.

Demonstrate communication between two authorized departments and rejection of an unauthorized request.
'''
import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from getpass import getpass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


DEPARTMENTS = ["Finance", "HR", "Supply Chain"]
ADMIN = "Administrator"
USERS = {
    "admin": {"password": "admin123", "role": ADMIN},
    "finance": {"password": "fin123", "role": "Finance"},
    "hr": {"password": "hr123", "role": "HR"},
    "supply": {"password": "sup123", "role": "Supply Chain"}
}
ACL = {
    "Finance": {"HR", "Supply Chain"},
    "HR": {"Finance"},
    "Supply Chain": {"Finance"}
}
KEYS = {}
DOCUMENTS = {}
AUDIT_LOG = []

def log_event(event, actor, details=""):
    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "actor": actor,
        "details": details
    }
    AUDIT_LOG.append(entry)
    print("[AUDIT]", entry)

def new_department_keys():
    print("\nEnter Diffie-Hellman parameters")
    p = int(input("Enter prime number p: "))
    g = int(input("Enter generator g: "))

    if p < 5:
        raise ValueError("p must be at least 5.")

    for i in range(2, int(p ** 0.5) + 1):
        if p % i == 0:
            raise ValueError("p must be prime.")

    if not 2 <= g <= p - 2:
        raise ValueError("g must be between 2 and p-2.")

    private_key = int(input("Enter private key: "))
    if not 2 <= private_key <= p - 2:
        raise ValueError("Private key must be between 2 and p-2.")

    public_key = pow(g, private_key, p)
    print(public_key)
    return {
        "p": p,
        "g": g,
        "dh_private": private_key,
        "dh_public": public_key,
        "rsa_private": rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        ),
        "expires": datetime.now(timezone.utc) + timedelta(days=30),
        "revoked": False,
        "version": 1
    }

def initialize_keys():
    for department in DEPARTMENTS:
        KEYS[department] = new_department_keys()
        log_event("KEY_CREATED", ADMIN, department)


def key_is_valid(department):
    key = KEYS.get(department)
    if key is None:
        return False

    if key["revoked"]:
        log_event("KEY_REJECTED", department, "Key revoked")
        return False

    if datetime.now(timezone.utc) >= key["expires"]:
        log_event("KEY_REJECTED", department, "Key expired")
        return False

    return True


def derive_aes_key(shared_secret, salt, doc_id, sender, recipient):
    # Both departments derive the same 256-bit key.
    info = f"CompanyDocument|{doc_id}|{sender}|{recipient}".encode()

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    ).derive(shared_secret)


def canonical_message(doc):
    # Bind the signature to the sender, recipient, document ID,
    # nonce, salt, and ciphertext.
    fields = {
        "id": doc["id"],
        "sender": doc["sender"],
        "recipient": doc["recipient"],
        "nonce": doc["nonce"],
        "salt": doc["salt"],
        "ciphertext": doc["ciphertext"],
        "sender_version": doc["sender_version"],
        "recipient_version": doc["recipient_version"]
    }
    return json.dumps(fields, sort_keys=True).encode()


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(data):
    return base64.b64decode(data.encode("ascii"))


def send_document(sender, recipient, plaintext):
    if sender not in DEPARTMENTS or recipient not in DEPARTMENTS:
        print("Invalid department.")
        return

    if recipient not in ACL.get(sender, set()):
        log_event("UNAUTHORIZED_SEND", sender, f"to {recipient}")
        print("ACCESS DENIED: Department communication is not permitted.")
        return

    if not key_is_valid(sender) or not key_is_valid(recipient):
        print("Send failed: a department key is expired or revoked.")
        return

    sender_keys = KEYS[sender]
    recipient_keys = KEYS[recipient]

    shared = pow(recipient_keys["dh_public"],sender_keys["dh_private"],sender_keys["p"])

    doc_id = str(uuid.uuid4())
    salt = os.urandom(16)
    nonce = os.urandom(12)

    aes_key = derive_aes_key(shared, salt, doc_id, sender, recipient)

    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), doc_id.encode())

    doc = {
        "id": doc_id,
        "sender": sender,
        "recipient": recipient,
        "nonce": b64(nonce),
        "salt": b64(salt),
        "ciphertext": b64(ciphertext),
        "sender_version": sender_keys["version"],
        "recipient_version": recipient_keys["version"]
    }

    # Sign the encrypted document and its identifying metadata.
    signature = sender_keys["rsa_private"].sign(
        canonical_message(doc),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    doc["signature"] = b64(signature)
    DOCUMENTS[doc_id] = doc

    log_event("KEY_USED", sender, f"DH/AES-GCM for document {doc_id}")
    log_event("DOCUMENT_SENT", sender, f"to {recipient}; ID={doc_id}")
    print("Document encrypted and signed.")
    print("Document ID:", doc_id)


def receive_document(recipient, doc_id):
    doc = DOCUMENTS.get(doc_id)

    if not doc:
        print("Document not found.")
        return

    sender = doc["sender"]

    if recipient != doc["recipient"]:
        log_event(
            "UNAUTHORIZED_ACCESS", recipient,
            f"attempted document {doc_id}"
        )
        print("ACCESS DENIED: This document belongs to another department.")
        return

    if sender not in ACL or recipient not in ACL[sender]:
        log_event("UNAUTHORIZED_ACCESS", recipient, doc_id)
        print("ACCESS DENIED: No permission for this communication.")
        return

    if not key_is_valid(sender) or not key_is_valid(recipient):
        print("Access denied: sender or recipient key is expired/revoked.")
        return

    sender_keys = KEYS[sender]
    recipient_keys = KEYS[recipient]

    if (
        doc["sender_version"] != sender_keys["version"]
        or doc["recipient_version"] != recipient_keys["version"]
    ):
        log_event("KEY_VERSION_MISMATCH", recipient, doc_id)
        print("Access denied: document uses a replaced key version.")
        return

    # Verify the RSA signature before decrypting.
    try:
        sender_keys["rsa_private"].public_key().verify(
            unb64(doc["signature"]),
            canonical_message(doc),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception:
        log_event("SIGNATURE_FAILURE", recipient, doc_id)
        print("Rejected: sender signature is invalid.")
        return
    shared = pow(sender_keys["dh_public"],recipient_keys["dh_private"],recipient_keys["p"])

    aes_key = derive_aes_key(shared,unb64(doc["salt"]),doc["id"],sender,recipient)

    try:
        plaintext = AESGCM(aes_key).decrypt(
            unb64(doc["nonce"]),
            unb64(doc["ciphertext"]),
            doc["id"].encode()
        ).decode("utf-8")
    except Exception:
        log_event("DECRYPTION_FAILURE", recipient, doc_id)
        print("Rejected: ciphertext authentication failed.")
        return

    log_event("DOCUMENT_RECEIVED", recipient, doc_id)
    print("\nSignature verified successfully.")
    print("Decrypted document:", plaintext)


def admin_menu():
    while True:
        print("\n--- ADMINISTRATOR KEY MANAGEMENT ---")
        print("1. Show key status")
        print("2. Revoke department key")
        print("3. Renew/replace department keys")
        print("4. Set key expiry in days")
        print("5. Show audit log")
        print("6. Logout")

        choice = input("Choice: ").strip()

        if choice == "1":
            for d, k in KEYS.items():
                print(
                    d,
                    "| version:", k["version"],
                    "| expires:", k["expires"].isoformat(),
                    "| revoked:", k["revoked"]
                )

        elif choice == "2":
            d = input("Department: ").strip()
            if d not in KEYS:
                print("Unknown department.")
                continue
            KEYS[d]["revoked"] = True
            log_event("KEY_REVOKED", ADMIN, d)
            print("Key revoked.")

        elif choice == "3":
            d = input("Department to renew: ").strip()
            if d not in KEYS:
                print("Unknown department.")
                continue

            old_version = KEYS[d]["version"]
            KEYS[d] = new_department_keys()
            KEYS[d]["version"] = old_version + 1
            log_event("KEY_REPLACED", ADMIN, f"{d}, version {old_version + 1}")
            print("New DH and RSA keys generated.")
            print("Previously encrypted documents using this key version")
            print("will be rejected. Re-encryption/migration is required.")

        elif choice == "4":
            d = input("Department: ").strip()
            if d not in KEYS:
                print("Unknown department.")
                continue
            try:
                days = int(input("Expiry in days: "))
                if days <= 0:
                    print("Days must be positive.")
                    continue
                KEYS[d]["expires"] = (
                    datetime.now(timezone.utc) + timedelta(days=days)
                )
                log_event("KEY_EXPIRY_UPDATED", ADMIN, f"{d}: {days} days")
                print("Expiry updated.")
            except ValueError:
                print("Enter a valid integer.")

        elif choice == "5":
            print(json.dumps(AUDIT_LOG, indent=2))

        elif choice == "6":
            break

        else:
            print("Invalid choice.")


def department_menu(username, department):
    while True:
        print(f"\n--- {department} DEPARTMENT ---")
        print("1. Send encrypted document")
        print("2. Receive/decrypt document")
        print("3. Logout")

        choice = input("Choice: ").strip()

        if choice == "1":
            recipient = input(
                "Recipient (Finance, HR, Supply Chain): "
            ).strip()
            text = input("Document text: ")
            send_document(department, recipient, text)

        elif choice == "2":
            doc_id = input("Document ID: ").strip()
            receive_document(department, doc_id)

        elif choice == "3":
            break

        else:
            print("Invalid choice.")


def main():
    initialize_keys()

    while True:
        print("\n=== SECURE COMPANY DOCUMENT EXCHANGE ===")
        print("Demo accounts:")
        print("admin / admin123")
        print("finance / fin123")
        print("hr / hr123")
        print("supply / sup123")
        print("1. Login")
        print("2. Exit")

        choice = input("Choice: ").strip()

        if choice == "2":
            break
        if choice != "1":
            print("Invalid choice.")
            continue

        username = input("Username: ").strip()
        password = getpass("Password: ")

        account = USERS.get(username)
        if not account or account["password"] != password:
            log_event("LOGIN_FAILURE", username, "Invalid credentials")
            print("Login failed.")
            continue

        role = account["role"]
        log_event("LOGIN_SUCCESS", username, role)

        if role == ADMIN:
            admin_menu()
        else:
            department_menu(username, role)


if __name__ == "__main__":
    main()
