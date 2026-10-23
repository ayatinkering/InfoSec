'''A law firm stores confidential contracts in an encrypted database.
Lawyers must be able to search by keyword, retrieve matching contracts, and verify their integrity.

Implement a menu-driven Python program that:
1. Accepts contract IDs, client IDs, and contract contents.
2. Encrypts each contract using AES-CBC with a user-provided key and IV.
3. Generates a searchable index using keyed hashes of normalized keywords.
4. Allows lawyers to search for contracts without decrypting every stored contract.
5. Computes and stores a SHA-256 hash for each original contract.
6. Verifies the hash after decryption to detect modification.
7. Restricts access by role and allows administrators to revoke users.
8. Demonstrates successful keyword search, tampering detection, and unauthorized-access rejection.'''


import os
import re
import json
import hmac
import base64
import hashlib
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

CONTRACT_FILE = "contracts.txt"
USER_FILE = "users.txt"
AUDIT_FILE = "audit_log.txt"
DEFAULT_USERS = {
    "admin": {"password": "admin123", "role": "Administrator", "revoked": False},
    "lawyer1": {"password": "law123", "role": "Lawyer", "revoked": False},
    "lawyer2": {"password": "law456", "role": "Lawyer", "revoked": False}
}

contracts = {}
users = {}

def load_json(filename, default):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return default

def save_json(filename, data):
    with open(filename, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

def audit(message):
    with open(AUDIT_FILE, "a", encoding="utf-8") as file:
        file.write(message + "\n")
    print("AUDIT:", message)

def login():
    username = input("Username: ").strip()
    password = getpass("Password: ")

    user = users.get(username)

    if user is None or user["password"] != password:
        print("ACCESS DENIED: Invalid credentials.")
        audit("Failed login attempt.")
        return None, None

    if user["revoked"]:
        print("ACCESS DENIED: This user has been revoked.")
        audit("Revoked user attempted login: " + username)
        return None, None

    print("Login successful. Role:", user["role"])
    audit(username + " logged in.")
    return username, user["role"]

def get_aes_key():
    key_text = input("Enter AES key: ")
    key = key_text.encode("utf-8")
    if len(key) > 16:
        print("Key is too long. Enter a key of at most 16 bytes.")
        return None
    key = key.ljust(16, b'\0')
    print("AES key padded to 16 bytes.")
    return key

def get_index_key():
    index_text = getpass("Enter keyword-index secret: ")
    if not index_text:
        print("Index secret cannot be empty.")
        return None
    return hashlib.sha256(index_text.encode("utf-8")).digest()

def normalize_keywords(text):
    return set(re.findall(r"\b[a-z0-9]+\b", text.lower()))

def keyword_token(word, index_key):
    return hmac.new(index_key, word.encode("utf-8"), hashlib.sha256).hexdigest()

def build_index(text, index_key):
    return sorted(keyword_token(word, index_key)
        for word in normalize_keywords(text)
    )

def encrypt_contract(text, key):
    iv = b"\x00" * AES.block_size
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
    return base64.b64encode(encrypted).decode("ascii")

def decrypt_contract(ciphertext, key):
    iv = b"\x00" * AES.block_size
    encrypted = base64.b64decode(ciphertext, validate=True)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(encrypted), AES.block_size)
    return plaintext.decode("utf-8")

def add_contract():
    key = get_aes_key()
    if key is None:
        return

    index_key = get_index_key()
    if index_key is None:
        return

    contract_id = input("Enter contract ID: ").strip()
    client_id = input("Enter client ID: ").strip()
    content = input("Enter contract contents: ").strip()

    if not contract_id or not client_id or not content:
        print("All fields are required.")
        return

    if contract_id in contracts:
        print("Contract ID already exists.")
        return

    original = (
        "Contract ID: " + contract_id + "\n"
        + "Client ID: " + client_id + "\n"
        + "Contents: " + content
    )

    encrypted = encrypt_contract(original, key)
    original_hash = hashlib.sha256(original.encode("utf-8")).hexdigest()

    contracts[contract_id] = {
        "client_id": client_id,
        "ciphertext": encrypted,
        "sha256": original_hash,
        "keyword_index": build_index(original, index_key)
    }

    save_json(CONTRACT_FILE, contracts)

    print("\nContract stored successfully.")
    print("Encrypted ciphertext:", encrypted)
    print("SHA-256 hash:", original_hash)
    print("Searchable keyword index created.")
    audit("Contract added: " + contract_id)

def search_contracts():
    if not contracts:
        print("No contracts available. Add a contract first.")
        return

    index_key = get_index_key()
    search_text = input("Enter keyword or phrase to search: ").strip()

    keywords = normalize_keywords(search_text)

    if not keywords:
        print("Please enter a valid keyword.")
        return

    search_tokens = [
        keyword_token(word, index_key)
        for word in keywords
    ]

    matches = []

    for contract_id, data in contracts.items():
        stored_index = data.get("keyword_index", [])

        # Match when every searched word exists in the index
        if all(token in stored_index for token in search_tokens):
            matches.append(contract_id)

    if matches:
        print("\n===== SEARCH RESULTS =====")
        for contract_id in matches:
            print("Matching Contract ID:", contract_id)
    else:
        print("No matching contracts found.")
        print("Check the index secret and the spelling of your keyword.")

def retrieve_contract():
    contract_id = input("Enter contract ID: ").strip()

    if contract_id not in contracts:
        print("Contract not found.")
        return

    key = get_aes_key()
    if key is None:
        return

    data = contracts[contract_id]

    try:
        plaintext = decrypt_contract(data["ciphertext"], key)
    except (ValueError, TypeError, UnicodeDecodeError):
        print("TAMPERING DETECTED: Decryption or padding failed.")
        audit("Contract decryption failed: " + contract_id)
        return

    current_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    print("\nDecrypted contract:")
    print(plaintext)
    print("\nStored SHA-256:", data["sha256"])
    print("Calculated SHA-256:", current_hash)

    if hmac.compare_digest(current_hash, data["sha256"]):
        print("INTEGRITY VERIFIED: Contract is unchanged.")
        audit("Contract integrity verified: " + contract_id)
    else:
        print("TAMPERING DETECTED: Hash mismatch.")
        audit("Contract hash mismatch: " + contract_id)

def display_hashes():
    if not contracts:
        print("No contracts stored.")
        return

    for contract_id, data in contracts.items():
        print("\nContract ID:", contract_id)
        print("SHA-256:", data["sha256"])

def revoke_user():
    username = input("Enter username to revoke: ").strip()

    if username not in users:
        print("User not found.")
        return

    if users[username]["role"] == "Administrator":
        print("Administrator account cannot be revoked here.")
        return

    users[username]["revoked"] = True
    save_json(USER_FILE, users)
    print("User", username, "has been revoked.")
    audit("User revoked: " + username)


def show_users():
    for username, data in users.items():
        status = "REVOKED" if data["revoked"] else "ACTIVE"
        print(username, "-", data["role"], "-", status)


def tamper_contract():
    contract_id = input("Enter contract ID to tamper with: ").strip()

    if contract_id not in contracts:
        print("Contract not found.")
        return

    ciphertext = contracts[contract_id]["ciphertext"]

    # Change one character in the stored ciphertext for demonstration.
    first = "A" if ciphertext[0] != "A" else "B"
    contracts[contract_id]["ciphertext"] = first + ciphertext[1:]

    save_json(CONTRACT_FILE, contracts)
    print("Ciphertext modified for tampering demonstration.")
    audit("Contract ciphertext modified: " + contract_id)


def view_audit_log():
    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as file:
            print(file.read())
    except FileNotFoundError:
        print("No audit log exists yet.")

def lawyer_menu():
    while True:
        print("\n===== LAWYER MENU =====")
        print("1. Add and encrypt contract")
        print("2. Search contracts by keyword")
        print("3. Retrieve and verify contract")
        print("4. Display stored SHA-256 hashes")
        print("5. Logout")

        choice = input("Enter choice: ")

        match choice:
            case "1":
                add_contract()
            case "2":
                search_contracts()
            case "3":
                retrieve_contract()
            case "4":
                display_hashes()
            case "5":
                break
            case _:
                print("Invalid choice.")


def admin_menu():
    while True:
        print("\n===== ADMINISTRATOR MENU =====")
        print("1. Revoke user")
        print("2. Show users")
        print("3. Tamper with contract (testing)")
        print("4. View audit log")
        print("5. Logout")

        choice = input("Enter choice: ")

        match choice:
            case "1":
                revoke_user()
            case "2":
                show_users()
            case "3":
                tamper_contract()
            case "4":
                view_audit_log()
            case "5":
                break
            case _:
                print("Invalid choice.")

def main():
    global contracts, users

    contracts = load_json(CONTRACT_FILE, {})
    users = load_json(USER_FILE, DEFAULT_USERS.copy())

    # Add default accounts when no user file exists.
    if not os.path.exists(USER_FILE):
        save_json(USER_FILE, users)

    while True:
        print("\n===== SECURE CONTRACT MANAGEMENT =====")
        print("1. Login")
        print("0. Exit")

        choice = input("Enter choice: ")

        match choice:
            case "1":
                username, role = login()

                match role:
                    case "Lawyer":
                        lawyer_menu()
                    case "Administrator":
                        admin_menu()
                    case None:
                        pass
                    case _:
                        print("Access denied: Unknown role.")

            case "0":
                print("Exiting system.")
                break

            case _:
                print("Invalid choice.")


if __name__ == "__main__":
    main()
