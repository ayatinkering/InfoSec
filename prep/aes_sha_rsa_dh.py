'''
A multinational company stores confidential employee documents, financial reports, and contracts on a central server. 
Employees must securely share documents while ensuring that only authorized users can retrieve or modify them.

On the client side:
An employee logs in using stored password hashes.
The employee uploads a document containing a document ID, department, classification, and contents.( all stored in a txt file)
The document is encrypted using AES-CBC with a user-provided string key of any length (must be padded or truncated as requirement)and IV=0. 
The hex key and encrypted text must be displayed
SHA-256 is used to calculate the document hash, and RSA digital signatures are used to authenticate approved documents.(both must be displayed)
The system demonstrates Diffie–Hellman key exchange between two authorized employees.

On the server side:
The server verifies document hashes and digital signatures before accepting a document.
An encrypted searchable index enables searches by department, classification, or keyword.
The application supports key revocation and prevents revoked users from accessing protected documents.
Paillier encryption is used to demonstrate aggregate calculations on encrypted numerical data contained in financial reports.
An administrator can manage users, permissions, keys, and audit records.
Write a menu-driven Python program with Employee, Department Manager, and Administrator roles. Implement encryption, decryption, signing, verification, searching, and role based access control. Demonstrate how a modified document is detected and how a revoked employee is denied access.
'''

import os
import json
import hashlib
import hmac
import math
from datetime import datetime
from getpass import getpass

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

USERS_FILE = "company_users.txt"
DOCUMENTS_FILE = "company_documents.txt"
INDEX_FILE = "company_index.txt"
AUDIT_FILE = "company_audit.txt"

INDEX_SECRET = b"CompanySearchIndexSecret2026"

PA_P = PA_Q = PA_N = PA_N2 = PA_G = PA_LAMBDA = PA_MU = None

def read_file(filename):
    if not os.path.exists(filename):
        return []

    records = []

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return records


def write_file(filename, records):
    with open(filename, "w", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record) + "\n")


def append_file(filename, record):
    with open(filename, "a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")


def audit(username, action, status):
    append_file(AUDIT_FILE, {
        "time": datetime.now().isoformat(timespec="seconds"),
        "username": username,
        "action": action,
        "status": status
    })

def is_prime(number):
    if number < 2:
        return False

    if number in (2, 3):
        return True

    if number % 2 == 0:
        return False

    divisor = 3

    while divisor * divisor <= number:
        if number % divisor == 0:
            return False
        divisor += 2

    return True


def input_prime(message):
    while True:
        try:
            number = int(input(message))

            if is_prime(number):
                return number

            print("Enter a valid prime number.")

        except ValueError:
            print("Enter an integer.")


def input_integer(message):
    while True:
        try:
            return int(input(message))
        except ValueError:
            print("Enter a valid integer.")

def get_rsa_parameters():
    print("\n--- RSA PARAMETERS ---")

    while True:
        p = input_prime("Enter RSA prime p: ")
        q = input_prime("Enter RSA prime q: ")

        if p != q:
            break

        print("p and q must be different.")

    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e = input_integer("Enter public exponent e: ")

        if 1 < e < phi and math.gcd(e, phi) == 1:
            break

        print("e must be greater than 1, less than phi,")
        print("and relatively prime to phi =", phi)

    d = pow(e, -1, phi)

    print("RSA modulus n:", n)
    print("Euler phi(n):", phi)
    print("Public key (e, n):", (e, n))
    print("Private key (d, n):", (d, n))

    return {
        "p": p,
        "q": q,
        "n": n,
        "e": e,
        "d": d
    }


def rsa_sign(text, user):
    parameters = user["rsa"]
    n = parameters["n"]
    d = parameters["d"]

    digest = hashlib.sha256(text.encode("utf-8")).digest()
    digest_number = int.from_bytes(digest, "big") % n

    signature = pow(digest_number, d, n)

    print("SHA-256 HASH:", digest.hex())
    print("RSA SIGNATURE:", signature)

    return signature


def rsa_verify(text, signature, user):
    parameters = user["rsa"]
    n = parameters["n"]
    e = parameters["e"]

    digest = hashlib.sha256(text.encode("utf-8")).digest()
    digest_number = int.from_bytes(digest, "big") % n

    return pow(int(signature), e, n) == digest_number

def setup_paillier():
    global PA_P, PA_Q, PA_N, PA_N2
    global PA_G, PA_LAMBDA, PA_MU

    print("\n--- PAILLIER PARAMETERS ---")

    while True:
        PA_P = input_prime("Enter Paillier prime p: ")
        PA_Q = input_prime("Enter Paillier prime q: ")

        if PA_P != PA_Q:
            break

        print("p and q must be different.")

    PA_N = PA_P * PA_Q
    PA_N2 = PA_N * PA_N
    PA_G = PA_N + 1
    PA_LAMBDA = math.lcm(PA_P - 1, PA_Q - 1)

    value = pow(PA_G, PA_LAMBDA, PA_N2)
    L_value = (value - 1) // PA_N

    if math.gcd(L_value, PA_N) != 1:
        raise ValueError("Invalid Paillier parameters.")

    PA_MU = pow(L_value, -1, PA_N)

    print("Public key (n, g):", (PA_N, PA_G))
    print("Private key lambda:", PA_LAMBDA)
    print("Private key mu:", PA_MU)


def paillier_encrypt(message):
    if not 0 <= message < PA_N:
        raise ValueError(f"Message must be in the range 0 to {PA_N - 1}.")

    while True:
        r = input_integer(
            f"Enter Paillier randomizer r (1 to {PA_N - 1}): "
        )

        if 1 <= r < PA_N and math.gcd(r, PA_N) == 1:
            break

        print("r must be in range and relatively prime to n.")

    ciphertext = (
        pow(PA_G, message, PA_N2)
        * pow(r, PA_N, PA_N2)
    ) % PA_N2

    print("Paillier ciphertext:", ciphertext)

    return ciphertext


def paillier_decrypt(ciphertext):
    value = pow(ciphertext, PA_LAMBDA, PA_N2)
    L_value = (value - 1) // PA_N

    return (L_value * PA_MU) % PA_N


# =========================================================
# INITIAL ADMINISTRATOR SETUP
# =========================================================

def setup_admin():
    if os.path.exists(USERS_FILE):
        return

    print("\nFIRST-TIME SETUP: CREATE ADMINISTRATOR")

    username = input("Administrator username: ").strip()
    password = getpass("Administrator password: ")
    department = input("Administrator department: ").strip()

    rsa_parameters = get_rsa_parameters()

    admin = {
        "username": username,
        "password_hash": hashlib.sha256(
            password.encode()
        ).hexdigest(),
        "role": "Administrator",
        "department": department,
        "revoked": False,
        "rsa": rsa_parameters
    }

    write_file(USERS_FILE, [admin])
    print("Administrator account created.")

def login():
    username = input("Username: ").strip()
    password = getpass("Password: ")

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    for user in read_file(USERS_FILE):
        if user["username"] == username:
            if user["revoked"]:
                print("Access denied: account revoked.")
                audit(username, "Login", "DENIED - REVOKED")
                return None

            if hmac.compare_digest(
                user["password_hash"], password_hash
            ):
                print("Login successful.")
                audit(username, "Login", "SUCCESS")
                return user

            print("Incorrect password.")
            audit(username, "Login", "FAILED")
            return None

    print("User not found.")
    return None


def get_active_user(username):
    for user in read_file(USERS_FILE):
        if user["username"] == username and not user["revoked"]:
            return user

    return None

def prepare_aes_key(user_key):
    if not user_key:
        raise ValueError("AES key cannot be empty.")

    key = user_key.encode("utf-8")

    # Truncate to 32 bytes or pad with zero bytes.
    key = key[:32].ljust(32, b"\0")

    return key


def aes_encrypt(plaintext, user_key):
    key = prepare_aes_key(user_key)
    iv = b"\x00" * 16

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(
        pad(plaintext.encode("utf-8"), AES.block_size)
    )

    print("AES KEY (HEX):", key.hex())
    print("ENCRYPTED TEXT (HEX):", ciphertext.hex())

    return ciphertext.hex()


def aes_decrypt(ciphertext_hex, user_key):
    key = prepare_aes_key(user_key)
    iv = b"\x00" * 16

    ciphertext = bytes.fromhex(ciphertext_hex)

    if not ciphertext or len(ciphertext) % AES.block_size != 0:
        raise ValueError("Invalid ciphertext length.")

    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return plaintext.decode("utf-8")


# =========================================================
# ENCRYPTED SEARCH INDEX
# =========================================================

def search_token(value):
    normalized = value.strip().lower().encode("utf-8")

    return hmac.new(
        INDEX_SECRET,
        normalized,
        hashlib.sha256
    ).hexdigest()


def add_to_index(document):
    index = read_file(INDEX_FILE)

    words = [
        document["department"],
        document["classification"]
    ]

    words.extend(document["contents"].lower().split())

    tokens = list({
        search_token(word.strip(".,!?;:()[]{}\"'"))
        for word in words
        if word.strip(".,!?;:()[]{}\"'")
    })

    index.append({
        "document_id": document["document_id"],
        "tokens": tokens
    })

    write_file(INDEX_FILE, index)


def can_access(user, document):
    match user["role"]:
        case "Administrator":
            return True

        case "Department Manager":
            return (
                user["department"].lower()
                == document["department"].lower()
            )

        case "Employee":
            same_department = (
                user["department"].lower()
                == document["department"].lower()
            )

            not_restricted = (
                document["classification"].lower() != "restricted"
            )

            return same_department and not_restricted

        case _:
            return False


def search_documents(user):
    query = input(
        "Enter department, classification, or exact keyword: "
    ).strip()

    token = search_token(query)

    index = read_file(INDEX_FILE)
    documents = read_file(DOCUMENTS_FILE)

    matching_ids = {
        item["document_id"]
        for item in index
        if token in item["tokens"]
    }

    found = False

    for document in documents:
        if (
            document["document_id"] in matching_ids
            and can_access(user, document)
        ):
            print("Matching document:", document["document_id"])
            found = True

    if not found:
        print("No accessible matching documents.")

    audit(user["username"], "Search", "COMPLETED")


# =========================================================
# UPLOAD DOCUMENT
# =========================================================

def upload_document(user):
    document_id = input("Document ID: ").strip()

    documents = read_file(DOCUMENTS_FILE)

    if not document_id:
        print("Document ID cannot be empty.")
        return

    if any(d["document_id"] == document_id for d in documents):
        print("Document ID already exists.")
        return

    department = input("Department: ").strip()

    classification = input(
        "Classification (Public/Confidential/Restricted): "
    ).strip()

    match classification.lower():
        case "public":
            classification = "Public"

        case "confidential":
            classification = "Confidential"

        case "restricted":
            classification = "Restricted"

        case _:
            print("Invalid classification.")
            return

    if user["role"] != "Administrator":
        if department.lower() != user["department"].lower():
            print("You can upload only to your own department.")
            return

    contents = input("Document contents: ")

    document_data = {
        "document_id": document_id,
        "department": department,
        "classification": classification,
        "contents": contents
    }

    plaintext = json.dumps(document_data, sort_keys=True)

    aes_key = input("Enter AES string key: ")

    try:
        ciphertext = aes_encrypt(plaintext, aes_key)
    except ValueError as error:
        print("Encryption error:", error)
        return

    document_hash = hashlib.sha256(
        plaintext.encode("utf-8")
    ).hexdigest()

    print("SHA-256 HASH:", document_hash)

    signature = rsa_sign(plaintext, user)

    financial_value = input_integer(f"Enter financial value (0 to {PA_N - 1}): ")

    if not 0 <= financial_value < PA_N:
        print("Financial value is outside the allowed range.")
        return

    financial_ciphertext = paillier_encrypt(financial_value)

    record = {
        "document_id": document_id,
        "department": department,
        "classification": classification,
        "ciphertext": ciphertext,
        "hash": document_hash,
        "signature": signature,
        "signer": user["username"],
        "financial_ciphertext": financial_ciphertext
    }

    append_file(DOCUMENTS_FILE, record)

    document_data["contents"] = contents
    add_to_index(document_data)

    print("Document encrypted and stored successfully.")
    audit(user["username"], "Upload", "SUCCESS")

def verify_document(document, plaintext):
    actual_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    if not hmac.compare_digest(actual_hash, document["hash"]):
        print("HASH VERIFICATION FAILED.")
        print("Document may have been modified.")
        return False

    signer = None

    for account in read_file(USERS_FILE):
        if account["username"] == document["signer"]:
            signer = account
            break

    if signer is None or signer["revoked"]:
        print("Signature rejected: signer unavailable or revoked.")
        return False

    if rsa_verify(plaintext, document["signature"], signer):
        print("SHA-256 hash verified.")
        print("RSA signature verified.")
        return True

    print("RSA signature verification failed.")
    return False

def retrieve_document(user):
    document_id = input("Document ID: ").strip()

    documents = read_file(DOCUMENTS_FILE)

    document = next((d for d in documents if d["document_id"] == document_id),None)

    if document is None:
        print("Document not found.")
        return

    fresh_user = get_active_user(user["username"])

    if fresh_user is None:
        print("Access denied: account revoked.")
        return

    if not can_access(fresh_user, document):
        print("Access denied: insufficient permissions.")
        audit(user["username"], "Retrieve", "DENIED")
        return

    if document["classification"].lower() == "restricted":
        if fresh_user["role"] not in [
            "Department Manager", "Administrator"
        ]:
            print("Access denied: restricted document.")
            return

    aes_key = getpass("Enter AES key used during upload: ")

    try:
        plaintext = aes_decrypt(document["ciphertext"], aes_key)
    except (ValueError, UnicodeDecodeError):
        print("Decryption failed: incorrect key or corrupted data.")
        return

    print("\nDECRYPTED DOCUMENT:")
    print(plaintext)

    if verify_document(document, plaintext):
        print("SERVER ACCEPTED DOCUMENT.")
    else:
        print("SERVER REJECTED DOCUMENT.")

    audit(user["username"], "Retrieve", "COMPLETED")


def verify_saved_document(user):
    document_id = input("Document ID: ").strip()

    documents = read_file(DOCUMENTS_FILE)

    document = next(
        (d for d in documents if d["document_id"] == document_id),
        None
    )

    if document is None:
        print("Document not found.")
        return

    if not can_access(user, document):
        print("Access denied.")
        return

    aes_key = getpass("Enter AES key: ")

    try:
        plaintext = aes_decrypt(document["ciphertext"], aes_key)
    except (ValueError, UnicodeDecodeError):
        print("Decryption failed.")
        return

    verify_document(document, plaintext)


# =========================================================
# DIFFIE-HELLMAN - USER-ENTERED PARAMETERS
# =========================================================

def diffie_hellman(user):
    print("\n--- DIFFIE-HELLMAN KEY EXCHANGE ---")

    p = input_prime("Enter prime p: ")

    g = input_integer("Enter generator g: ")

    if not 1 < g < p:
        print("g must be greater than 1 and less than p.")
        return

    a = input_integer("Enter Employee A private value: ")
    b = input_integer("Enter Employee B private value: ")

    if not (1 <= a <= p - 2 and 1 <= b <= p - 2):
        print("Private values must be between 1 and p-2.")
        return

    public_a = pow(g, a, p)
    public_b = pow(g, b, p)

    shared_a = pow(public_b, a, p)
    shared_b = pow(public_a, b, p)

    print("Employee A public value:", public_a)
    print("Employee B public value:", public_b)
    print("Employee A shared secret:", shared_a)
    print("Employee B shared secret:", shared_b)
    print("Shared secrets match:", shared_a == shared_b)

    audit(user["username"], "Diffie-Hellman", "SUCCESS")


# =========================================================
# PAILLIER AGGREGATION
# =========================================================

def aggregate_financial_data(user):
    if user["role"] not in ["Department Manager", "Administrator"]:
        print("Access denied: manager or administrator required.")
        return

    documents = read_file(DOCUMENTS_FILE)

    encrypted_values = [
        d["financial_ciphertext"]
        for d in documents
        if (
            user["role"] == "Administrator"
            or d["department"].lower() == user["department"].lower()
        )
    ]

    if not encrypted_values:
        print("No financial values found.")
        return

    aggregate_ciphertext = 1

    for ciphertext in encrypted_values:
        aggregate_ciphertext = (
            aggregate_ciphertext * ciphertext
        ) % PA_N2

    print("Aggregate ciphertext:", aggregate_ciphertext)

    total = paillier_decrypt(aggregate_ciphertext)

    print("Decrypted aggregate total:", total)
    print("Individual values were not decrypted separately.")

    audit(user["username"], "Paillier aggregation", "SUCCESS")


# =========================================================
# ADMINISTRATOR FUNCTIONS
# =========================================================

def add_user(user):
    if user["role"] != "Administrator":
        print("Access denied.")
        return

    username = input("New username: ").strip()

    users = read_file(USERS_FILE)

    if not username or any(
        account["username"] == username for account in users
    ):
        print("Invalid or duplicate username.")
        return

    password = getpass("New password: ")

    print("1. Employee")
    print("2. Department Manager")
    print("3. Administrator")

    role_choice = input("Select role: ")

    match role_choice:
        case "1":
            role = "Employee"

        case "2":
            role = "Department Manager"

        case "3":
            role = "Administrator"

        case _:
            print("Invalid role.")
            return

    department = input("Department: ").strip()

    print("Enter RSA parameters for the new user.")
    rsa_parameters = get_rsa_parameters()

    new_user = {
        "username": username,
        "password_hash": hashlib.sha256(
            password.encode()
        ).hexdigest(),
        "role": role,
        "department": department,
        "revoked": False,
        "rsa": rsa_parameters
    }

    users.append(new_user)
    write_file(USERS_FILE, users)

    print("User created successfully.")
    audit(user["username"], "Add user " + username, "SUCCESS")


def revoke_user(user):
    if user["role"] != "Administrator":
        print("Access denied.")
        return

    target = input("Username to revoke: ").strip()

    if target == user["username"]:
        print("You cannot revoke your own account.")
        return

    users = read_file(USERS_FILE)

    for account in users:
        if account["username"] == target:
            account["revoked"] = True
            write_file(USERS_FILE, users)

            print("User revoked successfully.")
            audit(user["username"], "Revoke " + target, "SUCCESS")
            return

    print("User not found.")


def view_audit(user):
    if user["role"] != "Administrator":
        print("Access denied.")
        return

    for record in read_file(AUDIT_FILE):
        print(record)


def tamper_demo(user):
    if user["role"] != "Administrator":
        print("Access denied.")
        return

    documents = read_file(DOCUMENTS_FILE)

    if not documents:
        print("Upload a document first.")
        return

    document_id = input("Document ID to tamper with: ").strip()

    for document in documents:
        if document["document_id"] == document_id:
            ciphertext = bytearray(
                bytes.fromhex(document["ciphertext"])
            )

            ciphertext[0] ^= 1
            document["ciphertext"] = ciphertext.hex()

            write_file(DOCUMENTS_FILE, documents)

            print("Ciphertext modified deliberately.")
            print("Try retrieving the document to detect tampering.")

            audit(user["username"], "Tamper demonstration", "SUCCESS")
            return

    print("Document not found.")


def change_password(user):
    old_password = getpass("Current password: ")
    new_password = getpass("New password: ")

    users = read_file(USERS_FILE)

    for account in users:
        if account["username"] == user["username"]:
            old_hash = hashlib.sha256(
                old_password.encode()
            ).hexdigest()

            if not hmac.compare_digest(
                old_hash, account["password_hash"]
            ):
                print("Incorrect current password.")
                return

            account["password_hash"] = hashlib.sha256(
                new_password.encode()
            ).hexdigest()

            write_file(USERS_FILE, users)

            print("Password changed.")
            audit(user["username"], "Change password", "SUCCESS")
            return


# =========================================================
# EMPLOYEE MENU
# =========================================================

def employee_menu(user):
    while True:
        if get_active_user(user["username"]) is None:
            print("Account revoked. Logging out.")
            return

        print("\n===== EMPLOYEE MENU =====")
        print("1. Upload document")
        print("2. Retrieve document")
        print("3. Search documents")
        print("4. Verify document")
        print("5. Diffie-Hellman exchange")
        print("6. Change password")
        print("7. Logout")

        choice = input("Enter choice: ")

        match choice:
            case "1":
                upload_document(user)

            case "2":
                retrieve_document(user)

            case "3":
                search_documents(user)

            case "4":
                verify_saved_document(user)

            case "5":
                diffie_hellman(user)

            case "6":
                change_password(user)

            case "7":
                audit(user["username"], "Logout", "SUCCESS")
                return

            case _:
                print("Invalid choice.")


# =========================================================
# DEPARTMENT MANAGER MENU
# =========================================================

def manager_menu(user):
    while True:
        if get_active_user(user["username"]) is None:
            print("Account revoked. Logging out.")
            return

        print("\n===== DEPARTMENT MANAGER MENU =====")
        print("1. Upload document")
        print("2. Retrieve document")
        print("3. Search documents")
        print("4. Verify document")
        print("5. Diffie-Hellman exchange")
        print("6. Paillier financial aggregation")
        print("7. Change password")
        print("8. Logout")

        choice = input("Enter choice: ")

        match choice:
            case "1":
                upload_document(user)

            case "2":
                retrieve_document(user)

            case "3":
                search_documents(user)

            case "4":
                verify_saved_document(user)

            case "5":
                diffie_hellman(user)

            case "6":
                aggregate_financial_data(user)

            case "7":
                change_password(user)

            case "8":
                audit(user["username"], "Logout", "SUCCESS")
                return

            case _:
                print("Invalid choice.")


# =========================================================
# ADMINISTRATOR MENU
# =========================================================

def administrator_menu(user):
    while True:
        if get_active_user(user["username"]) is None:
            print("Account revoked. Logging out.")
            return

        print("\n===== ADMINISTRATOR MENU =====")
        print("1. Add user")
        print("2. Revoke user")
        print("3. Upload document")
        print("4. Retrieve document")
        print("5. Search documents")
        print("6. Verify document")
        print("7. Diffie-Hellman exchange")
        print("8. Paillier financial aggregation")
        print("9. View audit log")
        print("10. Demonstrate tampering")
        print("11. Change password")
        print("12. Logout")

        choice = input("Enter choice: ")

        match choice:
            case "1":
                add_user(user)

            case "2":
                revoke_user(user)

            case "3":
                upload_document(user)

            case "4":
                retrieve_document(user)

            case "5":
                search_documents(user)

            case "6":
                verify_saved_document(user)

            case "7":
                diffie_hellman(user)

            case "8":
                aggregate_financial_data(user)

            case "9":
                view_audit(user)

            case "10":
                tamper_demo(user)

            case "11":
                change_password(user)

            case "12":
                audit(user["username"], "Logout", "SUCCESS")
                return

            case _:
                print("Invalid choice.")


# =========================================================
# MAIN MENU
# =========================================================

def main():
    setup_paillier()
    setup_admin()

    while True:
        print("\n===== COMPANY SECURITY SYSTEM =====")
        print("1. Login")
        print("2. Exit")

        choice = input("Enter choice: ")

        match choice:
            case "1":
                user = login()

                if user is not None:
                    match user["role"]:
                        case "Employee":
                            employee_menu(user)

                        case "Department Manager":
                            manager_menu(user)

                        case "Administrator":
                            administrator_menu(user)

                        case _:
                            print("Unknown role.")

            case "2":
                print("Application closed.")
                break

            case _:
                print("Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, ZeroDivisionError) as error:
        print("Configuration or input error:", error)