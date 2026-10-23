#It uses Diffie–Hellman to derive a 32-byte AES key, stores encrypted document contents and metadata in .txt files, calculates RSA keys from user inputs, and uses match-case for the menus.
import os
import json
import math
import hashlib
import hmac
from datetime import datetime
from getpass import getpass

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

USERS_FILE = "users.txt"
DOCUMENTS_FILE = "documents.txt"
INDEX_FILE = "search_index.txt"
AUDIT_FILE = "audit_log.txt"

INDEX_SECRET = b"CompanySearchIndex2026"

def read_file(filename):
    records = []

    if os.path.exists(filename):
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


# ============================================================
# PASSWORD HASHING AND USER INITIALIZATION
# ============================================================

def password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


def initialize():
    if os.path.exists(USERS_FILE):
        return

    users = [
        {
            "username": "emp1",
            "password": password_hash("emp123"),
            "role": "Employee",
            "department": "Sales",
            "revoked": False
        },
        {
            "username": "emp2",
            "password": password_hash("emp456"),
            "role": "Employee",
            "department": "Finance",
            "revoked": False
        },
        {
            "username": "manager1",
            "password": password_hash("mgr123"),
            "role": "Department Manager",
            "department": "Finance",
            "revoked": False
        },
        {
            "username": "admin",
            "password": password_hash("admin123"),
            "role": "Administrator",
            "department": "Administration",
            "revoked": False
        }
    ]

    write_file(USERS_FILE, users)

    print("Default users created.")
    print("emp1 / emp123")
    print("emp2 / emp456")
    print("manager1 / mgr123")
    print("admin / admin123")


# ============================================================
# LOGIN
# ============================================================

def login():
    username = input("Username: ").strip()
    password = getpass("Password: ")

    users = read_file(USERS_FILE)

    for user in users:
        if user["username"] == username:

            if user["revoked"]:
                print("Access denied: account revoked.")
                audit(username, "Login", "REVOKED")
                return None

            if hmac.compare_digest(
                user["password"], password_hash(password)
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


# ============================================================
# ROLE-BASED ACCESS CONTROL
# ============================================================

def can_access(user, document):
    if user["revoked"]:
        return False

    if user["role"] == "Administrator":
        return True

    if user["department"].lower() != document["department"].lower():
        return False

    if document["classification"].lower() == "restricted":
        return user["role"] == "Department Manager"

    return user["role"] in ["Employee", "Department Manager"]


# ============================================================
# PRIME NUMBER VALIDATION
# ============================================================

def is_prime(n):
    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    i = 3

    while i * i <= n:
        if n % i == 0:
            return False
        i += 2

    return True


# ============================================================
# DIFFIE-HELLMAN KEY EXCHANGE
# ============================================================

def get_dh_parameters():
    print("\n===== DIFFIE-HELLMAN =====")

    try:
        p = int(input("Enter prime p: "))
        g = int(input("Enter generator g: "))
        a = int(input("Enter Employee A private value a: "))
        b = int(input("Enter Employee B private value b: "))
    except ValueError:
        print("Enter integers only.")
        return None

    if not is_prime(p):
        print("p must be prime.")
        return None

    if not 1 < g < p:
        print("Invalid generator.")
        return None

    if not (1 <= a <= p - 2 and 1 <= b <= p - 2):
        print("Private values must be between 1 and p-2.")
        return None

    A = pow(g, a, p)
    B = pow(g, b, p)

    secret_a = pow(B, a, p)
    secret_b = pow(A, b, p)

    print("Employee A public value:", A)
    print("Employee B public value:", B)
    print("Employee A shared secret:", secret_a)
    print("Employee B shared secret:", secret_b)

    if secret_a != secret_b:
        print("Key exchange failed.")
        return None

    # Convert the shared secret into a 32-byte AES key.
    # This is an educational key-derivation demonstration.
    shared_bytes = secret_a.to_bytes(
        max(1, (secret_a.bit_length() + 7) // 8), "big"
    )

    aes_key = hashlib.sha256(shared_bytes).digest()

    print("AES-256 KEY (HEX):", aes_key.hex())

    return {
        "p": p,
        "g": g,
        "A": A,
        "B": B,
        "aes_key": aes_key
    }


def derive_saved_dh_key(document):
    print("\n===== RECREATE DIFFIE-HELLMAN KEY =====")

    try:
        private_value = int(
            input("Enter your private value (a or b): ")
        )
    except ValueError:
        print("Invalid private value.")
        return None

    p = document["dh_p"]
    g = document["dh_g"]
    A = document["dh_A"]
    B = document["dh_B"]

    if not 1 <= private_value <= p - 2:
        print("Invalid private value.")
        return None

    # Identify which public value belongs to the entered private value.
    calculated_public = pow(g, private_value, p)

    if calculated_public == A:
        shared_secret = pow(B, private_value, p)
    elif calculated_public == B:
        shared_secret = pow(A, private_value, p)
    else:
        print("Private value does not match either public value.")
        return None

    shared_bytes = shared_secret.to_bytes(
        max(1, (shared_secret.bit_length() + 7) // 8), "big"
    )

    aes_key = hashlib.sha256(shared_bytes).digest()

    print("Recreated AES KEY (HEX):", aes_key.hex())

    return aes_key


# ============================================================
# AES-CBC ENCRYPTION AND DECRYPTION
# ============================================================

def aes_encrypt(plaintext, aes_key):
    iv = b"\x00" * 16

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(
        pad(plaintext.encode("utf-8"), AES.block_size)
    )

    print("AES KEY (HEX):", aes_key.hex())
    print("IV (HEX):", iv.hex())
    print("CIPHERTEXT (HEX):", ciphertext.hex())

    return ciphertext.hex()


def aes_decrypt(ciphertext_hex, aes_key):
    iv = b"\x00" * 16

    ciphertext = bytes.fromhex(ciphertext_hex)

    if not ciphertext or len(ciphertext) % AES.block_size != 0:
        raise ValueError("Invalid AES ciphertext length.")

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return plaintext.decode("utf-8")


# ============================================================
# RSA KEY CALCULATION
# ============================================================

def get_rsa_parameters():
    print("\n===== RSA KEY CALCULATION =====")

    try:
        p = int(input("Enter RSA prime p: "))
        q = int(input("Enter RSA prime q: "))
        e = int(input("Enter public exponent e: "))
    except ValueError:
        print("Enter integers only.")
        return None

    if not is_prime(p) or not is_prime(q) or p == q:
        print("p and q must be distinct primes.")
        return None

    n = p * q
    phi = (p - 1) * (q - 1)

    if not 1 < e < phi or math.gcd(e, phi) != 1:
        print("Invalid e. It must be coprime with phi(n).")
        return None

    d = pow(e, -1, phi)

    print("n =", n)
    print("phi(n) =", phi)
    print("Public exponent e =", e)
    print("Private exponent d =", d)

    return {"n": n, "e": e, "d": d}


# ============================================================
# RSA SIGNATURE DEMONSTRATION
# ============================================================

def rsa_sign(text, n, d):
    digest = hashlib.sha256(text.encode()).digest()
    hash_number = int.from_bytes(digest, "big") % n

    signature = pow(hash_number, d, n)

    print("SHA-256 HASH:", digest.hex())
    print("RSA SIGNATURE:", signature)

    return signature


def rsa_verify(text, signature, n, e):
    digest = hashlib.sha256(text.encode()).digest()
    hash_number = int.from_bytes(digest, "big") % n

    return pow(signature, e, n) == hash_number


# ============================================================
# ENCRYPTED SEARCH INDEX
# ============================================================

def search_token(value):
    return hmac.new(
        INDEX_SECRET,
        value.lower().strip().encode(),
        hashlib.sha256
    ).hexdigest()


def add_to_index(document_id, department, classification, contents):
    index = read_file(INDEX_FILE)

    words = [
        department,
        classification
    ]

    words.extend(contents.split())

    tokens = sorted({
        search_token(word.strip(".,!?;:()[]{}\"'"))
        for word in words
        if word.strip(".,!?;:()[]{}\"'")
    })

    index.append({
        "document_id": document_id,
        "tokens": tokens
    })

    write_file(INDEX_FILE, index)


def search_documents(user):
    query = input(
        "Enter department, classification, or keyword: "
    ).strip()

    token = search_token(query)
    index = read_file(INDEX_FILE)
    documents = read_file(DOCUMENTS_FILE)

    matches = {
        entry["document_id"]
        for entry in index
        if token in entry["tokens"]
    }

    found = False

    for document in documents:
        if (
            document["document_id"] in matches
            and can_access(user, document)
        ):
            print(
                "Matching document:",
                document["document_id"],
                "| Department:", document["department"],
                "| Classification:", document["classification"]
            )
            found = True

    if not found:
        print("No accessible matching documents.")

    audit(user["username"], "Search", "COMPLETED")


# ============================================================
# UPLOAD DOCUMENT
# ============================================================

def upload_document(user):
    if user["role"] not in ["Employee", "Department Manager"]:
        print("Administrator cannot upload through this menu.")
        return

    document_id = input("Document ID: ").strip()

    documents = read_file(DOCUMENTS_FILE)

    if not document_id:
        print("Document ID cannot be empty.")
        return

    if any(d["document_id"] == document_id for d in documents):
        print("Document ID already exists.")
        return

    department = input("Department: ").strip()

    if department.lower() != user["department"].lower():
        print("You can upload only to your own department.")
        return

    classification = input(
        "Classification (Public/Confidential/Restricted): "
    ).strip()

    if classification.lower() not in [
        "public", "confidential", "restricted"
    ]:
        print("Invalid classification.")
        return

    contents = input("Enter document contents: ")

    dh = get_dh_parameters()

    if dh is None:
        return

    rsa = get_rsa_parameters()

    if rsa is None:
        return

    # Entire logical document is encrypted.
    plaintext = json.dumps({
        "document_id": document_id,
        "department": department,
        "classification": classification,
        "contents": contents
    }, sort_keys=True)

    ciphertext = aes_encrypt(plaintext, dh["aes_key"])
    digest = hashlib.sha256(plaintext.encode()).hexdigest()

    signature = rsa_sign(
        plaintext,
        rsa["n"],
        rsa["d"]
    )

    document = {
        "document_id": document_id,
        "department": department,
        "classification": classification,

        # The contents are stored encrypted, not as plaintext.
        "ciphertext": ciphertext,
        "hash": digest,

        "signature": signature,
        "rsa_n": rsa["n"],
        "rsa_e": rsa["e"],

        # Public DH parameters are retained for later key recreation.
        "dh_p": dh["p"],
        "dh_g": dh["g"],
        "dh_A": dh["A"],
        "dh_B": dh["B"],

        "signer": user["username"]
    }

    append_file(DOCUMENTS_FILE, document)

    add_to_index(
        document_id, department, classification, contents
    )

    print("\nDocument saved successfully in", DOCUMENTS_FILE)
    print("Plaintext contents are not stored in that file.")
    print("Encrypted contents, hash, signature and metadata are stored.")

    audit(user["username"], "Upload", "SUCCESS")


# ============================================================
# RETRIEVE AND VERIFY DOCUMENT
# ============================================================

def retrieve_document(user):
    document_id = input("Enter document ID: ").strip()

    documents = read_file(DOCUMENTS_FILE)

    document = next(
        (
            d for d in documents
            if d["document_id"] == document_id
        ),
        None
    )

    if document is None:
        print("Document not found.")
        return

    fresh_user = get_active_user(user["username"])

    if fresh_user is None:
        print("Access denied: account revoked.")
        return

    if not can_access(fresh_user, document):
        print("Access denied by role or department.")
        audit(user["username"], "Retrieve", "DENIED")
        return

    aes_key = derive_saved_dh_key(document)

    if aes_key is None:
        return

    try:
        plaintext = aes_decrypt(
            document["ciphertext"],
            aes_key
        )
    except (ValueError, UnicodeDecodeError):
        print("Decryption failed.")
        return

    print("\nDECRYPTED DOCUMENT:")
    print(plaintext)

    actual_hash = hashlib.sha256(plaintext.encode()).hexdigest()

    if not hmac.compare_digest(actual_hash, document["hash"]):
        print("HASH VERIFICATION FAILED.")
        print("The document may have been modified.")
        audit(user["username"], "Verify hash", "FAILED")
        return

    print("SHA-256 hash verified.")

    if rsa_verify(
        plaintext,
        document["signature"],
        document["rsa_n"],
        document["rsa_e"]
    ):
        print("RSA signature verified.")
        print("SERVER ACCEPTED DOCUMENT.")
    else:
        print("RSA signature verification failed.")
        print("SERVER REJECTED DOCUMENT.")

    audit(user["username"], "Retrieve", "COMPLETED")


# ============================================================
# VERIFY A DOCUMENT
# ============================================================

def verify_document(user):
    document_id = input("Document ID: ").strip()

    documents = read_file(DOCUMENTS_FILE)

    document = next(
        (
            d for d in documents
            if d["document_id"] == document_id
        ),
        None
    )

    if document is None:
        print("Document not found.")
        return

    if not can_access(user, document):
        print("Access denied.")
        return

    aes_key = derive_saved_dh_key(document)

    if aes_key is None:
        return

    try:
        plaintext = aes_decrypt(document["ciphertext"], aes_key)
    except (ValueError, UnicodeDecodeError):
        print("Decryption failed.")
        return

    actual_hash = hashlib.sha256(plaintext.encode()).hexdigest()

    if not hmac.compare_digest(actual_hash, document["hash"]):
        print("Document hash mismatch.")
        return

    print("Document hash verified.")

    if rsa_verify(
        plaintext,
        document["signature"],
        document["rsa_n"],
        document["rsa_e"]
    ):
        print("Digital signature verified.")
    else:
        print("Digital signature invalid.")


# ============================================================
# PAILLIER PARAMETERS
# ============================================================

def get_paillier_parameters():
    print("\n===== PAILLIER PARAMETERS =====")

    try:
        p = int(input("Enter Paillier prime p: "))
        q = int(input("Enter Paillier prime q: "))
    except ValueError:
        print("Enter integers only.")
        return None

    if not is_prime(p) or not is_prime(q) or p == q:
        print("p and q must be distinct primes.")
        return None

    n = p * q
    n2 = n * n
    g = n + 1

    lam = math.lcm(p - 1, q - 1)
    value = pow(g, lam, n2)
    L_value = (value - 1) // n

    if math.gcd(L_value, n) != 1:
        print("Invalid Paillier parameters.")
        return None

    mu = pow(L_value, -1, n)

    print("n =", n)
    print("g =", g)
    print("lambda =", lam)
    print("mu =", mu)

    return {
        "n": n,
        "n2": n2,
        "g": g,
        "lambda": lam,
        "mu": mu
    }


def paillier_encrypt(value, params):
    n = params["n"]
    n2 = params["n2"]
    g = params["g"]

    try:
        r = int(input("Enter Paillier randomizer r: "))
    except ValueError:
        print("Enter an integer.")
        return None

    if not 1 <= r < n or math.gcd(r, n) != 1:
        print("r must satisfy 1 <= r < n and gcd(r,n)=1.")
        return None

    return (
        pow(g, value, n2) * pow(r, n, n2)
    ) % n2


def paillier_decrypt(ciphertext, params):
    n = params["n"]
    n2 = params["n2"]

    value = pow(ciphertext, params["lambda"], n2)
    L_value = (value - 1) // n

    return (L_value * params["mu"]) % n


# ============================================================
# FINANCIAL AGGREGATION
# ============================================================

def aggregate_financial_data(user):
    if user["role"] not in ["Department Manager", "Administrator"]:
        print("Access denied.")
        return

    params = get_paillier_parameters()

    if params is None:
        return

    try:
        count = int(input("Number of financial values: "))
    except ValueError:
        print("Invalid count.")
        return

    if count <= 0:
        print("Count must be positive.")
        return

    encrypted_values = []

    for i in range(count):
        try:
            value = int(input(f"Enter financial value {i + 1}: "))
        except ValueError:
            print("Invalid value.")
            return

        if not 0 <= value < params["n"]:
            print("Each value must be between 0 and n-1.")
            return

        ciphertext = paillier_encrypt(value, params)

        if ciphertext is None:
            return

        encrypted_values.append(ciphertext)

        print("Encrypted value:", ciphertext)

    total_ciphertext = 1

    for ciphertext in encrypted_values:
        total_ciphertext = (
            total_ciphertext * ciphertext
        ) % params["n2"]

    print("Aggregated ciphertext:", total_ciphertext)

    total = paillier_decrypt(total_ciphertext, params)

    print("Decrypted aggregate:", total)
    print("Expected sum:", sum([
        int(input_value)
        for input_value in []
    ]) if False else "See the total above.")

    audit(user["username"], "Paillier aggregation", "SUCCESS")


# ============================================================
# ADD USER
# ============================================================

def add_user(user):
    if user["role"] != "Administrator":
        print("Administrator access required.")
        return

    username = input("New username: ").strip()

    users = read_file(USERS_FILE)

    if not username or any(
        u["username"] == username for u in users
    ):
        print("Invalid or existing username.")
        return

    password = getpass("New password: ")

    print("1. Employee")
    print("2. Department Manager")
    print("3. Administrator")

    role_choice = input("Choose role: ")

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

    users.append({
        "username": username,
        "password": password_hash(password),
        "role": role,
        "department": department,
        "revoked": False
    })

    write_file(USERS_FILE, users)

    audit(user["username"], "Add user", "SUCCESS")
    print("User added.")


# ============================================================
# REVOKE USER
# ============================================================

def revoke_user(user):
    if user["role"] != "Administrator":
        print("Administrator access required.")
        return

    username = input("Username to revoke: ").strip()

    if username == user["username"]:
        print("Cannot revoke your own active account.")
        return

    users = read_file(USERS_FILE)

    for account in users:
        if account["username"] == username:
            account["revoked"] = True
            write_file(USERS_FILE, users)

            audit(user["username"], "Revoke " + username, "SUCCESS")
            print("User revoked.")
            return

    print("User not found.")


# ============================================================
# MANAGE PERMISSIONS
# ============================================================

def manage_permissions(user):
    if user["role"] != "Administrator":
        print("Administrator access required.")
        return

    username = input("Username: ").strip()
    users = read_file(USERS_FILE)

    for account in users:
        if account["username"] == username:
            print("1. Employee")
            print("2. Department Manager")
            print("3. Administrator")

            choice = input("New role: ")

            match choice:
                case "1":
                    account["role"] = "Employee"
                case "2":
                    account["role"] = "Department Manager"
                case "3":
                    account["role"] = "Administrator"
                case _:
                    print("Invalid role.")
                    return

            account["department"] = input("Department: ").strip()

            write_file(USERS_FILE, users)
            audit(user["username"], "Manage permissions", "SUCCESS")
            print("Permissions updated.")
            return

    print("User not found.")


# ============================================================
# AUDIT LOG
# ============================================================

def view_audit_log(user):
    if user["role"] != "Administrator":
        print("Administrator access required.")
        return

    for entry in read_file(AUDIT_FILE):
        print(entry)


# ============================================================
# TAMPERING DEMONSTRATION
# ============================================================

def tamper_demo(user):
    if user["role"] != "Administrator":
        print("Administrator access required.")
        return

    document_id = input("Document ID to modify: ").strip()
    documents = read_file(DOCUMENTS_FILE)

    for document in documents:
        if document["document_id"] == document_id:
            ciphertext = bytearray(
                bytes.fromhex(document["ciphertext"])
            )

            ciphertext[0] ^= 1
            document["ciphertext"] = ciphertext.hex()

            write_file(DOCUMENTS_FILE, documents)

            print("Ciphertext modified.")
            print("Retrieve the document to demonstrate failure.")

            audit(user["username"], "Tampering demo", "SUCCESS")
            return

    print("Document not found.")


# ============================================================
# PASSWORD CHANGE
# ============================================================

def change_password(user):
    old_password = getpass("Current password: ")
    new_password = getpass("New password: ")

    users = read_file(USERS_FILE)

    for account in users:
        if account["username"] == user["username"]:
            if not hmac.compare_digest(
                account["password"], password_hash(old_password)
            ):
                print("Incorrect password.")
                return

            account["password"] = password_hash(new_password)

            write_file(USERS_FILE, users)

            audit(user["username"], "Change password", "SUCCESS")
            print("Password changed.")
            return


# ============================================================
# ROLE-SPECIFIC MENUS
# ============================================================

def employee_menu(user):
    while True:
        print("\n===== EMPLOYEE MENU =====")
        print("1. Upload document")
        print("2. Retrieve document")
        print("3. Search documents")
        print("4. Verify document")
        print("5. Change password")
        print("6. Logout")

        choice = input("Choice: ")

        match choice:
            case "1":
                upload_document(user)
            case "2":
                retrieve_document(user)
            case "3":
                search_documents(user)
            case "4":
                verify_document(user)
            case "5":
                change_password(user)
            case "6":
                break
            case _:
                print("Invalid choice.")


def manager_menu(user):
    while True:
        print("\n===== DEPARTMENT MANAGER MENU =====")
        print("1. Upload document")
        print("2. Retrieve document")
        print("3. Search documents")
        print("4. Verify document")
        print("5. Paillier financial aggregation")
        print("6. Change password")
        print("7. Logout")

        choice = input("Choice: ")

        match choice:
            case "1":
                upload_document(user)
            case "2":
                retrieve_document(user)
            case "3":
                search_documents(user)
            case "4":
                verify_document(user)
            case "5":
                aggregate_financial_data(user)
            case "6":
                change_password(user)
            case "7":
                break
            case _:
                print("Invalid choice.")


def administrator_menu(user):
    while True:
        print("\n===== ADMINISTRATOR MENU =====")
        print("1. Add user")
        print("2. Revoke user")
        print("3. Manage permissions")
        print("4. View audit log")
        print("5. Demonstrate tampering")
        print("6. Paillier financial aggregation")
        print("7. Logout")

        choice = input("Choice: ")

        match choice:
            case "1":
                add_user(user)
            case "2":
                revoke_user(user)
            case "3":
                manage_permissions(user)
            case "4":
                view_audit_log(user)
            case "5":
                tamper_demo(user)
            case "6":
                aggregate_financial_data(user)
            case "7":
                break
            case _:
                print("Invalid choice.")


# ============================================================
# MAIN MENU
# ============================================================

def main():
    initialize()

    while True:
        print("\n===== COMPANY DOCUMENT SECURITY =====")
        print("1. Login")
        print("2. Exit")

        choice = input("Choice: ")

        match choice:
            case "1":
                user = login()

                if user:
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
                print("Program closed.")
                break

            case _:
                print("Invalid choice.")


if __name__ == "__main__":
    main()
