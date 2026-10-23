'''
A hospital stores confidential patient records and wants doctors to retrieve records securely while allowing analysts to calculate aggregate medical statistics without revealing individual patient measurements.

On the client side:
- A hospital employee logs in with a user ID and password.
- The employee enters a patient ID, diagnosis, medical measurement, and date.
- The application demonstrates a classical substitution cipher or transposition cipher for educational comparison with modern encryption.
- The complete medical record is encrypted using des, and its SHA-256 hash is generated.
- A doctor digitally signs an approved report using an ElGamal private key.
On the server side:
- The server verifies user permissions, report signatures, and record integrity.
- Encrypted medical measurements are aggregated using Paillier encryption.
- An encrypted keyword index allows authorized doctors to search for records by diagnosis.
- The system supports key updates and revocation when an employee leaves the hospital.
- An administrator can inspect audit logs but cannot automatically access every decrypted patient record.
Develop a menu-driven Python program with Doctor, Medical Data Analyst, and Administrator roles. Implement record encryption/decryption, signature verification, hashing, searchable indexing, and homomorphic aggregation. Demonstrate tampering detection and access denial.
'''

import os
import json
import re
import hmac
import hashlib
import secrets
import math
from datetime import date

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


USER_FILE = "users.txt"
RECORD_FILE = "records.txt"
AUDIT_FILE = "audit_log.txt"
SIGNATURE_FILE = "signatures.txt"

INDEX_SECRET = b"hospital_demo_index_secret"

# Educational ElGamal parameters
EG_P = 467
EG_G = 2
EG_X = 127
EG_Y = pow(EG_G, EG_X, EG_P)

# Educational Paillier parameters
PA_P = 17
PA_Q = 19
PA_N = PA_P * PA_Q
PA_N2 = PA_N * PA_N
PA_G = PA_N + 1
PA_LAMBDA = math.lcm(PA_P - 1, PA_Q - 1)

'''
def get_elgamal_parameters():
    print("\n===== ELGAMAL PARAMETERS =====")

    p = int(input("Enter prime number p: "))
    g = int(input("Enter generator g: "))
    x = int(input("Enter private key x: "))

    if p <= 2 or g <= 1 or g >= p or x <= 0 or x >= p - 1:
        print("Invalid ElGamal parameters.")
        return None

    y = pow(g, x, p)

    print("\n===== ELGAMAL KEYS =====")
    print("Prime p:", p)
    print("Generator g:", g)
    print("Private key x:", x)
    print("Public key y:", y)

    return p, g, x, y

    ===== ELGAMAL PARAMETERS =====
Enter prime number p: 467
Enter generator g: 2
Enter private key x: 127
'''

def paillier_l(value):
    return (value - 1) // PA_N
PA_MU = pow(paillier_l(pow(PA_G, PA_LAMBDA, PA_N2)), -1, PA_N)

'''
import math

def get_paillier_parameters():
    print("\n===== PAILLIER PARAMETERS =====")

    p = int(input("Enter prime number p: "))
    q = int(input("Enter prime number q: "))

    if p <= 2 or q <= 2 or p == q:
        print("Invalid parameters. Enter two distinct primes greater than 2.")
        return None

    n = p * q
    n2 = n * n
    g = n + 1

    lam = math.lcm(p - 1, q - 1)

    value = pow(g, lam, n2)
    L_value = (value - 1) // n

    if math.gcd(L_value, n) != 1:
        print("Invalid parameters: modular inverse does not exist.")
        return None

    mu = pow(L_value, -1, n)

    print("\n===== PAILLIER KEYS =====")
    print("Prime p:", p)
    print("Prime q:", q)
    print("Public key n:", n)
    print("Public key g:", g)
    print("Private key lambda:", lam)
    print("Private key mu:", mu)

    return n, g, lam, mu

    ===== PAILLIER PARAMETERS =====
Enter prime number p: 17
Enter prime number q: 19
'''
def read_lines(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, "r", encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]

def append_line(filename, data):
    with open(filename, "a", encoding="utf-8") as file:
        file.write(json.dumps(data) + "\n")

def write_lines(filename, data):
    with open(filename, "w", encoding="utf-8") as file:
        for item in data:
            file.write(json.dumps(item) + "\n")

def audit(message):
    append_line(AUDIT_FILE, {"time": str(date.today()),"event": message})

def initialize():
    if not os.path.exists(USER_FILE):
        users = [
            {"user_id": "doc1", "password": "doc123",
             "role": "Doctor", "active": True},
            {"user_id": "analyst1", "password": "ana123",
             "role": "Analyst", "active": True},
            {"user_id": "admin", "password": "admin123",
             "role": "Administrator", "active": True}
        ]
        write_lines(USER_FILE, users)

    for filename in (RECORD_FILE, AUDIT_FILE, SIGNATURE_FILE):
        if not os.path.exists(filename):
            open(filename, "w", encoding="utf-8").close()

def login():
    users = read_lines(USER_FILE)
    user_id = input("User ID: ").strip()
    password = input("Password: ")

    for user in users:
        if user["user_id"] == user_id and user["password"] == password:
            if not user["active"]:
                print("Access denied: user has been revoked.")
                audit(f"Revoked login blocked: {user_id}")
                return None

            print("Login successful. Role:", user["role"])
            audit(f"Login successful: {user_id}")
            return user

    print("Invalid user ID or password.")
    audit(f"Failed login attempt: {user_id}")
    return None


def get_des_key():
    text = input("Enter DES key (maximum 8 UTF-8 bytes): ")
    key = text.encode("utf-8")
    if not key or len(key) > 8:
        print("Key must contain 1 to 8 UTF-8 bytes.")
        return None
    return key.ljust(8, b"\0")

def encrypt_text(plaintext, key):
    # Random IV; DES-CBC requires an 8-byte IV.
    iv = secrets.token_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), 8))
    return iv.hex() + ":" + ciphertext.hex()


def decrypt_text(encrypted, key):
    iv_hex, ciphertext_hex = encrypted.split(":", 1)
    cipher = DES.new(key, DES.MODE_CBC, bytes.fromhex(iv_hex))
    plaintext = unpad(cipher.decrypt(bytes.fromhex(ciphertext_hex)), 8)
    return plaintext.decode("utf-8")


def normalize_keywords(text):
    return re.findall(r"[a-z0-9]+", text.lower())


def keyword_token(word):
    return hmac.new(INDEX_SECRET, word.encode("utf-8"), hashlib.sha256).hexdigest()

def build_index(diagnosis):
    return sorted({keyword_token(word)
                   for word in normalize_keywords(diagnosis)})

def paillier_encrypt(message):
    if not 0 <= message < PA_N:
        raise ValueError(f"Measurement must be between 0 and {PA_N - 1}.")

    while True:
        r = secrets.randbelow(PA_N - 1) + 1
        if math.gcd(r, PA_N) == 1:
            break

    return (pow(PA_G, message, PA_N2) *
            pow(r, PA_N, PA_N2)) % PA_N2

def paillier_decrypt(ciphertext):
    value = paillier_l(pow(ciphertext, PA_LAMBDA, PA_N2))
    return (value * PA_MU) % PA_N

def classical_cipher(text):
    result = ""

    for char in text:
        if "a" <= char <= "z":
            result += chr((ord(char) - ord("a") + 3) % 26 + ord("a"))
        elif "A" <= char <= "Z":
            result += chr((ord(char) - ord("A") + 3) % 26 + ord("A"))
        else:
            result += char

    return result

def add_record(user):
    if user["role"] != "Doctor":
        print("Access denied: doctors only.")
        return

    key = get_des_key()
    if key is None:
        return

    patient_id = input("Patient ID: ").strip()
    diagnosis = input("Diagnosis: ").strip()
    measurement_text = input("Medical measurement (integer): ").strip()
    record_date = input("Date (YYYY-MM-DD): ").strip()

    try:
        measurement = int(measurement_text)
        date.fromisoformat(record_date)

        if not patient_id or not diagnosis:
            raise ValueError("Patient ID and diagnosis are required.")

        encrypted_measurement = paillier_encrypt(measurement)

    except ValueError as error:
        print("Invalid input:", error)
        return

    record = {
        "patient_id": patient_id,
        "diagnosis": diagnosis,
        "measurement": measurement,
        "date": record_date
    }

    plaintext = json.dumps(record, sort_keys=True)
    encrypted = encrypt_text(plaintext, key)
    digest = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
   
    saved = {
        "patient_id": patient_id,
        "encrypted_record": encrypted,
        "sha256": digest,
        "keyword_index": build_index(diagnosis),
        "encrypted_measurement": encrypted_measurement
    }

    append_line(RECORD_FILE, saved)
    print("Classical Caesar cipher comparison:")
    print("Original diagnosis:", diagnosis)
    print("Encrypted diagnosis:", classical_cipher(diagnosis))

    print("\nRecord saved successfully.")
    print("Encrypted record:", encrypted)
    print("SHA-256:", digest)
    print("Encrypted measurement:", encrypted_measurement)
    audit(f"{user['user_id']} added patient record {patient_id}")


def retrieve_record(user):
    if user["role"] != "Doctor":
        print("Access denied: doctors only.")
        return

    patient_id = input("Patient ID to retrieve: ").strip()
    key = get_des_key()
    if key is None:
        return

    records = read_lines(RECORD_FILE)
    found = next((r for r in records
                  if r["patient_id"] == patient_id), None)

    if not found:
        print("Record not found.")
        return

    try:
        plaintext = decrypt_text(found["encrypted_record"], key)
        calculated_hash = hashlib.sha256(
            plaintext.encode("utf-8")
        ).hexdigest()

        print("\nDecrypted record:")
        print(plaintext)
        print("Stored SHA-256:", found["sha256"])
        print("Calculated SHA-256:", calculated_hash)

        if hmac.compare_digest(calculated_hash, found["sha256"]):
            print("Integrity verified.")
        else:
            print("TAMPERING DETECTED: hash mismatch!")

        audit(f"{user['user_id']} retrieved patient record {patient_id}")

    except (ValueError, UnicodeDecodeError, TypeError):
        print("Decryption failed: wrong key or corrupted ciphertext.")
        audit(f"Decryption failed for patient {patient_id}")


def search_diagnosis(user):
    if user["role"] != "Doctor":
        print("Access denied: doctors only.")
        return

    query = input("Diagnosis keyword to search: ").strip().lower()
    words = normalize_keywords(query)

    if not words:
        print("Enter a valid keyword.")
        return

    wanted = [keyword_token(word) for word in words]
    records = read_lines(RECORD_FILE)

    matches = [
        r["patient_id"] for r in records
        if all(token in r.get("keyword_index", []) for token in wanted)
    ]

    if matches:
        print("Matching patient IDs:", ", ".join(matches))
    else:
        print("No matching records found.")

    audit(f"{user['user_id']} searched encrypted diagnosis index")


def sign_report(user):
    if user["role"] != "Doctor":
        print("Access denied: doctors only.")
        return

    report = input("Enter approved report text: ").strip()
    if not report:
        print("Report cannot be empty.")
        return

    digest = int.from_bytes(
        hashlib.sha256(report.encode("utf-8")).digest(), "big"
    ) % (EG_P - 1)

    # ElGamal signature requires gcd(k, p-1) = 1.
    while True:
        k = secrets.randbelow(EG_P - 2) + 1
        if math.gcd(k, EG_P - 1) == 1:
            break

    r = pow(EG_G, k, EG_P)
    s = (pow(k, -1, EG_P - 1) *
         (digest - EG_X * r)) % (EG_P - 1)

    append_line(SIGNATURE_FILE, {
        "report": report,
        "signer": user["user_id"],
        "r": r,
        "s": s
    })

    print("Report digitally signed.")
    print("Signature (r, s):", (r, s))
    audit(f"{user['user_id']} signed an approved report")


def verify_report(user):
    if user["role"] not in ("Doctor", "Administrator"):
        print("Access denied.")
        return

    signatures = read_lines(SIGNATURE_FILE)

    if not signatures:
        print("No signed reports available.")
        return

    for i, item in enumerate(signatures, start=1):
        print(f"{i}. Signer: {item['signer']} | Report: {item['report']}")

    try:
        choice = int(input("Select report number: "))
        item = signatures[choice - 1]
        r, s = item["r"], item["s"]

        digest = int.from_bytes(
            hashlib.sha256(item["report"].encode("utf-8")).digest(), "big"
        ) % (EG_P - 1)

        valid = (
            0 < r < EG_P
            and 0 <= s < EG_P - 1
            and pow(EG_G, digest, EG_P)
            == (pow(EG_Y, r, EG_P) * pow(r, s, EG_P)) % EG_P
        )

        print("Signature valid." if valid else "INVALID SIGNATURE!")
        audit(f"{user['user_id']} verified a report signature")

    except (ValueError, IndexError):
        print("Invalid selection.")


def aggregate_measurements(user):
    if user["role"] != "Analyst":
        print("Access denied: analysts only.")
        return

    records = read_lines(RECORD_FILE)

    if not records:
        print("No measurements available.")
        return

    # Homomorphic addition: multiply ciphertexts modulo n².
    encrypted_sum = 1
    for record in records:
        encrypted_sum = (
            encrypted_sum * record["encrypted_measurement"]
        ) % PA_N2

    # Trusted service decrypts only the aggregate, not each measurement.
    # This is a classroom simulation of server-side key isolation.
    total = paillier_decrypt(encrypted_sum)

    print("Number of records aggregated:", len(records))
    print("Encrypted aggregate:", encrypted_sum)
    print("Decrypted aggregate total:", total)
    print("Individual patient measurements were not displayed.")

    audit(f"{user['user_id']} requested aggregate statistics")


def revoke_user(user):
    if user["role"] != "Administrator":
        print("Access denied: administrators only.")
        return

    target = input("User ID to revoke: ").strip()
    users = read_lines(USER_FILE)

    if target == user["user_id"]:
        print("You cannot revoke your own active administrator account.")
        return

    for item in users:
        if item["user_id"] == target:
            item["active"] = False
            write_lines(USER_FILE, users)
            print("User revoked successfully.")
            audit(f"{user['user_id']} revoked {target}")
            return

    print("User not found.")


def update_user_password(user):
    if user["role"] != "Administrator":
        print("Access denied: administrators only.")
        return

    target = input("User ID to update: ").strip()
    new_password = input("Enter new password: ")

    if not new_password:
        print("Password cannot be empty.")
        return

    users = read_lines(USER_FILE)

    for item in users:
        if item["user_id"] == target and item["active"]:
            item["password"] = new_password
            write_lines(USER_FILE, users)
            print("Password updated.")
            audit(f"{user['user_id']} updated credentials for {target}")
            return

    print("Active user not found.")


def view_audit_log(user):
    if user["role"] != "Administrator":
        print("Access denied: administrators only.")
        return

    if not os.path.exists(AUDIT_FILE):
        print("No audit log available.")
        return

    with open(AUDIT_FILE, "r", encoding="utf-8") as file:
        print("\n===== AUDIT LOG =====")
        print(file.read() or "Audit log is empty.")


def tamper_demo(user):
    if user["role"] != "Administrator":
        print("Access denied: administrators only.")
        return

    records = read_lines(RECORD_FILE)

    if not records:
        print("Add a record first.")
        return

    patient_id = input("Patient ID to tamper with: ").strip()
    record = next((r for r in records
                   if r["patient_id"] == patient_id), None)

    if not record:
        print("Record not found.")
        return

    # Modify stored hash to demonstrate integrity failure.
    record["sha256"] = "0" * 64
    write_lines(RECORD_FILE, records)

    print("Stored hash modified for demonstration.")
    print("Retrieve this record as a doctor to see the integrity warning.")
    audit(f"{user['user_id']} tampered with stored hash for {patient_id}")


def menu(user):
    while True:
        print(f"\n===== {user['role'].upper()} MENU =====")

        if user["role"] == "Doctor":
            print("1. Add patient record")
            print("2. Retrieve/decrypt patient record")
            print("3. Search by diagnosis")
            print("4. Sign approved report")
            print("5. Verify report signature")
            print("6. Logout")

            choice = input("Enter choice: ").strip()
            actions = {
                "1": lambda: add_record(user),
                "2": lambda: retrieve_record(user),
                "3": lambda: search_diagnosis(user),
                "4": lambda: sign_report(user),
                "5": lambda: verify_report(user)
            }

        elif user["role"] == "Analyst":
            print("1. Aggregate encrypted measurements")
            print("2. Logout")
            choice = input("Enter choice: ").strip()
            actions = {"1": lambda: aggregate_measurements(user)}

        else:
            print("1. Revoke user")
            print("2. Update user password")
            print("3. View audit log")
            print("4. Tampering demonstration")
            print("5. Verify report signature")
            print("6. Logout")

            choice = input("Enter choice: ").strip()
            actions = {
                "1": lambda: revoke_user(user),
                "2": lambda: update_user_password(user),
                "3": lambda: view_audit_log(user),
                "4": lambda: tamper_demo(user),
                "5": lambda: verify_report(user)
            }

        if choice in ("6", "2") and user["role"] == "Analyst":
            audit(f"{user['user_id']} logged out")
            print("Logged out.")
            break

        if choice == "6" and user["role"] != "Analyst":
            audit(f"{user['user_id']} logged out")
            print("Logged out.")
            break

        if choice in actions:
            actions[choice]()
        else:
            print("Invalid choice.")


def main():
    initialize()

    while True:
        print("\n===== HOSPITAL SECURE MEDICAL RECORDS =====")
        print("1. Login")
        print("2. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            user = login()
            if user:
                menu(user)
        elif choice == "2":
            print("Application closed.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()

    ''' CALLING FUNCTIONS
    elgamal_params = get_elgamal_parameters()

if elgamal_params:
    EG_P, EG_G, EG_X, EG_Y = elgamal_params

paillier_params = get_paillier_parameters()

if paillier_params:
    PA_N, PA_G, PA_LAMBDA, PA_MU = paillier_params
    PA_N2 = PA_N * PA_N
    '''