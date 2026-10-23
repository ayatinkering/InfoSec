'''
A healthcare organization wants to analyze patient statistics while protecting confidential patient data.

Write a menu-driven Python program that:
1. Accepts patient IDs and numerical health measurements.
2. Encrypts the numerical measurements using Paillier encryption.
3. Computes the aggregate of encrypted measurements without decrypting individual records.
4. Generates SHA-256 hashes of the original records.
5. Digitally signs selected reports using the authorized doctor's RSA private key.
6. Verifies the report signatures and detects altered records.
7. Implements Doctor, Analyst, and Administrator roles.
8. Displays the encrypted aggregate, decrypted final result, signature verification, and access-control results.'''


import hashlib
from math import gcd
import json

RECORD_FILE = "patient_records.txt"
REPORT_FILE = "signed_reports.txt"
AUDIT_FILE = "audit_log.txt"

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def inverse(a, m):
    return pow(a, -1, m)

def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()

def log_action(message):
    audit_log.append(message)
    print(message)

users = {
    "doctor": {"password": "doc123", "role": "Doctor"},
    "analyst": {"password": "ana123", "role": "Analyst"},
    "admin": {"password": "admin123", "role": "Administrator"}
}

records = []
audit_log = []
signatures = {}

# Paillier parameters
n = None
n2 = None
g = None
lam = None
mu = None

# RSA parameters for the authorized doctor
rsa_n = None
rsa_e = None
rsa_d = None

def setup_paillier():
    global n, n2, g, lam, mu

    print("\n--- PAILLIER KEY SETUP ---")
    p = int(input("Enter Paillier prime p: "))
    q = int(input("Enter Paillier prime q: "))

    if not is_prime(p) or not is_prime(q) or p == q:
        print("Error: p and q must be different prime numbers.")
        return False

    n = p * q
    n2 = n * n
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)

    g = int(input("Enter Paillier parameter g: "))

    if not (1 < g < n2) or gcd(g, n2) != 1:
        print("Error: g must be between 1 and n^2 and coprime to n^2.")
        n = n2 = g = lam = mu = None
        return False

    value = pow(g, lam, n2)
    if (value - 1) % n != 0:
        print("Invalid g: L(g^lambda mod n^2) is not an integer.")
        n = n2 = g = lam = mu = None
        return False

    L_value = (value - 1) // n

    if gcd(L_value, n) != 1:
        print("Invalid g: modular inverse does not exist.")
        n = n2 = g = lam = mu = None
        return False

    mu = inverse(L_value, n)

    print("Public key (n, g):", (n, g))
    print("Private key (lambda, mu):", (lam, mu))
    log_action("Administrator configured Paillier keys.")
    return True

def paillier_encrypt(message, r):
    if not 0 <= message < n:
        raise ValueError("Measurement must be between 0 and n-1.")
    if not 1 <= r < n or gcd(r, n) != 1:
        raise ValueError("r must be in [1, n-1] and coprime to n.")

    return (pow(g, message, n2) * pow(r, n, n2)) % n2

def paillier_decrypt(ciphertext):
    value = pow(ciphertext, lam, n2)
    L_value = (value - 1) // n
    return (L_value * mu) % n

def setup_rsa():
    global rsa_n, rsa_e, rsa_d

    print("\n--- DOCTOR RSA KEY SETUP ---")
    p = int(input("Enter RSA prime p: "))
    q = int(input("Enter RSA prime q: "))

    if not is_prime(p) or not is_prime(q) or p == q:
        print("Error: p and q must be different primes.")
        return False

    rsa_n = p * q
    phi = (p - 1) * (q - 1)
    rsa_e = int(input("Enter public exponent e: "))

    if not 1 < rsa_e < phi or gcd(rsa_e, phi) != 1:
        print("Error: e must be coprime to phi and between 1 and phi.")
        rsa_n = rsa_e = rsa_d = None
        return False

    rsa_d = inverse(rsa_e, phi)

    print("RSA public key (n, e):", (rsa_n, rsa_e))
    print("RSA private exponent d:", rsa_d)
    log_action("Administrator configured the doctor's RSA keys.")
    return True

def sign_report(report):
    digest = int(sha256(report), 16)
    return pow(digest % rsa_n, rsa_d, rsa_n)

def verify_signature(report, signature):
    digest = int(sha256(report), 16)
    recovered = pow(signature, rsa_e, rsa_n)
    return recovered == digest % rsa_n

def login():
    username = input("\nUsername (doctor/analyst/admin): ").strip().lower()
    password = input("Password: ")

    if username not in users or users[username]["password"] != password:
        print("ACCESS DENIED: Invalid login.")
        log_action("Failed login attempt.")
        return None

    role = users[username]["role"]
    print("Login successful. Role:", role)
    log_action(username + " logged in as " + role + ".")
    return role
def save_records():
    with open(RECORD_FILE, "w") as file:
        json.dump(records, file, indent=4)

    print("Patient records saved to file.")


def load_records():
    global records

    try:
        with open(RECORD_FILE, "r") as file:
            records = json.load(file)

        print("Patient records loaded successfully.")

    except FileNotFoundError:
        records = []
        print("No existing patient records found.")


def save_reports():
    with open(REPORT_FILE, "w") as file:
        json.dump(signatures, file, indent=4)

    print("Signed reports saved to file.")


def load_reports():
    global signatures

    try:
        with open(REPORT_FILE, "r") as file:
            signatures = json.load(file)

        # JSON object keys are strings; convert signatures back to integers.
        signatures = {
            report: int(signature)
            for report, signature in signatures.items()
        }

        print("Signed reports loaded successfully.")

    except FileNotFoundError:
        signatures = {}
        print("No existing signed reports found.")


def log_action(message):
    audit_log.append(message)

    with open(AUDIT_FILE, "a") as file:
        file.write(message + "\n")

    print(message)

def add_record():
    if n is None:
        print("Configure Paillier keys first.")
        return
    patient_id = input("Enter patient ID: ").strip()
    if not patient_id:
        print("Patient ID cannot be empty.")
        return
    if any(record["patient_id"] == patient_id for record in records):
        print("Patient ID already exists.")
        return
    measurement = int(input("Enter numerical measurement (integer): "))
    r = int(input("Enter Paillier encryption value r: "))

    try:
        ciphertext = paillier_encrypt(measurement, r)
    except ValueError as error:
        print("Error:", error)
        return

    original = patient_id + "|" + str(measurement)

    record = {
        "patient_id": patient_id,
        "measurement": measurement,
        "ciphertext": ciphertext,
        "hash": sha256(original)
    }

    records.append(record)
    save_records()
    print("\nRecord stored.")
    print("Encrypted measurement:", ciphertext)
    print("SHA-256 hash:", record["hash"])
    log_action("Doctor added patient record " + patient_id + ".")

def aggregate_records():
    if n is None or not records:
        print("Configure Paillier keys and add records first.")
        return
    encrypted_total = 1
    for record in records:
        encrypted_total = (encrypted_total * record["ciphertext"]) % n2

    print("\nEncrypted aggregate:", encrypted_total)
    log_action("Analyst computed the encrypted aggregate.")

    choice = input("Decrypt final aggregate? (yes/no): ").strip().lower()

    if choice == "yes":
        total = paillier_decrypt(encrypted_total)
        print("Decrypted final aggregate:", total)
        print("Number of records:", len(records))
        log_action("Analyst decrypted the aggregate total.")

def check_integrity():
    if not records:
        print("No patient records available.")
        return

    print("\n--- RECORD INTEGRITY CHECK ---")
    for record in records:
        original = record["patient_id"] + "|" + str(record["measurement"])
        current_hash = sha256(original)

        if current_hash == record["hash"]:
            print(record["patient_id"], ": INTACT")
        else:
            print(record["patient_id"], ": ALTERED")

    log_action("Record integrity check performed.")

def sign_selected_report():
    if rsa_n is None:
        print("Configure the doctor's RSA keys first.")
        return

    if not records:
        print("No records available.")
        return

    check_integrity()
    report = input("Enter report text to sign (e.g. Total measurement = 150): ")

    signature = sign_report(report)
    signatures[report] = signature
    save_reports()
    print("\nReport:", report)
    print("SHA-256:", sha256(report))
    print("RSA digital signature:", signature)
    print("Report signed successfully.")

    log_action("Doctor signed a report.")

def verify_selected_report():
    if rsa_n is None:
        print("Configure the doctor's RSA keys first.")
        return

    if not signatures:
        print("No signed reports available.")
        return

    report = input("Enter the exact report text to verify: ")

    if report not in signatures:
        print("SIGNATURE NOT FOUND: Report text does not match a stored report.")
        log_action("Report verification failed: report not found.")
        return

    if verify_signature(report, signatures[report]):
        print("RSA signature: VALID")
        print("Report integrity: VERIFIED")
        log_action("RSA report signature verified.")
    else:
        print("RSA signature: INVALID")
        print("Report may have been altered.")
        log_action("RSA report signature verification failed.")

def alter_record():
    if not records:
        print("No records available.")
        return

    patient_id = input("Enter patient ID to alter: ").strip()

    for record in records:
        if record["patient_id"] == patient_id:
            record["measurement"] = int(input("Enter replacement measurement: "))
            print("Record modified for integrity-testing demonstration.")
            log_action("Record " + patient_id + " was modified.")
            return

    print("Patient ID not found.")

def show_audit_log():
    print("\n--- AUDIT LOG ---")
    if not audit_log:
        print("No activity recorded.")
    else:
        for entry in audit_log:
            print(entry)

def show_users():
    print("\n--- USERS AND ROLES ---")
    for username, details in users.items():
        print(username, "-", details["role"])


def doctor_menu():
    while True:
        print("\n===== DOCTOR MENU =====")
        print("1. Add and encrypt patient record")
        print("2. Check record integrity")
        print("3. Sign a report")
        print("4. Verify report signature")
        print("5. Logout")

        choice = input("Enter choice: ")

        match choice:
            case "1":
                add_record()

            case "2":
                check_integrity()

            case "3":
                sign_selected_report()

            case "4":
                verify_selected_report()

            case "5":
                print("Doctor logged out.")
                break

            case _:
                print("Invalid choice.")


def analyst_menu():
    while True:
        print("\n===== ANALYST MENU =====")
        print("1. Compute encrypted aggregate")
        print("2. Check record integrity")
        print("3. Verify report signature")
        print("4. Logout")

        choice = input("Enter choice: ")

        match choice:
            case "1":
                aggregate_records()

            case "2":
                check_integrity()

            case "3":
                verify_selected_report()

            case "4":
                print("Analyst logged out.")
                break

            case _:
                print("Invalid choice.")


def admin_menu():
    while True:
        print("\n===== ADMINISTRATOR MENU =====")
        print("1. Configure Paillier keys")
        print("2. Configure Doctor RSA keys")
        print("3. Alter record for testing")
        print("4. View audit log")
        print("5. View users and roles")
        print("6. Logout")

        choice = input("Enter choice: ")

        match choice:
            case "1":
                setup_paillier()

            case "2":
                setup_rsa()

            case "3":
                alter_record()

            case "4":
                show_audit_log()

            case "5":
                show_users()

            case "6":
                print("Administrator logged out.")
                break

            case _:
                print("Invalid choice.")


def main():
    load_records()
    load_reports()
    print("HEALTHCARE SECURE STATISTICS SYSTEM")

    while True:
        print("\n===== MAIN MENU =====")
        print("1. Login")
        print("0. Exit")

        choice = input("Enter choice: ")

        match choice:
            case "1":
                role = login()

                match role:
                    case "Doctor":
                        doctor_menu()

                    case "Analyst":
                        analyst_menu()

                    case "Administrator":
                        admin_menu()

                    case None:
                        print("Login failed.")

                    case _:
                        print("Invalid role.")

            case "0":
                print("Exiting system.")
                break

            case _:
                print("Invalid choice.")


if __name__ == "__main__":
    main()
