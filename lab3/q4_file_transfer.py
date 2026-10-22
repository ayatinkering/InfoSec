"""Q4: RSA-2048 versus P-256 hybrid file encryption, benchmark, and transfer.

RSA wraps an AES-256 key with OAEP/SHA-256; ECC derives it with ECDH/HKDF.
Both use AES-GCM for file contents. Q1 and Q2 supply the asymmetric functions.
Run benchmark, sender, or receiver from this one file's menu.
"""

# Import file, transport, serialization, timing, and cryptographic primitives.
import base64
import csv
import hashlib
import json
from pathlib import Path
import socket
import struct
from time import perf_counter
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
import q1_rsa as rsa
import q2_ecc as ecc



# ---------- GENERATE RECEIVER KEY ----------
# Generate the RSA-2048 or P-256 private key requested by the file-transfer exercise.
def generate_receiver_key(algorithm):
    if algorithm == "RSA":
        return rsa.generate_keys(2048)

    if algorithm == "ECC":
        return ecc.generate_keys("P-256")

    raise ValueError("Algorithm must be RSA or ECC.")



# ---------- ENCRYPT RSA ----------
# Encrypt file bytes with AES-GCM and wrap only the AES key with RSA-OAEP.
def encrypt_rsa(message, public_key):
    session_key = get_random_bytes(32)
    wrapped_key = rsa.encrypt(session_key, public_key)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=get_random_bytes(12))

    # Authenticate this unencrypted metadata too; decryption must use the same bytes.
    cipher.update(b"Lab3-RSA-file-v1" + wrapped_key)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    return {
        'wrapped_key': wrapped_key,
        'nonce': cipher.nonce,
        'ciphertext': ciphertext,
        'tag': tag,
    }



# ---------- DECRYPT RSA ----------
# Unwrap the AES key and verify/decrypt the file ciphertext.
def decrypt_rsa(packet, private_key):
    session_key = rsa.decrypt(packet["wrapped_key"], private_key)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=packet["nonce"])

    # Authenticate this unencrypted metadata too; decryption must use the same bytes.
    cipher.update(b"Lab3-RSA-file-v1" + packet["wrapped_key"])

    # A changed tag/ciphertext raises ValueError; never return unverified plaintext.
    return cipher.decrypt_and_verify(packet["ciphertext"], packet["tag"])



# ---------- ENCRYPT FILE BYTES ----------
# Choose the requested RSA or ECC hybrid for arbitrary binary file bytes.
def encrypt_file_bytes(message, algorithm, public_key):
    if algorithm == "RSA":
        return encrypt_rsa(message, public_key)

    if algorithm == "ECC":
        return ecc.encrypt(message, public_key)

    raise ValueError("Algorithm must be RSA or ECC.")



# ---------- DECRYPT FILE BYTES ----------
# Select the matching hybrid decryption and return bytes only after verification.
def decrypt_file_bytes(packet, algorithm, private_key):
    if algorithm == "RSA":
        return decrypt_rsa(packet, private_key)

    if algorithm == "ECC":
        return ecc.decrypt(packet, private_key)

    raise ValueError("Algorithm must be RSA or ECC.")



# ---------- SERIALIZE PACKET ----------
# Base64-encode binary packet fields and serialize a transportable JSON envelope.
def serialize_packet(packet, algorithm):
    fields = {}

    for name, value in packet.items():
        fields[name] = base64.b64encode(value).decode("ascii")

    envelope = {
        'algorithm': algorithm,
        'fields': fields,
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")



# ---------- DESERIALIZE PACKET ----------
# Parse the envelope and recover binary fields; this does not decrypt the data.
def deserialize_packet(encoded):
    envelope = json.loads(encoded.decode("utf-8"))
    algorithm = envelope["algorithm"]

    if algorithm not in ("RSA", "ECC"):
        raise ValueError("Unsupported packet algorithm.")

    packet = {}

    for name, value in envelope["fields"].items():
        packet[name] = base64.b64decode(value, validate=True)

    return algorithm, packet



# ---------- BENCHMARK ----------
# Compare full file-encryption workflows on the same datasets, reporting time and overhead.
def benchmark(datasets, repeats=1):
    if repeats <= 0:
        raise ValueError("Repetitions must be positive.")

    rows = []

    for algorithm in ("RSA", "ECC"):
        keygen_total = 0

        for _ in range(repeats):
            start = perf_counter()
            private_key = generate_receiver_key(algorithm)
            keygen_total += perf_counter() - start

        public_key = private_key.public_key()
        public_der = public_key.export_key(format="DER")
        private_der = private_key.export_key(format="DER")

        for label, message in datasets:
            enc_total = 0
            dec_total = 0

            for _ in range(repeats):
                start = perf_counter()
                packet = encrypt_file_bytes(message, algorithm, public_key)
                enc_total += perf_counter() - start

                start = perf_counter()
                recovered = decrypt_file_bytes(packet, algorithm, private_key)
                dec_total += perf_counter() - start

                if recovered != message:
                    raise ValueError("File round trip failed for " + algorithm)

            # Report both cryptographic overhead and serialized transport size.
            crypto_bytes = sum(len(value) for value in packet.values())
            wire_bytes = len(serialize_packet(packet, algorithm))
            rows.append({
                'file': label,
                'algorithm': algorithm,
                'plaintext_bytes': len(message),
                'keygen_ms': keygen_total / repeats * 1000,
                'encrypt_ms': enc_total / repeats * 1000,
                'decrypt_ms': dec_total / repeats * 1000,
                'public_key_bytes': len(public_der),
                'private_key_bytes': len(private_der),
                'crypto_overhead_bytes': crypto_bytes - len(message),
                'json_wire_bytes': wire_bytes,
            })

    return rows



# ---------- RECEIVE EXACT ----------
# Loop until the requested byte count arrives, or reject an early disconnect.
def receive_exact(connection, count):
    data = bytearray()

    while len(data) < count:
        chunk = connection.recv(min(65536, count - len(data)))

        if not chunk:
            raise ConnectionError("Connection ended before the complete message arrived.")

        data.extend(chunk)

    return bytes(data)



# ---------- SEND FRAME ----------
# Prefix data with its length and send all bytes through the socket.
def send_frame(connection, data):
    connection.sendall(struct.pack("!Q", len(data)) + data)



# ---------- RECEIVE FRAME ----------
# Read a length prefix, enforce the size limit, and receive exactly one frame.
def receive_frame(connection, maximum=64 * 1024 * 1024):
    count = struct.unpack("!Q", receive_exact(connection, 8))[0]

    if count > maximum:
        raise ValueError("Frame exceeds the configured maximum size.")

    return receive_exact(connection, count)



# ---------- FINGERPRINT ----------
# Hash a public-key encoding so it can be checked through a trusted route.
def fingerprint(public_key):
    return hashlib.sha256(public_key.public_key().export_key(format="DER")).hexdigest()



# ---------- HANDLE RECEIVER ----------
# Send the receiver public key, receive one encrypted file, verify, then save it.
def handle_receiver(connection, algorithm, private_key, destination):
    public_der = private_key.public_key().export_key(format="DER")
    greeting = {
        'algorithm': algorithm,
        'public_key': base64.b64encode(public_der).decode('ascii'),
    }
    send_frame(connection, json.dumps(greeting).encode("utf-8"))

    received_algorithm, packet = deserialize_packet(receive_frame(connection))

    if received_algorithm != algorithm:
        raise ValueError("Packet algorithm does not match the receiver.")

    message = decrypt_file_bytes(packet, algorithm, private_key)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    # Exclusive creation prevents accidentally replacing an existing file.
    with destination.open("xb") as output:
        output.write(message)

    digest = hashlib.sha256(message).hexdigest()
    acknowledgement = json.dumps({
        'bytes': len(message),
        'sha256': digest,
    }).encode("utf-8")
    send_frame(connection, acknowledgement)
    return len(message)



# ---------- SEND FILE ----------
# Read and encrypt a file for the receiver, check its pinned key if supplied, and transmit.
def send_file(host, port, source, expected_fingerprint=None):
    message = Path(source).read_bytes()

    with socket.create_connection((host, port), timeout=60) as connection:
        greeting = json.loads(receive_frame(connection, maximum=16384).decode("utf-8"))
        algorithm = greeting["algorithm"]
        key_der = base64.b64decode(greeting["public_key"], validate=True)

        if algorithm == "RSA":
            public_key = RSA.import_key(key_der)
        elif algorithm == "ECC":
            public_key = ECC.import_key(key_der)
        else:
            raise ValueError("Unsupported receiver algorithm.")

        actual = fingerprint(public_key)

        if expected_fingerprint and actual != expected_fingerprint.lower().strip():
            raise ValueError("Receiver public-key fingerprint does not match.")

        packet = encrypt_file_bytes(message, algorithm, public_key)
        send_frame(connection, serialize_packet(packet, algorithm))
        acknowledgement = json.loads(receive_frame(connection, maximum=16384).decode("utf-8"))

    if acknowledgement["bytes"] != len(message):
        raise ValueError("Receiver reported a different file size.")

    if acknowledgement["sha256"] != hashlib.sha256(message).hexdigest():
        raise ValueError("Receiver reported a different file hash.")

    return acknowledgement



# ---------- RECEIVE FILE ----------
# Listen for one file-transfer client without overwriting an existing destination.
def receive_file(host, port, algorithm, destination):
    if Path(destination).exists():
        raise FileExistsError("Choose a new destination; existing files are not overwritten.")

    private_key = generate_receiver_key(algorithm)
    print("Receiver public-key SHA-256 fingerprint:", fingerprint(private_key), flush=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        server.settimeout(120)
        print("Listening at", (host, port), "for one file", flush=True)
        connection, _ = server.accept()

        with connection:
            connection.settimeout(60)
            size = handle_receiver(connection, algorithm, private_key, destination)

    print("Verified and saved", size, "bytes to", destination)



# ---------- BENCHMARK DEMO ----------
# Read file/size/repetition inputs and display or save measured comparison results.
def benchmark_demo():
    paths = input("Input file paths, separated by | [Enter=generate 1 and 10 MiB]: ").strip()
    datasets = []

    if paths:
        for name in paths.split("|"):
            path = Path(name.strip())
            datasets.append((path.name, path.read_bytes()))
    else:
        sizes = input('Generated sizes in MiB, comma separated [1,10]: ')

        if sizes == "":
            sizes = '1,10'

        for size_text in sizes.split(","):
            size = float(size_text)

            if size <= 0:
                raise ValueError("Each file size must be positive.")

            datasets.append((str(size) + " MiB", get_random_bytes(int(size * 1024 * 1024))))

    repeats = input('Repetitions [1]: ')

    if repeats == "":
        repeats = '1'

    repeats = int(repeats)
    rows = benchmark(datasets, repeats)

    for row in rows:
        print("\nFile:", row["file"], "| Algorithm:", row["algorithm"])

        for name, value in row.items():
            if name not in ("file", "algorithm"):
                if isinstance(value, float):
                    displayed_value = round(value, 3)
                else:
                    displayed_value = value

                print("  " + name + ":", displayed_value)

    print("\nBoth approaches encrypt bulk data with AES-256-GCM; asymmetric operations protect its key.")
    print("Key generation is measured separately; enc/dec exclude disk, network, and JSON/base64 time.")
    print("DER sizes show key storage; crypto overhead excludes base64/JSON expansion.")
    print("P-256 has roughly 128-bit classical strength; RSA-2048 roughly 112, not equal strength.")
    print("Both are vulnerable to a sufficiently capable quantum computer. Timing is machine-dependent.")
    csv_path = input("Save results CSV path [Enter=skip]: ").strip()

    if csv_path:
        with Path(csv_path).open("x", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
def main():

    # Choose inputs here; press Enter for the worked example defaults.
    mode = input('Mode: 1=benchmark; 2=send; 3=receive [1]: ')

    if mode == "":
        mode = '1'

    if mode == "1":
        benchmark_demo()
    elif mode == "2":
        host = input('Receiver host [127.0.0.1]: ')

        if host == "":
            host = '127.0.0.1'

        port = input('Receiver port [5053]: ')

        if port == "":
            port = '5053'

        port = int(port)
        source = input("File path to send: ").strip()
        expected = input("Trusted receiver fingerprint [Enter=unauthenticated local demo]: ").strip()

        if not expected:
            print("Local demo only: the receiver key is not authenticated; a middleman could replace it.")

        print("Receiver acknowledgement:", send_file(host, port, source, expected or None))
    elif mode == "3":
        host = input('Listen address [127.0.0.1]: ')

        if host == "":
            host = '127.0.0.1'

        port = input('Listen port [5053]: ')

        if port == "":
            port = '5053'

        port = int(port)
        algorithm = input('Algorithm: RSA/ECC [RSA]: ')

        if algorithm == "":
            algorithm = 'RSA'

        algorithm = algorithm.upper()
        default_path = str(Path(__file__).resolve().parent / "output" / "received.bin")
        destination = input('NEW destination file [' + default_path + ']: ')

        if destination == "":
            destination = default_path

        receive_file(host, port, algorithm, destination)
    else:
        raise ValueError("Choose mode 1, 2, or 3.")


# Report invalid input or transfer errors clearly at the program boundary.
if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, TypeError, KeyError) as error:
        print("Error:", error)
        raise SystemExit(1)
