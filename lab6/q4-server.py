"""Lab 6 socket signature demo, step 2: receive and verify using a public key."""

import socket
import json
import base64
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss



# ---------- READ A COMPLETE TCP MESSAGE ----------
# The client signals EOF with shutdown(SHUT_WR); recv() can return partial data.
def receive_packet(connection):
    data = b""

    while True:
        chunk = connection.recv(4096)

        if not chunk:
            break

        data += chunk

    return json.loads(data.decode("utf-8"))



# ---------- VERIFY ONLY WHAT ARRIVED ----------
# Use the signer's trusted PUBLIC key, never a newly generated key pair.
def verify_packet(packet, public_key):
    message = packet["message"].encode("utf-8")
    signature = base64.b64decode(packet["signature"], validate=True)
    digest = SHA256.new(message)

    verifier = pss.new(public_key)

    try:
        verifier.verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False



# ---------- HANDLE ONE CLIENT ----------
# Send a small result back so the client can display verification status too.
def handle_client(connection, public_key):
    packet = receive_packet(connection)
    valid = verify_packet(packet, public_key)
    if valid:
        connection.sendall(b"VALID")
        print("Signature valid")
    else:
        connection.sendall(b"INVALID")
        print("Signature invalid / message changed")

    return valid



# ---------- LISTEN ON THE CHOSEN ADDRESS ----------
# Restart after each client: this simple lab server handles one connection.
def run_server(public_key, host="127.0.0.1", port=5000):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        server.settimeout(120)

        print("Signature server waiting at", (host, port), flush=True)
        connection, address = server.accept()

        with connection:
            connection.settimeout(30)
            print("Connected:", address)
            return handle_client(connection, public_key)



# ---------- INPUTS ----------
# Run q4-keys.py once first; this file needs only its public.pem output.
def main():
    default_key = Path(__file__).resolve().parent / "output" / "public.pem"
    key_path = input('Public key path [Enter=output/public.pem]: ')

    if key_path == "":
        key_path = str(default_key)

    host = input('Listen host [127.0.0.1]: ')

    if host == "":
        host = '127.0.0.1'

    port = input('Port [5000]: ')

    if port == "":
        port = '5000'

    port = int(port)
    key_bytes = Path(key_path).read_bytes()
    public_key = RSA.import_key(key_bytes)
    run_server(public_key, host, port)



if __name__ == "__main__":
    main()
