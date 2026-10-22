"""Lab 5: receive a complete message and return its SHA-256 hash."""

import hashlib
import socket



# ---------- RECEIVE THE WHOLE MESSAGE ----------
# TCP may split a message across many recv() calls.
# The client closes its writing side to mark the end of the message.
def receive_message(connection):
    chunks = []

    while True:
        chunk = connection.recv(4096)

        if not chunk:
            break

        chunks.append(chunk)

    return b"".join(chunks)



# ---------- HASH AND REPLY ----------
# Return the hash of EXACTLY what arrived, not a hard-coded expected message.
def handle_client(connection):
    received = receive_message(connection)
    digest = hashlib.sha256(received).hexdigest()

    connection.sendall(digest.encode("ascii"))

    print("Received:", received.decode("utf-8", errors="replace"))
    print("Hash sent:", digest)

    return digest



# ---------- START ONE SERVER ----------
# Start this file first, then run q2-client.py in another terminal.
def run_server(host="127.0.0.1", port=5001):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        server.settimeout(120)

        print("Hash server waiting at", (host, port), flush=True)
        connection, address = server.accept()

        with connection:
            connection.settimeout(30)
            print("Connected:", address)
            return handle_client(connection)



# ---------- INPUTS ----------
# CHANGE host/port on BOTH server and client if the question changes them.
def main():
    host = "127.0.0.1"
    port = 5001

    run_server(host, port)



if __name__ == "__main__":
    main()
