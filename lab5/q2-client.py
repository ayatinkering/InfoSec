"""Lab 5: compare the original message hash with the server's received hash."""

import hashlib
import socket



# ---------- SEND BYTES AND RECEIVE THE SERVER HASH ----------
# This function only transports the supplied data and returns the server reply.
# Hashing and comparison stay outside it so each step can be copied separately.
def send_data(data, host="127.0.0.1", port=5001):
    with socket.create_connection((host, port), timeout=30) as client:
        client.sendall(data)
        client.shutdown(socket.SHUT_WR)

        # Read until the server closes its reply, rather than assuming one recv.
        reply = b""

        while True:
            chunk = client.recv(4096)

            if not chunk:
                break

            reply += chunk

    return reply.decode("ascii")



# ---------- INPUTS AND RESULT ----------
# HINT: edit sent_data below AFTER computing local_hash. Restart the server per run.
# An unkeyed hash comparison detects this corruption; it does not authenticate peers.
def main():
    host = "127.0.0.1"
    port = 5001
    message = input('Message [Information Security Lab]: ')

    if message == "":
        message = 'Information Security Lab'

    original_data = message.encode("utf-8")
    local_hash = hashlib.sha256(original_data).hexdigest()

    # CHANGE HERE to alter only the transmitted copy, not the reference hash.
    sent_data = original_data
    # sent_data = b"Different transmitted message"

    server_hash = send_data(sent_data, host, port)
    valid = local_hash == server_hash

    print("Local original hash:", local_hash)
    print("Server received hash:", server_hash)
    if valid:
        print("Integrity verified")
    else:
        print("Tampering/corruption detected")



if __name__ == "__main__":
    main()
