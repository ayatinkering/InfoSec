"""Lab 6 socket signature demo: separate signing, packet creation, and sending."""

import socket
import json
import base64
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss



# ---------- SIGN THE ORIGINAL MESSAGE ----------
# This function does one thing: returns an RSA-PSS signature over these bytes.
def sign_message(message, private_key):
    digest = SHA256.new(message)
    # SCHEME TWIST: change PSS to another required scheme on BOTH sides.
    signer = pss.new(private_key)
    signature = signer.sign(digest)

    return signature



# ---------- BUILD A PORTABLE PACKET ----------
# JSON carries text; base64 makes signature bytes printable without changing them.
def build_packet(message, signature):
    signature_base64 = base64.b64encode(signature)
    signature_text = signature_base64.decode("ascii")

    packet = {
        "message": message,
        "signature": signature_text,
    }

    packet_text = json.dumps(packet)
    return packet_text.encode("utf-8")



# ---------- SEND AN ALREADY PREPARED PACKET ----------
# No signing happens here. You can reuse this transport with a different packet.
def send_packet(packet, host="127.0.0.1", port=5000):
    with socket.create_connection((host, port), timeout=30) as client:
        client.sendall(packet)
        client.shutdown(socket.SHUT_WR)
        reply = b""

        while True:
            chunk = client.recv(32)

            if not chunk:
                break

            reply += chunk

        result = reply.decode("ascii")

    return result == "VALID"



# ---------- INPUTS ----------
# First generate the keys and start the server in another terminal.
def main():
    default_key = Path(__file__).resolve().parent / "output" / "private.pem"
    key_path = input('Private key path [Enter=output/private.pem]: ')

    if key_path == "":
        key_path = str(default_key)

    host = input('Server host [127.0.0.1]: ')

    if host == "":
        host = '127.0.0.1'

    port = input('Port [5000]: ')

    if port == "":
        port = '5000'

    port = int(port)
    text = input('Message [Transfer 5000]: ')

    if text == "":
        text = 'Transfer 5000'

    key_bytes = Path(key_path).read_bytes()
    private_key = RSA.import_key(key_bytes)
    signature = sign_message(text.encode("utf-8"), private_key)

    # CHANGE HERE after signing. Keep signature unchanged to test detection.
    received_text = text
    # received_text = "Different transmitted message"

    packet = build_packet(received_text, signature)
    valid = send_packet(packet, host, port)
    print("Server verified signature:", valid)



if __name__ == "__main__":
    main()
