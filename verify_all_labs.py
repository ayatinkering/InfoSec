"""Check readability refactors: imports, formulas, tampering, search and sockets.

Run with the same Python interpreter used for the lab programs.
The local socket tests require permission to open loopback connections.
"""

# ---------- IMPORT TEST TOOLS ----------
import ast
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from Crypto.PublicKey import RSA

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "lab3"))



# ---------- LOAD FILES EVEN WHEN NAMES CONTAIN HYPHENS ----------
def load_module(relative_path):
    path = ROOT / relative_path
    name = relative_path.replace("/", "_").replace("-", "_").replace(".", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))

    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)

    return module



# ---------- FUNCTIONAL CHECKS ----------
class ReadabilityChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing_key = RSA.generate(2048)
        cls.wrong_key = RSA.generate(2048)

    def test_all_files_parse_and_import_without_prompts(self):
        for folder in ("lab1", "lab2", "lab3", "lab4", "lab5", "lab6", "lab7", "lab88"):
            for path in (ROOT / folder).glob("*.py"):
                ast.parse(path.read_text())

                with patch("builtins.input", side_effect=AssertionError("Import prompted for input")):
                    with redirect_stdout(io.StringIO()):
                        load_module(str(path.relative_to(ROOT)))

    def test_lab1_cipher_round_trips_and_known_outputs(self):
        from math import gcd
        affine = load_module("lab1/q1_affine.py")

        for a in range(26):
            if gcd(a, 26) == 1:
                for b in range(26):
                    text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    self.assertEqual(affine.decrypt(affine.encrypt(text, a, b), a, b), text)

        for path, key in [("q1_additive.py", 20), ("q1_multiplicative.py", 15),
                          ("q2_autokey.py", 7), ("q2_vigenere.py", "DOLLARS")]:
            module = load_module("lab1/" + path)
            self.assertEqual(module.decrypt(module.encrypt("Hello World", key), key), "HELLOWORLD")

        playfair = load_module("lab1/q3_playfair.py")
        matrix = playfair.make_matrix("GUIDANCE")
        for message in ("BALLOON", "XX", "The key is hidden under the door pad"):
            self.assertEqual(playfair.decrypt(playfair.encrypt(message, matrix), matrix), playfair.prepare(message))

        hill = load_module("lab1/q4_hill.py")
        self.assertEqual(hill.encrypt("WE", [[3, 3], [2, 7]]), "AU")
        self.assertEqual(hill.decrypt("AU", [[3, 3], [2, 7]]), "WE")

    def test_hash_functions_and_collision_counting(self):
        hashes = load_module("lab5/q1-hash.py")
        self.assertEqual(hashes.custom_hash(""), 5381)
        self.assertEqual(hashes.custom_hash("a"), 177670)
        self.assertEqual(hashes.calculate_standard_hashes("hello")["SHA-256"], hashlib.sha256(b"hello").hexdigest())
        comparison = load_module("lab5/q3-collision.py")
        _, collisions = comparison.measure_hashes(["same", "same"], hashlib.sha256)
        self.assertEqual(collisions, 0)

        class ConstantHash:
            def __init__(self, data):
                pass
            def hexdigest(self):
                return "always-the-same"

        _, collisions = comparison.measure_hashes(["one", "two"], ConstantHash)
        self.assertEqual(collisions, 1)

    def test_file_hashes(self):
        module = load_module("lab5/q4-pdf.py")
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.bin"
            received = Path(directory) / "received.bin"
            data = bytes(range(256)) * 100
            original.write_bytes(data)
            received.write_bytes(data)
            self.assertTrue(module.compare_file_hashes(original, received)[2])
            received.write_bytes(data + b"changed")
            self.assertFalse(module.compare_file_hashes(original, received)[2])

    def test_rsa_signature_families(self):
        for path in ("lab6/q1.py", "lab6/rsa-sha.py"):
            module = load_module(path)
            message = b"original message"
            signature = module.sign_message(message, self.signing_key)
            self.assertTrue(module.verify_signature(message, signature, self.signing_key.publickey()))
            self.assertFalse(module.verify_signature(message + b"changed", signature, self.signing_key.publickey()))
            self.assertFalse(module.verify_signature(message, signature, self.wrong_key.publickey()))

    def test_elgamal_signatures(self):
        module = load_module("lab6/q2-elgamel.py")
        public, private = module.generate_keys(128)
        signature = module.sign_message(b"original", public, private)
        self.assertTrue(module.verify_signature(b"original", signature, public))
        self.assertFalse(module.verify_signature(b"changed", signature, public))

    def test_schnorr_signatures(self):
        module = load_module("lab6/q3-schnorr.py")
        p, q, g = module.generate_parameters(64)
        self.assertEqual(pow(g, q, p), 1)
        public, private = module.generate_keys(p, q, g)
        signature = module.sign_message(b"original", p, q, g, private)
        self.assertTrue(module.verify_signature(b"original", signature, p, q, g, public))
        self.assertFalse(module.verify_signature(b"changed", signature, p, q, g, public))

    def test_dh_hmac_verification(self):
        module = load_module("lab6/dfhk.py")
        key = module.derive_hmac_key(2, 23)
        tag = module.create_hmac(b"original", key)
        self.assertTrue(module.verify_hmac(b"original", tag, key))
        self.assertFalse(module.verify_hmac(b"changed", tag, key))

    def test_lab4_exchange_tampering_and_revocation(self):
        module = load_module("lab4/q1_secure_corp.py")
        systems = {}
        module.register_system(systems, "Finance", bits=1024)
        module.register_system(systems, "HR", bits=1024)
        first, second = module.exchange_session_keys(systems, "Finance", "HR", 7919, 2)
        self.assertEqual(first, second)
        packet = module.encrypt_message(b"report", first)
        self.assertEqual(module.decrypt_message(packet, second), b"report")
        nonce, tag, ciphertext = packet
        changed = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        with self.assertRaises(ValueError):
            module.decrypt_message((nonce, tag, changed), second)
        transcript = module.create_transcript("Finance", "HR", 8, 19)
        signature = module.sign_transcript(transcript, systems["Finance"]["private"])
        changed_transcript = transcript + b"CHANGED"
        self.assertFalse(module.verify_transcript(changed_transcript, signature,
                                                 systems["Finance"]["public"]))
        module.revoke_system(systems, "Finance")
        with self.assertRaises(PermissionError):
            module.exchange_session_keys(systems, "Finance", "HR", 7919, 2)

    def test_paillier_addition_and_wraparound(self):
        for path in ("lab7/q1-pallier.py", "lab7/data-share.py", "lab88/q2-pallier.py"):
            module = load_module(path)
            public, private = module.generate_keys(64)
            for a, b in ((15, 25), (0, 0), (public[0] - 1, 2)):
                encrypted_sum = module.homomorphic_add(public, module.encrypt(public, a), module.encrypt(public, b))
                self.assertEqual(module.decrypt(public, private, encrypted_sum), (a + b) % public[0])
            with self.assertRaises(ValueError):
                module.encrypt(public, public[0])

    def test_raw_rsa_homomorphic_multiplication(self):
        module = load_module("lab7/q2-rsa.py")
        public, private = module.generate_keys(64)
        for a, b in ((7, 3), (0, 9), (public[0] - 1, 2)):
            encrypted = module.homomorphic_multiply(public, module.encrypt(a, public), module.encrypt(b, public))
            self.assertEqual(module.decrypt(encrypted, private), a * b % public[0])

    def test_symmetric_search_and_tampering(self):
        from Crypto.Random import get_random_bytes
        module = load_module("lab88/q1-sse.py")
        aes_key, search_key = get_random_bytes(32), get_random_bytes(32)
        documents = {"doc1": "Python python security", "doc2": "java", "doc3": "python math"}
        encrypted = module.encrypt_documents(documents, aes_key)
        index = module.build_encrypted_index(documents, aes_key, search_key)
        matches = module.search_documents("PYTHON!", index, encrypted, aes_key, search_key)
        self.assertEqual([item[0] for item in matches], ["doc1", "doc3"])
        self.assertEqual(module.search_documents("missing", index, encrypted, aes_key, search_key), [])
        nonce, tag, ciphertext = encrypted["doc1"]
        encrypted["doc1"] = nonce, tag, bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        with self.assertRaises(ValueError):
            module.search_documents("python", index, encrypted, aes_key, search_key)

    def test_paillier_search(self):
        module = load_module("lab88/q2-pallier.py")
        public, private = module.generate_keys(64)
        documents = {1: "python python", 2: "java", 3: "python math"}
        search_key = bytes(range(32))
        index = module.build_encrypted_index(documents, public, search_key)
        self.assertEqual(module.search_documents("PYTHON!", index, public, private, search_key), [1, 3])
        self.assertEqual(module.search_documents("absent", index, public, private, search_key), [])

    def test_generated_key_files_and_overwrite_protection(self):
        module = load_module("lab6/q4-keys.py")
        with tempfile.TemporaryDirectory() as directory:
            private, public = module.generate_key_files(Path(directory) / "private.pem", Path(directory) / "public.pem")
            self.assertEqual(RSA.import_key(private.read_bytes()).n, RSA.import_key(public.read_bytes()).n)
            with self.assertRaises(FileExistsError):
                module.generate_key_files(private, public)



# ---------- ACTUAL TCP TESTS ----------
class NetworkChecks(unittest.TestCase):
    # A bound ephemeral port avoids racing another local program on port 5000/5001.
    def run_pair(self, handler, client):
        failures = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(10)
            port = listener.getsockname()[1]

            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(10)
                        handler(connection)
                except Exception as error:
                    failures.append(error)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            result = client(port)
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            return result

    def test_hash_socket_original_and_tampered(self):
        server = load_module("lab5/q2-server.py")
        client = load_module("lab5/q2-client.py")
        for tamper in (False, True):
            original = ("Large message " * 1000).encode("utf-8")
            expected = hashlib.sha256(original).hexdigest()
            sent_data = original

            if tamper:
                sent_data = original + b"CHANGED"

            with redirect_stdout(io.StringIO()):
                server_hash = self.run_pair(server.handle_client,
                    lambda port: client.send_data(sent_data, port=port))
            self.assertEqual(server_hash == expected, not tamper)

    def test_signature_socket_original_and_tampered(self):
        server = load_module("lab6/q4-server.py")
        client = load_module("lab6/q4-client.py")
        key = RSA.generate(2048)
        for tamper in (False, True):
            original = "Long signed message " * 500
            signature = client.sign_message(original.encode("utf-8"), key)
            received = original

            if tamper:
                received = original + "CHANGED"

            packet = client.build_packet(received, signature)

            with redirect_stdout(io.StringIO()):
                valid = self.run_pair(lambda connection: server.handle_client(connection, key.publickey()),
                    lambda port: client.send_packet(packet, port=port))
            self.assertEqual(valid, not tamper)



if __name__ == "__main__":
    unittest.main(verbosity=2)
