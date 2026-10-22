"""Verify the mathematical examples, hybrids, prompts, and file transport."""

# Import test utilities and the five reusable question modules.
from contextlib import redirect_stdout
import io
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch
import q1_rsa as rsa
import q2_ecc as ecc
import q3_elgamal as elgamal
import q4_file_transfer as transfer
import q5_diffie_hellman as dh


# Reuse generated receiver keys so the tests spend time on behavior, not setup.
class Lab3Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_keys()
        cls.other_rsa_key = rsa.generate_keys()
        cls.ecc_key = ecc.generate_keys()

    # Check familiar numerical RSA results independently of the library path.
    def test_textbook_rsa_known_answer_and_binary(self):
        public, private = rsa.textbook_keys(61, 53, 17)
        self.assertEqual(public, (3233, 17))
        self.assertEqual(private, (3233, 2753))
        self.assertEqual(rsa.encrypt_number(65, *public), 2790)
        self.assertEqual(rsa.decrypt_number(2790, *private), 65)
        data = bytes(range(256))
        self.assertEqual(rsa.decrypt_textbook(rsa.encrypt_textbook(data, *public), *private), data)

    # Exercise the exact RSA-OAEP length boundary and wrong-key rejection.
    def test_rsa_oaep_limits_and_wrong_key(self):
        for data in (b"", b"Asymmetric Encryption", b"X" * 190):
            ct = rsa.encrypt(data, self.rsa_key.public_key())
            self.assertEqual(rsa.decrypt(ct, self.rsa_key), data)

        with self.assertRaises(ValueError):
            rsa.encrypt(b"X" * 191, self.rsa_key.public_key())

        with self.assertRaises(ValueError):
            rsa.decrypt(rsa.encrypt(b"secret", self.rsa_key), self.other_rsa_key)

    # Cover ECC aliases, manually supplied private scalars, and Unicode bytes.
    def test_ecc_curves_and_round_trips(self):
        for curve in ("secp256r1", "P-384", "P-521"):
            private = ecc.generate_keys(curve, private_value=7)

            for data in (b"", bytes(range(256)), "Secure नमस्ते".encode("utf-8")):
                packet = ecc.encrypt(data, private.public_key())
                self.assertEqual(ecc.decrypt(packet, private), data)

    # A changed tag, nonce, salt, ciphertext, or receiving key must not decrypt.
    def test_ecc_tampering_and_wrong_key(self):
        packet = ecc.encrypt(b"Confidential record", self.ecc_key.public_key())

        for field in ("tag", "nonce", "salt", "ciphertext", "ephemeral_public"):
            changed = dict(packet)
            value = changed[field]
            changed[field] = value[:-1] + bytes([value[-1] ^ 1])

            with self.assertRaises((ValueError, TypeError)):
                ecc.decrypt(changed, self.ecc_key)

        with self.assertRaises(ValueError):
            ecc.decrypt(packet, ecc.generate_keys())

    # Check a hand-computable ElGamal vector and every possible byte value.
    def test_elgamal_known_answer_and_binary(self):
        self.assertEqual(elgamal.encrypt_number(10, (23, 5, 8), k=3), (10, 14))
        self.assertEqual(elgamal.decrypt_number((10, 14), 23, 6), 10)
        self.assertEqual(elgamal.decrypt_number(elgamal.encrypt_number(0, (23, 5, 8), k=3), 23, 6), 0)
        public, private = elgamal.generate_keys(467, 2, 127)
        data = bytes(range(256))
        self.assertEqual(elgamal.decrypt(elgamal.encrypt(data, public), 467, private), data)

    # Verify both Diffie-Hellman peers and that KDF context affects the AES key.
    def test_diffie_hellman_known_answer(self):
        result = dh.exchange(23, 5, 6, 15)
        self.assertEqual((result["alice_public"], result["bob_public"]), (8, 19))
        self.assertEqual((result["alice_secret"], result["bob_secret"]), (2, 2))
        key = dh.derive_session_key(2, 23, 5, bytes(16))
        self.assertEqual(len(key), 32)
        self.assertNotEqual(key, dh.derive_session_key(2, 23, 5, bytes([1]) * 16))

    # Exercise complete file encryption, wire serialization, and tamper rejection.
    def test_hybrid_files_and_serialization(self):
        for algorithm, private in (("RSA", self.rsa_key), ("ECC", self.ecc_key)):
            for message in (b"", bytes(range(256)) * 100):
                packet = transfer.encrypt_file_bytes(message, algorithm, private.public_key())
                encoded = transfer.serialize_packet(packet, algorithm)
                decoded_algorithm, decoded = transfer.deserialize_packet(encoded)
                self.assertEqual(decoded_algorithm, algorithm)
                self.assertEqual(transfer.decrypt_file_bytes(decoded, algorithm, private), message)
                decoded["tag"] = bytes([decoded["tag"][0] ^ 1]) + decoded["tag"][1:]

                with self.assertRaises(ValueError):
                    transfer.decrypt_file_bytes(decoded, algorithm, private)

    # Check the benchmark returns comparable timing, key-size, and overhead data.
    def test_file_benchmark_measurements(self):
        rows = transfer.benchmark([("sample", b"A" * 1024)], repeats=1)
        self.assertEqual(len(rows), 2)

        for row in rows:
            self.assertEqual(row["plaintext_bytes"], 1024)
            self.assertGreater(row["encrypt_ms"], 0)
            self.assertGreater(row["decrypt_ms"], 0)
            self.assertGreater(row["public_key_bytes"], 0)
            self.assertGreater(row["crypto_overhead_bytes"], 0)
            self.assertGreater(row["json_wire_bytes"], 1024)

    # Run alternate prompt paths so numeric inputs are verified as well as defaults.
    def test_numeric_input_paths(self):
        examples = [
            (rsa.main, ["1", "1", "61", "53", "17", "2", "65"], "Decrypted integer: 65"),
            (rsa.main, ["1", "2", "3233", "17", "2753", "1", "Example"], "Decrypted text: Example"),
            (elgamal.main, ["467", "2", "127", "", "2", "123", "53"], "Verified: True"),
            (ecc.main, ["Test", "", "P-384", "7"], "Verified: True"),
        ]

        for function, inputs, expected in examples:
            output = io.StringIO()

            with patch("builtins.input", side_effect=inputs), redirect_stdout(output):
                function()

            self.assertIn(expected, output.getvalue())

    # Reject malformed number-theory inputs and oversized transport frames.
    def test_invalid_inputs(self):
        calls = [
            lambda: rsa.textbook_keys(61, 61, 17),
            lambda: rsa.textbook_keys(60, 53, 17),
            lambda: rsa.encrypt_number(3233, 3233, 17),
            lambda: elgamal.generate_keys(15, 2, 3),
            lambda: elgamal.encrypt(b"text", (23, 5, 8)),
            lambda: dh.exchange(15, 5, 6, 7),
            lambda: dh.compute_shared_secret(1, 6, 23),
            lambda: transfer.benchmark([], 0),
            lambda: transfer.deserialize_packet(b'{"algorithm":"unknown","fields":{}}'),
        ]

        for call in calls:
            with self.assertRaises(ValueError):
                call()

# Keep transport checks separate so a failure is easy to identify.
class TransportChecks(unittest.TestCase):
    # Cover exact reads, frame limits, and a prematurely closed connection.
    def test_framing(self):
        first, second = socket.socketpair()

        with first, second:
            transfer.send_frame(first, b"complete message")
            self.assertEqual(transfer.receive_frame(second), b"complete message")
            first.sendall(struct.pack("!Q", 100))

            with self.assertRaises(ValueError):
                transfer.receive_frame(second, maximum=10)

            first.sendall(b"short")
            first.shutdown(socket.SHUT_WR)

            with self.assertRaises(ConnectionError):
                transfer.receive_exact(second, 10)

    # Transfer a real temporary file through a TCP client and receiver handler.
    def test_tcp_file_transfer(self):
        for algorithm in ("RSA", "ECC"):
            private_key = transfer.generate_receiver_key(algorithm)
            failures = []

            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "source.bin"
                destination = Path(directory) / "received.bin"
                source.write_bytes(bytes(range(256)) * 1024)

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                    server.bind(("127.0.0.1", 0))
                    server.listen(1)
                    server.settimeout(10)
                    port = server.getsockname()[1]

                    def receiver():
                        try:
                            connection, _ = server.accept()

                            with connection:
                                connection.settimeout(10)
                                transfer.handle_receiver(connection, algorithm, private_key, destination)
                        except Exception as error:
                            failures.append(error)

                    worker = threading.Thread(target=receiver, daemon=True)
                    worker.start()
                    ack = transfer.send_file("127.0.0.1", port, source, transfer.fingerprint(private_key))
                    worker.join(timeout=10)

                    self.assertFalse(worker.is_alive())
                    self.assertEqual(failures, [])
                    self.assertEqual(ack["bytes"], source.stat().st_size)
                    self.assertEqual(destination.read_bytes(), source.read_bytes())

                # The public receive wrapper must refuse an existing destination.
                with self.assertRaises(FileExistsError):
                    transfer.receive_file("127.0.0.1", 0, algorithm, destination)


# Run all checks using the project's selected interpreter.
if __name__ == "__main__":
    unittest.main(verbosity=2)
