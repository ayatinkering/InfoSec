"""Meaningful checks for Lab 2, including independent known-answer vectors."""

from contextlib import redirect_stdout
import io
import unittest
from Crypto.Cipher import AES

import q1_des as des
import q2_aes128 as aes128
import q3_compare_des_aes256 as benchmark
import q4_triple_des as triple
import q5_aes192_steps as aes192


class Lab2Checks(unittest.TestCase):
    def test_known_des_block(self):
        key = bytes.fromhex("133457799BBCDFF1")
        block = bytes.fromhex("0123456789ABCDEF")
        self.assertEqual(des.encrypt(block, key)[:8].hex(), "85e813540f0ab405")

    def test_fips_aes128_block(self):
        key = bytes(range(16))
        block = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(aes128.encrypt(block, key)[:16].hex(),
                         "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_fips_aes192_educational_block(self):
        key = bytes(range(24))
        block = bytes.fromhex("00112233445566778899aabbccddeeff")
        keys = aes192.expand_key(key)
        self.assertEqual(len(keys), 13)
        self.assertTrue(all(len(k) == 16 for k in keys))
        self.assertEqual(aes192.encrypt_block(block, keys).hex(),
                         "dda97ca4864cdfe06eaf70a0ec0d7191")

    def test_fips_aes256_block(self):
        key = bytes(range(32))
        block = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(benchmark.encrypt_aes(block, key)[:16].hex(),
                         "8ea2b7ca516745bfeafc49904b496089")

    def test_round_trips_and_padding_boundaries(self):
        cases = [
            (des.encrypt, des.decrypt, b"A1B2C3D4", 8),
            (aes128.encrypt, aes128.decrypt, bytes(range(16)), 16),
            (benchmark.encrypt_aes, benchmark.decrypt_aes, bytes(range(32)), 16),
            (triple.encrypt, triple.decrypt, bytes.fromhex(triple.DEMO_KEY_HEX), 8),
            (aes192.encrypt, aes192.decrypt, bytes(range(24)), 16),
        ]
        messages = [b"", b"A", b"X" * 7, b"X" * 8, b"X" * 15,
                    b"X" * 16, b"X" * 17, bytes(range(256)),
                    "Spaces, punctuation! नमस्ते".encode("utf-8")]
        for encrypt, decrypt, key, block_size in cases:
            for message in messages:
                with self.subTest(algorithm=encrypt.__module__, length=len(message)):
                    ciphertext = encrypt(message, key)
                    self.assertEqual(len(ciphertext),
                                     (len(message) // block_size + 1) * block_size)
                    self.assertEqual(decrypt(ciphertext, key), message)

    def test_educational_aes_matches_library_for_varied_keys_and_blocks(self):
        for seed in range(12):
            key = bytes((i * 17 + seed * 13) % 256 for i in range(24))
            block = bytes((i * 31 + seed * 7) % 256 for i in range(16))
            actual = aes192.encrypt_block(block, aes192.expand_key(key))
            expected = AES.new(key, AES.MODE_ECB).encrypt(block)
            self.assertEqual(actual, expected)

    def test_trace_covers_multiple_blocks_and_final_round(self):
        key = bytes(range(24))
        message = b"A" * 20
        output = io.StringIO()
        with redirect_stdout(output):
            traced = aes192.encrypt_with_steps(message, key)
        self.assertEqual(traced, aes192.encrypt(message, key))
        text = output.getvalue()
        self.assertEqual(text.count("BLOCK "), 2)
        self.assertEqual(text.count("  MixColumns"), 22)
        self.assertEqual(text.count("Round 12 (final; no MixColumns)"), 2)
        self.assertIn("w[51]", text)
        self.assertIn("K[12]", text)

    def test_bad_inputs_and_manual_key_errors(self):
        calls = [
            lambda: des.encrypt(b"abc", b"short"),
            lambda: aes128.encrypt(b"abc", b"0" * 15),
            lambda: benchmark.encrypt_aes(b"abc", b"0" * 16),
            lambda: triple.encrypt(b"abc", bytes.fromhex(triple.MANUAL_KEY_HEX)),
            lambda: aes192.encrypt(b"abc", bytes.fromhex(aes192.MANUAL_KEY_HEX)),
            lambda: aes192.encrypt_block(b"short", aes192.expand_key(bytes(24))),
            lambda: benchmark.measure(des.encrypt, b"abc", b"A1B2C3D4", 0),
            lambda: aes128.decrypt(b"incomplete", bytes(16)),
        ]
        for call in calls:
            with self.assertRaises(ValueError):
                call()

    def test_benchmark_returns_measurements(self):
        rows = benchmark.compare(b"Performance Testing of Encryption Algorithms", 20)
        self.assertEqual([row[0] for row in rows], ["DES", "AES-256"])
        for _, enc, dec in rows:
            self.assertGreater(enc, 0)
            self.assertGreater(dec, 0)


class ModeVariantChecks(unittest.TestCase):
    def test_mode_round_trips_for_every_key_size(self):
        cases = [(des, b"A1B2C3D4", 8)]
        cases += [(aes128, bytes(range(size)), 16) for size in (16, 24, 32)]
        for module, key, block in cases:
            for message in (b"", b"A", b"X" * block, bytes(range(35))):
                with self.subTest(module=module.__name__, size=len(key), length=len(message)):
                    ct = module.encrypt_ecb(message, key)
                    self.assertEqual(module.decrypt_ecb(ct, key), message)
                    for mode in ("cbc", "cfb", "ofb"):
                        iv, ct = getattr(module, "encrypt_" + mode)(message, key)
                        self.assertEqual(len(iv), block)
                        self.assertEqual(getattr(module, "decrypt_" + mode)(ct, key, iv), message)
                        if mode != "cbc":
                            self.assertEqual(len(ct), len(message))
                    iv, ct = module.encrypt_cfb(message, key, segment_size=8)
                    self.assertEqual(module.decrypt_cfb(ct, key, iv, segment_size=8), message)
                    nonce, ct = module.encrypt_ctr(message, key, initial_value=37)
                    self.assertEqual(module.decrypt_ctr(ct, key, nonce, initial_value=37), message)
                    for mode in (("eax", "gcm") if module is aes128 else ("eax",)):
                        nonce, ct, tag = getattr(module, "encrypt_" + mode)(message, key, aad=b"header")
                        self.assertEqual(getattr(module, "decrypt_" + mode)(ct, key, nonce, tag, aad=b"header"), message)

    def test_nist_aes_mode_vectors(self):
        # SP 800-38A first-block vectors for CBC, CFB128, OFB, and CTR.
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        block = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        _, ct = aes128.encrypt_cbc(block, key, iv)
        self.assertEqual(ct[:16].hex(), "7649abac8119b246cee98e9b12e9197d")
        for mode in ("cfb", "ofb"):
            _, ct = getattr(aes128, "encrypt_" + mode)(block, key, iv)
            self.assertEqual(ct.hex(), "3b3fd92eb72dad20333449f8e83cfb4a")
        counter = int("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 16)
        _, ct = aes128.encrypt_ctr(block, key, nonce=b"", initial_value=counter)
        self.assertEqual(ct.hex(), "874d6191b620e3261bef6864990db6ce")
        _, ct, tag = aes128.encrypt_gcm(bytes(16), bytes(16), nonce=bytes(12))
        self.assertEqual(ct.hex(), "0388dace60b6a392f328c2b971b2fe78")
        self.assertEqual(tag.hex(), "ab6e47d42cec13bdf53a67b21257bddf")

    def test_authentication_rejects_tampering(self):
        for module, key, mode in [(des, b"A1B2C3D4", "eax"),
                                  (aes128, bytes(16), "eax"),
                                  (aes128, bytes(32), "gcm")]:
            nonce, ct, tag = getattr(module, "encrypt_" + mode)(b"secret", key, aad=b"header")
            change = lambda data: bytes([data[0] ^ 1]) + data[1:]
            for bad_ct, bad_nonce, bad_tag, bad_aad in [
                (change(ct), nonce, tag, b"header"),
                (ct, change(nonce), tag, b"header"),
                (ct, nonce, change(tag), b"header"),
                (ct, nonce, tag, b"wrong header"),
            ]:
                with self.assertRaises(ValueError):
                    getattr(module, "decrypt_" + mode)(bad_ct, key, bad_nonce, bad_tag, aad=bad_aad)

    def test_triple_des_variants(self):
        for size in (16, 24):
            key = bytes.fromhex(triple.DEMO_KEY_HEX)[:size]
            message = b"Two-key or three-key Triple DES"
            ct = des.encrypt_3des_ecb(message, key)
            self.assertEqual(des.decrypt_3des_ecb(ct, key), message)
            iv, ct = des.encrypt_3des_cbc(message, key)
            self.assertEqual(des.decrypt_3des_cbc(ct, key, iv), message)

    def test_parameters_and_key_generation(self):
        self.assertEqual(len(des.generate_key()), 8)
        for bits in (128, 192, 256):
            self.assertEqual(len(aes128.generate_key(bits)), bits // 8)
        for call in [
            lambda: aes128.generate_key(64),
            lambda: des.encrypt_cbc(b"abc", b"A1B2C3D4", iv=b"short"),
            lambda: aes128.encrypt_cbc(b"abc", bytes(16), iv=bytes(8)),
            lambda: aes128.encrypt_cfb(b"abc", bytes(16), segment_size=7),
            lambda: des.encrypt_ctr(b"abc", b"A1B2C3D4", nonce=bytes(8)),
            lambda: des.encrypt_3des_ecb(b"abc", bytes.fromhex(triple.MANUAL_KEY_HEX)),
        ]:
            with self.assertRaises(ValueError):
                call()


if __name__ == "__main__":
    unittest.main(verbosity=2)
