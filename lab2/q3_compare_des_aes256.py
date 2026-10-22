"""Q3: Compare average DES/AES-256 encryption and decryption times.

Both use ECB and PKCS#7. Timings include cipher creation and pad/unpad,
but exclude input, text conversion, and printing. Keys are chosen demo keys.
"""

from time import perf_counter
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad



# ---------- ENCRYPT DES ----------
# Encrypt des.
# Keep inputs/outputs explicit so this step can be reused independently.
def encrypt_des(message, key):

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = pad(message, DES.block_size)
    ciphertext = cipher.encrypt(padded_message)

    return ciphertext



# ---------- DECRYPT DES ----------
# Decrypt des.
# Keep inputs/outputs explicit so this step can be reused independently.
def decrypt_des(ciphertext, key):

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = DES.new(key, DES.MODE_ECB)
    padded_message = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_message, DES.block_size)

    return plaintext



# ---------- ENCRYPT AES ----------
# Encrypt aes.
# Keep inputs/outputs explicit so this step can be reused independently.
def encrypt_aes(message, key):
    if len(key) != 32:
        raise ValueError("This comparison requires AES-256: a 32-byte key.")

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)

    return ciphertext



# ---------- DECRYPT AES ----------
# Decrypt aes.
# Keep inputs/outputs explicit so this step can be reused independently.
def decrypt_aes(ciphertext, key):
    if len(key) != 32:
        raise ValueError("This comparison requires AES-256: a 32-byte key.")

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_message, AES.block_size)

    return plaintext



# ---------- MEASURE AVERAGE TIME ----------
# Warm up, repeat the supplied operation, then return average seconds per call.
# Keep printing outside the timer; key/cipher setup included in the callable is measured.
def measure_average_time(function, data, key, repeats):
    """Return average seconds per complete function call."""
    if repeats <= 0:
        raise ValueError("Repetitions must be greater than zero.")

    for _ in range(10):
        function(data, key)  # Warm up before starting the timer.

    start = perf_counter()
    for _ in range(repeats):
        function(data, key)

    return (perf_counter() - start) / repeats



# ---------- COMPARE ENCRYPTION TIMES ----------
# Encrypt/decrypt the same message using both algorithms and collect timings.
# A shorter time does not imply stronger encryption.
def compare_encryption_times(message, repeats=10000):
    """Return measured rows so another program can reuse the results."""
    des_key = b"A1B2C3D4"
    aes_key = bytes.fromhex("0123456789ABCDEF" * 4)  # 32 bytes, not 64.
    rows = []
    for name, encrypt, decrypt, key in [
        ("DES", encrypt_des, decrypt_des, des_key),
        ("AES-256", encrypt_aes, decrypt_aes, aes_key),
    ]:
        ciphertext = encrypt(message, key)
        if decrypt(ciphertext, key) != message:
            raise ValueError("Decryption verification failed for " + name)

        enc_time = measure_average_time(encrypt, message, key, repeats)
        dec_time = measure_average_time(decrypt, ciphertext, key, repeats)
        rows.append((name, enc_time, dec_time))

    return rows



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
def main():
    default = "Performance Testing of Encryption Algorithms"
    message = input('Plaintext [Enter = ' + default + ']: ')

    if message == "":
        message = default

    repeats = input('Repetitions [Enter = 10000]: ')

    if repeats == "":
        repeats = '10000'

    repeats = int(repeats)
    rows = compare_encryption_times(message.encode("utf-8"), repeats)
    print("ECB; cipher creation + pad/unpad included; average microseconds/call")
    print("{:<12} {:>14} {:>14}".format("Algorithm", "Encrypt (us)", "Decrypt (us)"))
    for name, enc, dec in rows:
        print("{:<12} {:>14.3f} {:>14.3f}".format(name, enc * 1e6, dec * 1e6))

    enc_winner = min(rows, key=lambda row: row[1])[0]
    dec_winner = min(rows, key=lambda row: row[2])[0]
    print("Faster in this run: encryption =", enc_winner, "; decryption =", dec_winner)
    print("Short-message results include Python/library overhead and machine effects.")
    print("Timing does not establish cryptographic strength; DES is obsolete.")




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
measure = measure_average_time
compare = compare_encryption_times



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
        raise SystemExit(1)
