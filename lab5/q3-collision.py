"""Lab 5: compare MD5, SHA-1, and SHA-256 on the same random dataset."""

import hashlib
import secrets
import string
import time



# ---------- MAKE THE DATASET ----------
# CHANGE count/length to compare the effect of dataset size and message length.
def generate_messages(count=100, length=30):
    if count <= 0 or length <= 0:
        raise ValueError("Count and length must be positive.")

    characters = string.ascii_letters + string.digits
    messages = []

    for _ in range(count):
        message = ""

        for _ in range(length):
            message += secrets.choice(characters)

        messages.append(message)

    return messages



# ---------- HASH AND COUNT REAL COLLISIONS ----------
# A duplicate message is NOT a collision. Different messages sharing a hash are.
# The timer includes hashing and the dictionary lookup used to check collisions.
def measure_hashes(messages, algorithm):
    seen_hashes = {}
    collisions = 0
    start = time.perf_counter()

    for message in messages:
        digest = algorithm(message.encode("utf-8")).hexdigest()

        if digest in seen_hashes and seen_hashes[digest] != message:
            collisions += 1
        else:
            seen_hashes[digest] = message

    elapsed = time.perf_counter() - start
    return elapsed, collisions



# ---------- COMPARE THE SAME INPUTS ----------
# HINT: no collisions in 100 messages does NOT prove collision resistance.
# Known MD5/SHA-1 attacks are not reproduced by a small random-string experiment.
def main():
    count = input('Number of strings [100]: ')

    if count == "":
        count = '100'

    count = int(count)
    length = input('Characters per string [30]: ')

    if length == "":
        length = '30'

    length = int(length)
    messages = generate_messages(count, length)

    algorithms = {
        'MD5': hashlib.md5,
        'SHA-1': hashlib.sha1,
        'SHA-256': hashlib.sha256,
    }

    for name, algorithm in algorithms.items():
        elapsed, collisions = measure_hashes(messages, algorithm)

        print("\n" + name)
        print("Time:", elapsed, "seconds")
        print("Collisions between different strings:", collisions)

    print("No random collisions here does not establish cryptographic strength.")



if __name__ == "__main__":
    main()
