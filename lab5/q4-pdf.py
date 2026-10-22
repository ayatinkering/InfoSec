"""Lab 5: compare the SHA-512 digests of any two files, including PDFs."""

import hashlib



# ---------- HASH A FILE WITHOUT LOADING IT ALL ----------
# Binary mode preserves exact bytes. update() feeds each chunk into ONE hash.
def file_hash(filename):
    digest = hashlib.sha512()

    with open(filename, "rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()



# ---------- COMPARE ORIGINAL AND RECEIVED FILES ----------
# HINT: duplicate a file, edit the copy, then compare. Do not re-create the
# original reference digest from the edited copy: that would change the baseline.
def compare_file_hashes(original_path, received_path):
    original_hash = file_hash(original_path)
    received_hash = file_hash(received_path)

    return original_hash, received_hash, original_hash == received_hash



# ---------- INPUT FILE PATHS ----------
# The filenames are inputs: no real original.pdf is required in the repository.
def main():
    original_path = input('Original file path [original.pdf]: ')

    if original_path == "":
        original_path = 'original.pdf'

    received_path = input('Received file path [received.pdf]: ')

    if received_path == "":
        received_path = 'received.pdf'

    original, received, valid = compare_file_hashes(original_path, received_path)

    print("Original SHA-512:", original)
    print("Received SHA-512:", received)
    if valid:
        print("File integrity verified")
    else:
        print("File modified or corrupted")



if __name__ == "__main__":
    try:
        main()
    except OSError as error:
        print("Cannot read file:", error)
