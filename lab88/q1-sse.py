"""Lab 8: HMAC search tokens, AES-GCM encrypted documents and document IDs."""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import hmac
import re


# ---------- TOKENIZE DOCUMENT TEXT ----------
# Lowercase English letters/digits so Python, PYTHON, and python match.
def words(text):
    return re.findall(r"[a-z0-9]+", text.lower())



# ---------- MAKE A REPEATABLE SECRET SEARCH TOKEN ----------
# The SAME word and search key yield the SAME token. Fresh randomized AES or
# Paillier encryptions cannot be compared directly for equality like this.
def create_search_token(word, search_key):
    normalized_word = word.lower()
    word_bytes = normalized_word.encode("utf-8")
    token_hash = hmac.new(search_key, word_bytes, hashlib.sha256)

    return token_hash.hexdigest()



# ---------- REQUIRE A SINGLE SEARCH WORD ----------
# HINT: a new keyword changes which posting list is found, not the keys.
def query_token(query, search_key):
    terms = words(query)

    if len(terms) != 1:
        raise ValueError("Enter exactly one word; multiword search is not implemented.")

    return create_search_token(terms[0], search_key)



# ---------- ENCRYPT ONE TEXT VALUE ----------
# Return everything needed to decrypt: (nonce, tag, ciphertext).
# Use separate encryption/search keys; ciphertext randomness must not break lookup.
def encrypt_data(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode("utf-8"))
    return cipher.nonce, tag, ciphertext



# ---------- DECRYPT AND VERIFY ONE TEXT VALUE ----------
# A changed ciphertext/tag should raise ValueError before returning plaintext.
def decrypt_data(encrypted, aes_key):
    nonce, tag, ciphertext = encrypted
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")



# ---------- ENCRYPT EVERY DOCUMENT ----------
# Keep the original plaintext corpus on the authorized client in this demo.
def encrypt_documents(documents, aes_key):
    encrypted_documents = {}

    for document_id, text in documents.items():
        encrypted_documents[document_id] = encrypt_data(text, aes_key)

    return encrypted_documents



# ---------- BUILD THE SEARCH INDEX ----------
# Map each HMAC token to ENCRYPTED document IDs. set() prevents duplicate IDs
# when a word appears repeatedly in the same document.
def build_encrypted_index(documents, aes_key, search_key):
    index = {}

    for document_id, text in documents.items():
        for word in set(words(text)):
            token = create_search_token(word, search_key)

            if token not in index:
                index[token] = []

            index[token].append(encrypt_data(document_id, aes_key))

    return index



# ---------- LOOK UP, DECRYPT IDs, THEN DECRYPT DOCUMENTS ----------
# This function takes the index and keys explicitly; it does not use hidden globals.
def search_documents(query, index, encrypted_documents, aes_key, search_key):
    token = query_token(query, search_key)
    results = []

    for encrypted_id in index.get(token, []):
        document_id = decrypt_data(encrypted_id, aes_key)
        document = decrypt_data(encrypted_documents[document_id], aes_key)
        results.append((document_id, document))

    return results



# ---------- EXAMPLE DATA AND QUERY ----------
# CHANGE the corpus below for another scenario. Keep the same keys for build/search.
# This is a teaching index: token repetition and access patterns can still leak.
def main():
    documents = {
        "doc1": "python cryptography security",
        "doc2": "java programming security",
        "doc3": "python machine learning",
        "doc4": "network security firewall",
        "doc5": "database encryption privacy",
        "doc6": "python encryption algorithms",
        "doc7": "machine learning models",
        "doc8": "firewall network monitoring",
        "doc9": "privacy secure database",
        "doc10": "cryptography python network",
    }
    query = input('Search word [python]: ')

    if query == "":
        query = 'python'

    aes_key = get_random_bytes(32)
    search_key = get_random_bytes(32)
    encrypted_documents = encrypt_documents(documents, aes_key)
    index = build_encrypted_index(documents, aes_key, search_key)

    # OPTIONAL TWIST: uncomment these lines to alter a stored document.
    # Keep its original tag. AES-GCM should then reject it during decryption.
    # nonce, tag, ciphertext = encrypted_documents["doc1"]
    # changed_ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    # encrypted_documents["doc1"] = (nonce, tag, changed_ciphertext)

    try:
        results = search_documents(query, index, encrypted_documents, aes_key, search_key)
        print("Search query:", query)

        for document_id, text in results:
            print(document_id + ":", text)

        if not results:
            print("No matching documents.")
    except ValueError as error:
        print("Decryption/authentication failed:", error)



if __name__ == "__main__":
    main()
