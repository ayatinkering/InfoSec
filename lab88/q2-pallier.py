"""Lab 8: HMAC-token search with Paillier-encrypted integer document IDs.

This is a HYBRID teaching index, not a full public-key searchable-encryption
protocol. Query generation requires search_key, not merely the Paillier public key.
The local plaintext documents are not encrypted by this example.
"""

import hashlib
import hmac
import re
from Crypto.Random import get_random_bytes

from Crypto.Util.number import getPrime
from math import gcd, lcm
from secrets import randbelow



# ---------- GENERATE PAILLIER KEYS ----------
# Public = (n,g); private = (lambda,mu). g=n+1 simplifies the formulas.
# Repeat if the primes match or lambda has no inverse modulo n.
def generate_keys(bits=1024):
    if bits < 32:
        raise ValueError("Use at least 32 bits for this educational example.")

    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)

        if p == q:
            continue

        n = p * q
        g = n + 1
        lam = lcm(p - 1, q - 1)

        if gcd(lam, n) != 1:
            continue

        mu = pow(lam, -1, n)
        return (n, g), (lam, mu)



# ---------- ENCRYPT ONE INTEGER ----------
# c = g^m * r^n mod n^2. New random r hides repeated plaintext values.
# HINT: encrypt the same m twice; the ciphertexts will usually differ.
def encrypt(public_key, message):
    n, g = public_key

    if not 0 <= message < n:
        raise ValueError("Message must satisfy 0 <= message < n.")

    while True:
        r = randbelow(n - 1) + 1

        if gcd(r, n) == 1:
            break

    modulus = n * n
    message_part = pow(g, message, modulus)
    random_part = pow(r, n, modulus)
    ciphertext = message_part * random_part % modulus
    return ciphertext



# ---------- DECRYPT ONE CIPHERTEXT ----------
# First calculate u=c^lambda mod n^2; L(u)=(u-1)//n; then m=L(u)*mu mod n.
# Range checks catch malformed inputs, but Paillier does NOT authenticate data.
def decrypt(public_key, private_key, ciphertext):
    n, g = public_key
    lam, mu = private_key

    if not 0 < ciphertext < n * n or gcd(ciphertext, n) != 1:
        raise ValueError("Ciphertext must be an invertible value modulo n^2.")

    u = pow(ciphertext, lam, n * n)
    l_value = (u - 1) // n
    return l_value * mu % n



# ---------- ADD WITHOUT DECRYPTING ----------
# Multiplying Paillier ciphertexts corresponds to ADDING plaintext integers.
# HINT: this intentional malleability is why a separate integrity check is needed.
def homomorphic_add(public_key, ciphertext_a, ciphertext_b):
    n, g = public_key
    return ciphertext_a * ciphertext_b % (n * n)


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



# ---------- ENCRYPT DOC IDs IN THE POSTING LISTS ----------
# Paillier randomness is correct: ID ciphertexts are decrypted, NOT compared
# against fresh encryptions. Stable HMAC tokens supply the word lookup instead.
def build_encrypted_index(documents, public_key, search_key):
    index = {}

    for document_id, text in documents.items():
        for word in set(words(text)):
            token = create_search_token(word, search_key)

            if token not in index:
                index[token] = []

            index[token].append(encrypt(public_key, document_id))

    return index



# ---------- SEARCH AND RETURN DECRYPTED IDs ----------
# Only an authorized key holder can decrypt the matching encrypted IDs.
def search_documents(query, index, public_key, private_key, search_key):
    token = query_token(query, search_key)
    document_ids = []

    for ciphertext in index.get(token, []):
        document_ids.append(decrypt(public_key, private_key, ciphertext))

    return sorted(document_ids)



# ---------- DATASET AND QUERY ----------
# CHANGE query/corpus to adapt the example. Do not change keys between indexing
# and searching. Paillier is malleable: valid changed ciphertexts can silently
# change IDs. It has NO AES-GCM-style tag to detect arbitrary tampering.
def main():
    sample_documents = {
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
    documents = {}

    for label, text in sample_documents.items():
        documents[int(label[3:])] = text

    bits = input('Educational Paillier key bits [1024]: ')

    if bits == "":
        bits = '1024'

    bits = int(bits)
    query = input('Search word [python]: ')

    if query == "":
        query = 'python'

    public_key, private_key = generate_keys(bits)
    search_key = get_random_bytes(32)
    index = build_encrypted_index(documents, public_key, search_key)
    results = search_documents(query, index, public_key, private_key, search_key)

    print("Query:", query)
    print("Matching IDs:", results)

    for document_id in results:
        print(document_id, documents[document_id])

    print("Hybrid HMAC lookup + encrypted IDs; not a complete PKSE construction.")



if __name__ == "__main__":
    main()
