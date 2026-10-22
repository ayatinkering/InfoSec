"""Q5: AES-192 encryption/decryption and an actual encryption round trace.

Use encrypt/decrypt for exam composition. The educational functions below
expose key expansion and every encryption transformation for this question.
State bytes are stored column by column, following FIPS 197.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

MANUAL_KEY_HEX = "FEDCBA9876543210FEDCBA9876543210"
# Append one explicit 8-byte component to make a 24-byte demonstration key.
DEMO_KEY_HEX = MANUAL_KEY_HEX + "FEDCBA9876543210"

# Fixed AES substitution table from FIPS 197. Each input byte indexes one byte.
SBOX = bytes.fromhex("""
63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
""")



# ---------- VALIDATE KEY ----------
# Reject a key with the wrong size or invalid algorithm-specific structure.
# Message padding never fixes a key-size error.
def validate_key(key):
    if len(key) != 24:
        raise ValueError("AES-192 needs exactly 24 key bytes (48 hex digits).")



# ---------- ENCRYPT AES192 ----------
# Use the short library AES-192 implementation with a 24-byte key.
# Use this short function for exam composition; the trace helpers are for Q5 steps.
def encrypt_aes192(message, key):
    """Short library implementation for reuse in a blended exam question."""
    validate_key(key)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)

    return ciphertext



# ---------- DECRYPT AES192 ----------
# Decrypt AES-192 ECB and remove message padding using the same 24-byte key.
# The manual key needs the explicit correction explained in main().
def decrypt_aes192(ciphertext, key):
    validate_key(key)

    # Create a fresh cipher object with the mode, key, and IV/nonce needed here.
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_message, AES.block_size)

    return plaintext



# ---------- XTIME ----------
# Multiply a byte by 2 in the AES finite field, reducing with polynomial 0x11B.
# This is NOT ordinary integer multiplication modulo 256.
def xtime(value):
    """Multiply by 2 in AES's byte field, reducing with polynomial 0x11B."""
    if value & 0x80:
        return ((value << 1) ^ 0x1B) & 0xFF

    return (value << 1) & 0xFF



# ---------- EXPAND KEY ----------
# Expand six initial AES-192 words into 52 words, grouped into 13 round keys.
# Every sixth word uses RotWord, SubWord and Rcon before the XOR.
def expand_key(key, trace=False):
    """AES-192: 6 initial 4-byte words -> 52 words -> 13 round keys."""
    validate_key(key)
    words = []
    for i in range(0, 24, 4):
        words.append(list(key[i:i + 4]))

    if trace:
        print("\nKEY EXPANSION: Nk=6 words, Nr=12 rounds, 52 words total")
        for i in range(6):
            print("w[{:02}] = {} (from original key)".format(i, bytes(words[i]).hex()))

    rcon = 1
    for i in range(6, 52):
        temp = words[i - 1][:]
        if i % 6 == 0:
            temp = temp[1:] + temp[:1]  # RotWord: rotate left by one byte.
            if trace:
                print("  RotWord:", bytes(temp).hex())

            for j in range(4):
                temp[j] = SBOX[temp[j]]  # SubWord: substitute each byte.

            if trace:
                print("  SubWord:", bytes(temp).hex())
                print("  Rcon: {:02x}000000".format(rcon))

            temp[0] ^= rcon
            rcon = xtime(rcon)

        word = []
        for j in range(4):
            word.append(words[i - 6][j] ^ temp[j])

        words.append(word)
        if trace:
            print("w[{:02}] = {} XOR {} = {}".format(
                i, bytes(words[i - 6]).hex(), bytes(temp).hex(), bytes(word).hex()))

    round_keys = []
    for round_number in range(13):
        round_key = []
        for word in words[round_number * 4:round_number * 4 + 4]:
            round_key.extend(word)

        round_keys.append(round_key)

    if trace:
        print("\nROUND KEYS (each 16 bytes, even though the original key is 24 bytes)")
        for i, round_key in enumerate(round_keys):
            print("K[{:02}] = {}".format(i, bytes(round_key).hex()))

    return round_keys



# ---------- ADD ROUND KEY ----------
# XOR each state byte with its matching round-key byte.
# XOR is its own inverse, but the complete AES decryption has other inverse steps.
def add_round_key(state, round_key):
    result = []
    for i in range(16):
        result.append(state[i] ^ round_key[i])

    return result



# ---------- SUB BYTES ----------
# Look up every state byte in the fixed nonlinear AES S-box.
# This function only substitutes bytes; it does not shift or mix them.
def sub_bytes(state):
    result = []
    for value in state:
        result.append(SBOX[value])

    return result



# ---------- SHIFT ROWS ----------
# Shift state row r left by r positions, using column-major storage.
# Mixing row-major and column-major layouts is a common implementation mistake.
def shift_rows(state):
    result = [0] * 16
    for row in range(4):
        for column in range(4):
            # Each row shifts left by its row number.
            result[4 * column + row] = state[4 * ((column + row) % 4) + row]

    return result



# ---------- MIX COLUMNS ----------
# Mix each 4-byte column with AES field arithmetic to spread changes.
# The final AES round deliberately skips this function.
def mix_columns(state):
    result = []
    for i in range(0, 16, 4):
        a, b, c, d = state[i:i + 4]
        total = a ^ b ^ c ^ d
        # Equivalent to multiplication by the standard AES MixColumns matrix.
        result.append(a ^ total ^ xtime(a ^ b))
        result.append(b ^ total ^ xtime(b ^ c))
        result.append(c ^ total ^ xtime(c ^ d))
        result.append(d ^ total ^ xtime(d ^ a))

    return result



# ---------- SHOW STATE ----------
# Display the current AES state as column-major hexadecimal bytes.
def show_state(label, state):
    print("  {:<18} {}".format(label, bytes(state).hex()))



# ---------- ENCRYPT BLOCK ----------
# Encrypt exactly one block through initial, main and final AES-192 rounds.
# No padding here: the higher-level function prepares complete message blocks.
def encrypt_block(block, round_keys, trace=False):
    """Encrypt exactly one 16-byte block without padding, using expanded keys."""
    if len(block) != 16 or len(round_keys) != 13:
        raise ValueError("Need a 16-byte block and 13 AES-192 round keys.")

    state = list(block)
    if trace:
        print("Initial round")
        show_state("Input", state)

    state = add_round_key(state, round_keys[0])
    if trace:
        show_state("AddRoundKey", state)

    for round_number in range(1, 13):
        if trace:
            if round_number == 12:
                print("Round", round_number, "(final; no MixColumns)")
            else:
                print("Round", round_number)

        state = sub_bytes(state)
        if trace:
            show_state("SubBytes", state)

        state = shift_rows(state)
        if trace:
            show_state("ShiftRows", state)

        if round_number != 12:
            state = mix_columns(state)
            if trace:
                show_state("MixColumns", state)

        state = add_round_key(state, round_keys[round_number])
        if trace:
            show_state("AddRoundKey", state)

    return bytes(state)



# ---------- ENCRYPT WITH STEPS ----------
# Pad the message and display real round keys and intermediate states per block.
# The output must match the library encryption; names alone are not a round trace.
def encrypt_with_steps(message, key):
    """Trace actual encryption values, then return the complete ECB ciphertext."""
    round_keys = expand_key(key, trace=True)
    padded = pad(message, AES.block_size)
    print("\nPadded plaintext HEX:", padded.hex())
    print("States below are serialized column by column (4 bytes per column).")
    ciphertext = b""
    for i in range(0, len(padded), 16):
        print("\nBLOCK", i // 16 + 1)
        ciphertext += encrypt_block(padded[i:i + 16], round_keys, trace=True)

    return ciphertext



# ---------- INPUTS, DEMONSTRATION, AND OUTPUT ----------
# Read the scenario inputs, call the reusable functions, then display results.
# CHANGE the message/key inputs to adapt this example. Importing this file does not run main().
def main():
    print("Manual key HEX:", MANUAL_KEY_HEX)
    print("That is 16 bytes as hex, or 32 as text; neither is an AES-192 key.")
    print("Demonstration correction: append FEDCBA9876543210 -> 24 bytes.")
    message = input('Plaintext [Enter = Top Secret Data]: ')

    if message == "":
        message = 'Top Secret Data'

    key_hex = input('24-byte key HEX [Enter = ' + DEMO_KEY_HEX + ']: ')

    if key_hex == "":
        key_hex = DEMO_KEY_HEX

    key = bytes.fromhex(key_hex)
    data = message.encode("utf-8")

    # Sender step: protect the ORIGINAL input and keep the returned result.
    ciphertext = encrypt_with_steps(data, key)
    if ciphertext != encrypt_aes192(data, key):
        raise ValueError("Educational AES trace does not match PyCryptodome.")

    print("\nCiphertext HEX:", ciphertext.hex())
    print("Verified: actual round trace matches PyCryptodome AES-192.")
    print("Decrypted text:", decrypt_aes192(ciphertext, key).decode("utf-8"))




# ---------- COMPATIBILITY NAMES ----------
# Existing examples can keep their short calls; the descriptive functions above
# are the actual implementations to read or copy. No extra computation happens here.
encrypt = encrypt_aes192
decrypt = decrypt_aes192



if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        print("Error:", error)
        raise SystemExit(1)
