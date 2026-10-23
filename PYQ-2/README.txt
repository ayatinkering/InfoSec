UNIVERSAL IS LAB — TWO SEPARATE MOCK PROJECTS
==============================================
Both projects include the EXACT SAME crypto_helpers.py from the previously
provided UNIVERSAL_IS_LAB_TOOLBOX, with identical SHA-256 checksum.

FILES:
  file.txt          - input; one record per line
  client.py         - separate client program, beginner step-by-step comments
  server.py         - separate server program, beginner step-by-step comments
  crypto_helpers.py - universal Labs 1-8 functions (unchanged)
  CHANGE_MAP.txt    - what to modify for other blended exam questions
  requirements.txt  - dependency

RUN:
  python -m pip install -r requirements.txt
  Terminal 1: python server.py
  Terminal 2: python client.py
  Client menu: 1 (read), 2 (setup), 4 (submit all), 5 (search), 6 (tally)
  Note: submit all only once per server session; repeated IDs are rejected.

EXPECTED INPUT TOTALS:
  BANK: 5000+3000+7000+2000+4000 = 21000
  VOTE: candidates 1,2,3 counts = [2,2,1]

CRITICAL WARNINGS:
  These are classroom demos. No registered signer authentication, no real
  timestamp authority, no secure client role authentication, no threshold
  Paillier decryption, no zero-knowledge ciphertext consistency proofs.
  E-voting server decrypts ballot plaintext, so real ballot secrecy is absent.
  Cipher and signature swaps must be made on BOTH client and server.

TESTING:
  Python syntax checks pass. End-to-end crypto execution not verified here:
  PyCryptodome is not installed in the current environment.

SCENARIO: BANKING_MOCK
