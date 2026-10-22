# InfoSec

Information Security lab programs for use in PyCharm.

Read [START_HERE.md](START_HERE.md) for the commented code layout, exact places
to change inputs or simulate tampering, and the order for running client/server
examples. The same files also work in VS Code.

- [Lab 1: all six regular exercises](lab1/README.md) — Python 3.8+, standard library only.
- [Lab 2: all five regular exercises](lab2/README.md) — Python 3.9+, PyCryptodome.
- [Lab 3: all five regular exercises](lab3/README.md) — RSA, ECC, ElGamal, file transfer, and Diffie–Hellman; Python 3.9+, PyCryptodome.
- Lab 4: `lab4/` — existing SecureCorp key management example.
- Lab 5: `lab5/` — hashing, integrity checks, sockets, and file hashes.
- Lab 6: `lab6/` — signatures, verification, DH/HMAC, and signature sockets.
- Lab 7: `lab7/` — homomorphic encryption and encrypted data sharing.
- Lab 8: `lab88/` — searchable encryption (existing folder name retained).

Run every Lab 1 exercise from this folder:

```bash
python lab1/run_all.py
```

Each question can also be run separately from its file in PyCharm.

Lab 2 needs the package listed in `requirements.txt`, installed into the same
Python interpreter selected in PyCharm. Setup steps and key corrections are
explained in the Lab 2 guide. Once installed:

```bash
python lab2/run_all.py
python lab2/verify_lab2.py
```

Lab 3 uses the same installed dependency and interpreter:

```bash
python lab3/run_all.py
python lab3/verify_lab3.py
```
