"""Lab 6 socket signature demo, step 1: generate the signer's key files."""

from pathlib import Path
from Crypto.PublicKey import RSA



# ---------- SAVE KEYS ONCE ----------
# The client gets the PRIVATE file. The server needs only the PUBLIC file.
# Exclusive creation refuses to overwrite existing keys accidentally.
def generate_key_files(private_path, public_path, bits=2048):
    private_path = Path(private_path)
    public_path = Path(public_path)

    if private_path.resolve() == public_path.resolve():
        raise ValueError("Private and public key paths must differ.")

    if private_path.exists() or public_path.exists():
        raise FileExistsError("A key file already exists; choose new paths or reuse it.")

    key = RSA.generate(bits)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    with private_path.open("xb") as file:
        file.write(key.export_key())

    with public_path.open("xb") as file:
        file.write(key.publickey().export_key())

    return private_path, public_path



# ---------- LOCAL OUTPUT PATHS ----------
# These generated keys stay in ignored output/; do not push private keys.
def main():
    folder = Path(__file__).resolve().parent / "output"
    private_path = input('New private key path [Enter=output/private.pem]: ')

    if private_path == "":
        private_path = str(folder / 'private.pem')

    public_path = input('New public key path [Enter=output/public.pem]: ')

    if public_path == "":
        public_path = str(folder / 'public.pem')

    bits = input('RSA bits [2048]: ')

    if bits == "":
        bits = '2048'

    bits = int(bits)

    private_file, public_file = generate_key_files(private_path, public_path, bits)
    print("Private key:", private_file)
    print("Public key:", public_file)
    print("Next: run q4-server.py, then q4-client.py.")



if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print("Error:", error)
