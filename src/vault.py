
import argparse
import getpass
import hashlib
import logging
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Cryptographic format constants
MAGIC = b"CEV1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

# Scrypt parameters
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

logging.basicConfig(
    filename="logs/vault.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


def derive_key(password, salt):
    """Derive a 256-bit encryption key using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(source, destination, password):
    """Encrypt one file using AES-256-GCM."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)
    aes = AESGCM(key)

    plaintext = source.read_bytes()
    ciphertext = aes.encrypt(nonce, plaintext, MAGIC)

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(MAGIC + salt + nonce + ciphertext)

    digest = hashlib.sha256(plaintext).hexdigest()

    logging.info("Encrypted: %s | SHA256: %s", source.name, digest)

    return digest


def decrypt_file(source, destination, password):
    """Decrypt and authenticate one encrypted file."""
    data = source.read_bytes()

    header_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE

    if len(data) < header_size + 16:
        raise ValueError("Invalid or incomplete encrypted file.")

    if data[:len(MAGIC)] != MAGIC:
        raise ValueError("Unrecognized encrypted file format.")

    salt_start = len(MAGIC)
    nonce_start = salt_start + SALT_SIZE
    ciphertext_start = nonce_start + NONCE_SIZE

    salt = data[salt_start:nonce_start]
    nonce = data[nonce_start:ciphertext_start]
    ciphertext = data[ciphertext_start:]

    key = derive_key(password, salt)
    aes = AESGCM(key)

    # Authentication fails if the password or data is incorrect.
    plaintext = aes.decrypt(nonce, ciphertext, MAGIC)

    destination.parent.mkdir(parents=True, exist_ok=True)

    # Exclusive creation prevents accidental overwriting.
    with destination.open("xb") as file:
        file.write(plaintext)

    digest = hashlib.sha256(plaintext).hexdigest()

    logging.info("Decrypted: %s | SHA256: %s", source.name, digest)

    return digest


def validate_directories(source, destination):
    """Validate directory locations before processing."""
    source = source.resolve()
    destination = destination.resolve()

    if not source.is_dir():
        raise ValueError("Source directory does not exist.")

    if source == destination or source in destination.parents:
        raise ValueError("Destination cannot be inside the source directory.")

    if destination == source or destination in source.parents:
        raise ValueError("Source and destination must not overlap.")

    return source, destination


def encrypt_directory(source, destination, password):
    """Recursively encrypt all files while preserving directories."""
    source, destination = validate_directories(source, destination)

    files = sorted(path for path in source.rglob("*") if path.is_file())

    if not files:
        print("No files found in source directory.")
        return

    success = 0
    failed = 0

    for file in files:
        relative_path = file.relative_to(source)

        output_file = destination / relative_path
        output_file = output_file.with_name(output_file.name + ".enc")

        if output_file.exists():
            print(f"[SKIPPED] Already exists: {relative_path}")
            failed += 1
            continue

        try:
            encrypt_file(file, output_file, password)
            print(f"[ENCRYPTED] {relative_path}")
            success += 1
        except (OSError, ValueError) as error:
            print(f"[ERROR] {relative_path}: {error}")
            logging.error("Encryption failed: %s | %s", relative_path, error)
            failed += 1

    print(f"\nEncryption complete: {success} successful, {failed} failed.")


def decrypt_directory(source, destination, password):
    """Recursively decrypt .enc files and preserve directories."""
    source, destination = validate_directories(source, destination)

    files = sorted(
        path for path in source.rglob("*")
        if path.is_file() and path.name.endswith(".enc")
    )

    if not files:
        print("No encrypted .enc files found.")
        return

    success = 0
    failed = 0

    for file in files:
        relative_path = file.relative_to(source)

        output_file = destination / relative_path.parent / relative_path.name[:-4]

        if output_file.exists():
            print(f"[SKIPPED] Output already exists: {relative_path}")
            failed += 1
            continue

        try:
            decrypt_file(file, output_file, password)
            print(f"[DECRYPTED] {relative_path}")
            success += 1

        except InvalidTag:
            print(f"[FAILED] Authentication failed: {relative_path}")
            logging.warning("Authentication failed: %s", relative_path)
            failed += 1

        except (OSError, ValueError) as error:
            print(f"[ERROR] {relative_path}: {error}")
            logging.error("Decryption failed: %s | %s", relative_path, error)
            failed += 1

    print(f"\nDecryption complete: {success} successful, {failed} failed.")


def main():
    parser = argparse.ArgumentParser(
        description="Cryptographic Encryption Vault - AES-256-GCM"
    )

    parser.add_argument(
        "operation",
        choices=["encrypt", "decrypt"],
        help="Encryption or decryption operation"
    )

    parser.add_argument("source", help="Source directory")
    parser.add_argument("destination", help="Destination directory")

    args = parser.parse_args()

    password = getpass.getpass("Enter master passphrase: ")

    if not password:
        print("Passphrase cannot be empty.")
        return

    if args.operation == "encrypt":
        confirmation = getpass.getpass("Confirm master passphrase: ")

        if password != confirmation:
            print("Passphrases do not match.")
            return

        encrypt_directory(
            Path(args.source),
            Path(args.destination),
            password
        )

    else:
        decrypt_directory(
            Path(args.source),
            Path(args.destination),
            password
        )


if __name__ == "__main__":
    main()

