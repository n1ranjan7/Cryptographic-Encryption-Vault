
import os
import json
import base64
import argparse
import getpass
import io
import zipfile
import shutil
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS = 600_000
KEY_SIZE = 32
VERSION = 1
AAD = b"CRYPTOVAULT-V1"


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(data):
    return base64.b64decode(data, validate=True)


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS
    )
    return kdf.derive(password.encode("utf-8"))


def make_archive(source):
    source = Path(source).resolve()

    if not source.is_dir():
        raise ValueError("Source must be a directory")

    buffer = io.BytesIO()
    count = 0

    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:

        for item in sorted(source.rglob("*")):
            if item.is_symlink():
                raise ValueError(
                    f"Symbolic links are not supported: {item}"
                )

            relative = item.relative_to(source).as_posix()

            if item.is_dir():
                archive.writestr(relative.rstrip("/") + "/", b"")
            elif item.is_file():
                archive.write(item, relative)
                count += 1

    return buffer.getvalue(), count


def encrypt_directory(source, vault_path, backup_path, password):
    vault_path = Path(vault_path)
    backup_path = Path(backup_path)

    if vault_path.exists() or backup_path.exists():
        raise FileExistsError("Vault or key backup already exists")

    if len(password) < 12:
        raise ValueError("Passphrase must be at least 12 characters")

    if vault_path.resolve() == backup_path.resolve():
        raise ValueError("Vault and backup must be different files")

    vault_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path.parent.mkdir(parents=True, exist_ok=True)

    archive_data, count = make_archive(source)

    # Generate a random 256-bit data encryption key.
    data_key = AESGCM.generate_key(bit_length=256)

    # Encrypt the complete directory archive.
    archive_nonce = os.urandom(12)
    encrypted_data = AESGCM(data_key).encrypt(
        archive_nonce, archive_data, AAD
    )

    # Derive a separate key from the master passphrase.
    salt = os.urandom(16)
    wrapping_key = derive_key(password, salt)
    wrap_nonce = os.urandom(12)

    # Encrypt the data encryption key for backup.
    wrapped_key = AESGCM(wrapping_key).encrypt(
        wrap_nonce, data_key, AAD
    )

    vault = {
        "version": VERSION,
        "algorithm": "AES-256-GCM",
        "archive_nonce": b64(archive_nonce),
        "ciphertext": b64(encrypted_data)
    }

    backup = {
        "version": VERSION,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": ITERATIONS,
        "salt": b64(salt),
        "wrap_nonce": b64(wrap_nonce),
        "wrapped_key": b64(wrapped_key)
    }

    created = []

    try:
        with open(vault_path, "x", encoding="utf-8") as f:
            json.dump(vault, f)
        created.append(vault_path)

        with open(backup_path, "x", encoding="utf-8") as f:
            json.dump(backup, f)
        created.append(backup_path)

    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        raise

    print(f"[SUCCESS] Encrypted {count} files")
    print(f"[VAULT] {vault_path}")
    print(f"[KEY BACKUP] {backup_path}")


def decrypt_directory(vault_path, backup_path, destination, password):
    destination = Path(destination)

    if destination.exists():
        raise FileExistsError(
            f"Destination already exists: {destination}"
        )

    with open(vault_path, "r", encoding="utf-8") as f:
        vault = json.load(f)

    with open(backup_path, "r", encoding="utf-8") as f:
        backup = json.load(f)

    if vault.get("version") != VERSION:
        raise ValueError("Unsupported vault version")

    if vault.get("algorithm") != "AES-256-GCM":
        raise ValueError("Unsupported encryption algorithm")

    if backup.get("version") != VERSION:
        raise ValueError("Unsupported backup version")

    if backup.get("kdf") != "PBKDF2-HMAC-SHA256":
        raise ValueError("Unsupported key derivation algorithm")

    if backup.get("iterations") != ITERATIONS:
        raise ValueError("Unexpected KDF configuration")

    # Recover the encryption key.
    salt = unb64(backup["salt"])
    wrap_nonce = unb64(backup["wrap_nonce"])
    wrapped_key = unb64(backup["wrapped_key"])

    wrapping_key = derive_key(password, salt)

    data_key = AESGCM(wrapping_key).decrypt(
        wrap_nonce, wrapped_key, AAD
    )

    # Authenticate and decrypt the archive.
    archive_nonce = unb64(vault["archive_nonce"])
    ciphertext = unb64(vault["ciphertext"])

    archive_data = AESGCM(data_key).decrypt(
        archive_nonce, ciphertext, AAD
    )

    # Validate archive paths before extraction.
    with zipfile.ZipFile(io.BytesIO(archive_data), "r") as archive:
        entries = archive.infolist()

        for entry in entries:
            name = PurePosixPath(entry.filename)

            if (
                name.is_absolute()
                or ".." in name.parts
                or not name.parts
                or "\\" in entry.filename
            ):
                raise ValueError("Unsafe archive path detected")

            mode = entry.external_attr >> 16

            if (mode & 0o170000) == 0o120000:
                raise ValueError("Symbolic links are not supported")

        destination.mkdir(parents=True)

        try:
            root = destination.resolve()

            for entry in entries:
                target = (destination / entry.filename).resolve()

                if not target.is_relative_to(root):
                    raise ValueError("Unsafe extraction path")

                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)

                    with archive.open(entry) as src:
                        with open(target, "xb") as dst:
                            shutil.copyfileobj(src, dst)

        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            raise

    print("[SUCCESS] Vault authenticated and restored")
    print(f"[RESTORED DIRECTORY] {destination}")


def main():
    parser = argparse.ArgumentParser(
        description="Cryptographic Directory Encryption Vault"
    )

    commands = parser.add_subparsers(
        dest="command", required=True
    )

    encrypt_parser = commands.add_parser("encrypt")
    encrypt_parser.add_argument("source")
    encrypt_parser.add_argument("vault")
    encrypt_parser.add_argument("backup")

    decrypt_parser = commands.add_parser("decrypt")
    decrypt_parser.add_argument("vault")
    decrypt_parser.add_argument("backup")
    decrypt_parser.add_argument("destination")

    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            password = getpass.getpass("Master passphrase: ")
            confirm = getpass.getpass("Confirm passphrase: ")

            if password != confirm:
                raise ValueError("Passphrases do not match")

            encrypt_directory(
                args.source,
                args.vault,
                args.backup,
                password
            )

        elif args.command == "decrypt":
            password = getpass.getpass("Master passphrase: ")

            decrypt_directory(
                args.vault,
                args.backup,
                args.destination,
                password
            )

    except Exception as error:
        print(f"[ERROR] {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
