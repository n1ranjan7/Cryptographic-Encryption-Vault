
import tempfile
import hashlib
from pathlib import Path

from vault import encrypt_directory, decrypt_directory


def calculate_hashes(folder):
    result = {}

    for path in Path(folder).rglob("*"):
        if path.is_file():
            relative = path.relative_to(folder).as_posix()
            result[relative] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()

    return result


def run_test():
    password = "MySecureTestPassword2026!"

    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)

        source = base / "sample_data"
        source.mkdir()

        (source / "document.txt").write_text(
            "Confidential document"
        )

        nested = source / "subfolder"
        nested.mkdir()

        (nested / "notes.txt").write_text(
            "Nested directory test"
        )

        vault = base / "backup.vault"
        backup = base / "key_backup.json"
        restored = base / "restored"

        print("\n--- ENCRYPTION TEST ---")

        encrypt_directory(
            source, vault, backup, password
        )

        print("\n--- DECRYPTION TEST ---")

        decrypt_directory(
            vault, backup, restored, password
        )

        print("\n--- INTEGRITY TEST ---")

        original_hashes = calculate_hashes(source)
        restored_hashes = calculate_hashes(restored)

        print("Original files:", len(original_hashes))
        print("Restored files:", len(restored_hashes))

        if original_hashes == restored_hashes:
            print("INTEGRITY: PASS")
            print("ALL TESTS PASSED")
        else:
            print("INTEGRITY: FAIL")
            raise AssertionError("File integrity verification failed")

        print("\n--- WRONG PASSWORD TEST ---")

        try:
            decrypt_directory(
                vault,
                backup,
                base / "wrong_password_restore",
                "IncorrectPassword123!"
            )
        except Exception:
            print("WRONG PASSWORD: SUCCESSFULLY REJECTED")
        else:
            raise AssertionError("Incorrect password was accepted")


if __name__ == "__main__":
    run_test()
