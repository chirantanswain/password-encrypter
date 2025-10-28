#!/usr/bin/env python3
"""
Password Encrypter (AES-GCM)
Author: Chirantan Swain
Creation Date: 28-Oct-2025
"""

import os
import json
import time
import base64
import secrets
import hashlib
import sys
from getpass import getpass

# cryptography imports
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Missing dependency 'cryptography'. Install it (see README).")
    sys.exit(1)

# ---------- Config ----------
MASTER_FILE = "master.json"
STORAGE_FILE = "stored_passwords.txt"
_PBKDF2_ITERATIONS = 200_000
_SALT_BYTES = 16
_AES_KEY_SIZE = 32        # 256-bit
_AES_GCM_NONCE_SIZE = 12  # 96-bit (recommended)

BANNER = r"""
██████╗  █████╗ ███████╗███████╗██╗    ██╗ █████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗╚══███╔╝██╔════╝██║    ██║██╔══██╗██╔══██╗██╔══██╗
██████╔╝███████║  ███╔╝ █████╗  ██║ █╗ ██║███████║██║  ██║██║  ██║
██╔══██╗██╔══██║ ███╔╝  ██╔══╝  ██║███╗██║██╔══██║██║  ██║██║  ██║
██║  ██║██║  ██║███████╗███████╗╚███╔███╔╝██║  ██║██████╔╝██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═════╝ ╚═════╝
                    Password Encrypter
===========================================================
    Author : Chirantan Swain
    Created: 28-Oct-2025
===========================================================
"""

# ---------------- Utility: key derivation ----------------
def derive_key(master_password: str, salt: bytes, iterations: int = _PBKDF2_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_AES_KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(master_password.encode("utf-8"))

# --------------- Master creation / verification ---------------
def create_master() -> bytes:
    print("=== Create master password ===")
    while True:
        pw1 = getpass("Enter new master password (hidden): ")
        if not pw1:
            print("Master password cannot be empty. Try again.")
            continue
        pw2 = getpass("Confirm new master password: ")
        if pw1 != pw2:
            print("Passwords do not match. Try again.\n")
            continue
        break

    salt = secrets.token_bytes(_SALT_BYTES)
    key = derive_key(pw1, salt, _PBKDF2_ITERATIONS)
    verifier = hashlib.sha256(key).hexdigest()
    record = {
        "schema": "pbkdf2-aesgcm-v1",
        "salt_hex": salt.hex(),
        "iterations": _PBKDF2_ITERATIONS,
        "verifier": verifier
    }
    with open(MASTER_FILE, "w", encoding="utf-8") as f:
        json.dump(record, f)
    try:
        os.chmod(MASTER_FILE, 0o600)
    except Exception:
        pass
    print("Master password created and saved.\n")
    return key

def verify_master() -> bytes | None:
    if not os.path.exists(MASTER_FILE):
        return create_master()

    # read and inspect record
    try:
        with open(MASTER_FILE, "r", encoding="utf-8") as f:
            rec = json.load(f)
    except Exception as e:
        print("Error reading master file:", e)
        return None

    # expected AES/PBKDF2 schema
    if rec.get("schema") != "pbkdf2-aesgcm-v1" or "salt_hex" not in rec or "verifier" not in rec:
        print("MASTER FILE SCHEMA MISMATCH.")
        print("It appears master.json was created by a different version of the program.")
        print("Options:")
        print("  1) If you want to KEEP existing encrypted data, run the matching script that created master.json.")
        print("  2) To reset and create a new master password (existing data will be inaccessible), backup and remove master.json.")
        print("\nTo backup & remove:")
        print("  cp master.json master.json.bak")
        print("  rm master.json")
        return None

    salt = bytes.fromhex(rec["salt_hex"])
    iterations = int(rec.get("iterations", _PBKDF2_ITERATIONS))
    expected_verifier = rec["verifier"]

    for attempt in range(3):
        pw = getpass("Enter master password (hidden): ")
        if not pw:
            print("Empty password entered.")
            continue
        try:
            key = derive_key(pw, salt, iterations)
        except Exception:
            print("Key derivation failed.")
            continue
        if secrets.compare_digest(hashlib.sha256(key).hexdigest(), expected_verifier):
            return key
        else:
            remaining = 2 - attempt
            if remaining > 0:
                print(f"Incorrect master password. {remaining} attempt(s) remaining.")
            else:
                print("Incorrect master password. No attempts left.")
    return None

# ---------------- AES-GCM encrypt / decrypt ----------------
def encrypt_password(plain_text: str, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(_AES_GCM_NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plain_text.encode("utf-8"), associated_data=None)
    combined = nonce + ct
    return base64.urlsafe_b64encode(combined).decode("utf-8")

def decrypt_password(encoded: str, key: bytes) -> str:
    combined = base64.urlsafe_b64decode(encoded.encode("utf-8"))
    if len(combined) < _AES_GCM_NONCE_SIZE + 16:
        raise ValueError("Encoded data is too short or malformed.")
    nonce = combined[:_AES_GCM_NONCE_SIZE]
    ct = combined[_AES_GCM_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    plain_bytes = aesgcm.decrypt(nonce, ct, associated_data=None)
    return plain_bytes.decode("utf-8")

# ---------------- Storage helpers ----------------
def append_to_storage(encoded_value: str):
    t = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(STORAGE_FILE, "a", encoding="utf-8") as f:
        f.write(f"{t}\t{encoded_value}\n")
    try:
        os.chmod(STORAGE_FILE, 0o600)
    except Exception:
        pass

# ---------------- Interactive ----------------
def interactive_encrypt(key: bytes):
    password = getpass("Enter the password to encrypt (hidden): ")
    if password == "":
        print("No password entered. Aborting.")
        return
    encoded = encrypt_password(password, key)
    append_to_storage(encoded)
    print("\n✅ Password encrypted and saved to file.")
    print("Encrypted value (base64):")
    print(encoded)

def interactive_decrypt(key: bytes):
    encoded = input("Enter the encrypted value (base64) to decrypt: ").strip()
    if not encoded:
        print("No input provided. Aborting.")
        return
    try:
        original = decrypt_password(encoded, key)
    except Exception as e:
        print("❌ Decryption failed:", e)
        return
    print("\n🔓 Decrypted (original) password:")
    print(original)

# ---------------- Main ----------------
def main():
    print(BANNER)
    key = verify_master()
    if key is None:
        print("Master authentication failed or master.json schema mismatch. Exiting.")
        return

    print("\nChoose action: 'encrypt' or 'decrypt' (type and press Enter)")
    action = input("Action (encrypt/decrypt): ").strip().lower()
    if action not in ("encrypt", "decrypt"):
        print("Unknown action. Please run again and choose 'encrypt' or 'decrypt'.")
    else:
        if action == "encrypt":
            interactive_encrypt(key)
        else:
            interactive_decrypt(key)

    # keep terminal open when launched from GUI
    try:
        input("\nProcess completed. Press Enter to exit...")
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
