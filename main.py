import os
import sys
import hmac
from database import VaultDB
import crypto_utils

def initialize_vault(db: VaultDB):
    """Executes initial creation setup for fresh system instances."""
    print("--- Initialize Your Secure Vault ---")
    # CHANGED: Replaced getpass with visible input()
    mp = input("Create Master Password (VISIBLE): ").strip()
    mp_confirm = input("Confirm Master Password (VISIBLE): ").strip()

    if not mp:
        print("[!] Password cannot be blank.")
        sys.exit(1)

    if mp != mp_confirm:
        print("[!] Passwords do not match. Execution halted.")
        sys.exit(1)

    # 1. Generate unique system initialization salts
    salt = os.urandom(16)
    
    # 2. Derive primary key
    derived_key = crypto_utils.derive_key(mp, salt)
    
    # 3. Create a verification signature to validate future log-ins safely
    nonce, verification_hash = crypto_utils.encrypt_data("vault_access_granted", derived_key)
    
    # Save parameters to DB
    db.save_auth_record(salt, nonce + verification_hash)
    print("[+] Vault initialized securely.\n")

def authenticate(db: VaultDB) -> bytes:
    """Validates user authorization credentials."""
    record = db.get_auth_record()
    if not record:
        initialize_vault(db)
        record = db.get_auth_record()

    salt, stored_blob = record
    stored_nonce = stored_blob[:12]
    stored_ciphertext = stored_blob[12:]

    print("--- Unlock Vault ---")
    # CHANGED: Replaced getpass with visible input()
    mp = input("Enter Master Password: ").strip()
    
    # Derive key from input
    derived_key = crypto_utils.derive_key(mp, salt)

    try:
        # Attempt to decrypt authentication token string
        decrypted_check = crypto_utils.decrypt_data(stored_ciphertext, stored_nonce, derived_key)
        # Use timing-attack safe comparison verification
        if hmac.compare_digest(decrypted_check, "vault_access_granted"):
            print("[+] Access Granted.\n")
            return derived_key
    except Exception:
        pass
    
    print("[!] Access Denied: Invalid Master Password.")
    sys.exit(1)

def main():
    db = VaultDB()
    # Lock loop inside secure authorization routine
    master_key = authenticate(db)

    try:
        while True:
            print("1. Store Credential\n2. Retrieve Credential\n3. Exit")
            choice = input("Select an option: ").strip()

            if choice == "1":
                service = input("Enter Service Name (e.g. Github): ")
                username = input("Enter Username/Email: ")
                # CHANGED: Replaced getpass with visible input()
                password = input("Enter Password to Encrypt: ").strip()

                nonce, ciphertext = crypto_utils.encrypt_data(password, master_key)
                db.add_credential(service, username, nonce, ciphertext)
                print(f"[+] Credential stored securely for {service}!\n")

            elif choice == "2":
                service = input("Enter Service Name to lookup: ")
                record = db.get_credential(service)

                if record:
                    username, nonce, ciphertext = record
                    try:
                        decrypted_password = crypto_utils.decrypt_data(ciphertext, nonce, master_key)
                        print(f"\n--- Account Data [{service}] ---")
                        print(f"Username: {username}")
                        print(f"Password: {decrypted_password}\n")
                    except Exception:
                        print("[!] Decryption sequence error occurred.\n")
                else:
                    print("[!] No record discovered matching that service name.\n")

            elif choice == "3":
                print("Vault closed securely.")
                break
            else:
                print("Invalid selection.\n")
    finally:
        db.close()
