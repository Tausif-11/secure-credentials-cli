import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import low_level
import config

def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Uses Argon2id to derive a secure 256-bit encryption key 
    from a user-supplied string password and a cryptographic salt.
    """
    return low_level.hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=config.ARGON2_TIME,
        memory_cost=config.ARGON2_MEMORY,
        parallelism=config.ARGON2_PARALLELISM,
        hash_len=config.KEY_LEN,
        type=low_level.Type.ID
    )

def encrypt_data(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts data using AES-256-GCM.
    Returns a tuple containing: (12-byte Nonce, Encrypted Ciphertext)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Generates a cryptographically secure random nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return nonce, ciphertext

def decrypt_data(ciphertext: bytes, nonce: bytes, key: bytes) -> str:
    """
    Decrypts AES-256-GCM ciphertext. 
    Will throw a cryptography.exceptions.InvalidTag error if the file 
    has been edited, corrupted, or tampered with by an attacker.
    """
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext_bytes.decode()