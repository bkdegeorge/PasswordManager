"""
Encryption module for password manager.
Uses AES-256-GCM for encryption and Argon2id for key derivation.
Falls back to PBKDF2-SHA256 if argon2 is not available.
"""

import os
import json
import base64
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Try to import argon2, fall back to PBKDF2 if not available
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False
    print("\n" + "="*70)
    print("WARNING: argon2-cffi not found!")
    print("Using PBKDF2-SHA256 for password hashing (less secure).")
    print("\nFor better security, install argon2:")
    print("  sudo pacman -S python-argon2-cffi")
    print("="*70 + "\n")


class CryptoManager:
    """Handles all encryption/decryption operations."""

    SALT_SIZE = 32
    NONCE_SIZE = 12
    KEY_SIZE = 32  # 256 bits for AES-256

    def __init__(self):
        if HAS_ARGON2:
            self.ph = PasswordHasher(
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                salt_len=16
            )
        else:
            self.ph = None

    def derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=600000,
        )
        return kdf.derive(master_password.encode())

    def hash_master_password(self, password: str) -> str:
        """Hash master password for verification."""
        if HAS_ARGON2:
            # Use Argon2id (preferred - memory-hard)
            return self.ph.hash(password)
        else:
            # Fallback to PBKDF2-SHA256 with high iteration count
            salt = os.urandom(16)
            hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
            # Store salt and hash together with a prefix to identify the method
            return 'pbkdf2$' + base64.b64encode(salt + hash_obj).decode()

    def verify_master_password(self, password: str, hash_value: str) -> bool:
        """Verify master password against stored hash."""
        if HAS_ARGON2 and not hash_value.startswith('pbkdf2$'):
            # Use Argon2 verification
            try:
                self.ph.verify(hash_value, password)
                return True
            except VerifyMismatchError:
                return False
        else:
            # Use PBKDF2 verification (fallback mode)
            try:
                # Remove prefix if present
                if hash_value.startswith('pbkdf2$'):
                    hash_value = hash_value[7:]

                decoded = base64.b64decode(hash_value)
                salt = decoded[:16]
                stored_hash = decoded[16:]

                # Recompute hash with same salt
                computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)

                # Constant-time comparison to prevent timing attacks
                return self._constant_time_compare(computed_hash, stored_hash)
            except Exception:
                return False

    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    def encrypt_data(self, data: str, master_password: str, salt: bytes = None) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        Returns: (encrypted_data, salt, nonce)
        """
        if salt is None:
            salt = os.urandom(self.SALT_SIZE)

        key = self.derive_key(master_password, salt)
        nonce = os.urandom(self.NONCE_SIZE)

        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(nonce, data.encode(), None)

        return encrypted, salt, nonce

    def decrypt_data(self, encrypted_data: bytes, master_password: str, salt: bytes, nonce: bytes) -> str:
        """
        Decrypt data using AES-256-GCM.
        Returns: decrypted string
        """
        key = self.derive_key(master_password, salt)
        aesgcm = AESGCM(key)

        try:
            decrypted = aesgcm.decrypt(nonce, encrypted_data, None)
            return decrypted.decode()
        except Exception as e:
            raise ValueError("Decryption failed. Incorrect password or corrupted data.") from e

    def encrypt_vault(self, vault_data: dict, master_password: str, salt: bytes = None) -> dict:
        """Encrypt entire vault data structure."""
        json_data = json.dumps(vault_data, indent=2)
        encrypted, salt, nonce = self.encrypt_data(json_data, master_password, salt)

        return {
            'encrypted_data': base64.b64encode(encrypted).decode(),
            'salt': base64.b64encode(salt).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'version': '1.0'
        }

    def decrypt_vault(self, encrypted_vault: dict, master_password: str) -> dict:
        """Decrypt entire vault data structure."""
        encrypted_data = base64.b64decode(encrypted_vault['encrypted_data'])
        salt = base64.b64decode(encrypted_vault['salt'])
        nonce = base64.b64decode(encrypted_vault['nonce'])

        json_data = self.decrypt_data(encrypted_data, master_password, salt, nonce)
        return json.loads(json_data)
