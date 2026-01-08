"""
Password vault storage backend.
"""

import json
import os
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path
from .crypto import CryptoManager


class PasswordEntry:
    """Represents a single password entry."""

    def __init__(self, title: str, username: str, password: str,
                 url: str = "", notes: str = "", category: str = "General"):
        self.id = datetime.now().timestamp()
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.category = category
        self.created = datetime.now().isoformat()
        self.modified = datetime.now().isoformat()

    def to_dict(self) -> dict:
        """Convert entry to dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'username': self.username,
            'password': self.password,
            'url': self.url,
            'notes': self.notes,
            'category': self.category,
            'created': self.created,
            'modified': self.modified
        }

    @staticmethod
    def from_dict(data: dict) -> 'PasswordEntry':
        """Create entry from dictionary."""
        entry = PasswordEntry(
            title=data['title'],
            username=data['username'],
            password=data['password'],
            url=data.get('url', ''),
            notes=data.get('notes', ''),
            category=data.get('category', 'General')
        )
        entry.id = data['id']
        entry.created = data['created']
        entry.modified = data.get('modified', data['created'])
        return entry

    def update(self, **kwargs):
        """Update entry fields."""
        for key, value in kwargs.items():
            if hasattr(self, key) and key not in ['id', 'created']:
                setattr(self, key, value)
        self.modified = datetime.now().isoformat()


class PasswordVault:
    """Manages password storage and retrieval."""

    def __init__(self, vault_path: str = None):
        if vault_path is None:
            vault_path = os.path.join(Path.home(), '.password_manager', 'vault.enc')

        self.vault_path = vault_path
        self.crypto = CryptoManager()
        self.entries: List[PasswordEntry] = []
        self.master_password_hash = None
        self.salt = None
        self.is_locked = True

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.vault_path), exist_ok=True)

    def create_vault(self, master_password: str):
        """Create a new vault with a master password."""
        if os.path.exists(self.vault_path):
            raise FileExistsError("Vault already exists")

        self.master_password_hash = self.crypto.hash_master_password(master_password)
        self.salt = os.urandom(self.crypto.SALT_SIZE)
        self.entries = []
        self.is_locked = False
        self._master_password = master_password
        self._save_vault(master_password)

    def unlock_vault(self, master_password: str) -> bool:
        """Unlock vault with master password."""
        if not os.path.exists(self.vault_path):
            raise FileNotFoundError("Vault does not exist")

        try:
            with open(self.vault_path, 'r') as f:
                encrypted_data = json.load(f)

            # Verify master password
            if not self.crypto.verify_master_password(master_password, encrypted_data['master_hash']):
                return False

            # Decrypt vault
            vault_data = self.crypto.decrypt_vault(encrypted_data, master_password)

            self.master_password_hash = encrypted_data['master_hash']
            self.entries = [PasswordEntry.from_dict(e) for e in vault_data['entries']]
            self.is_locked = False
            self._master_password = master_password
            return True

        except Exception as e:
            print(f"Error unlocking vault: {e}")
            return False

    def lock_vault(self):
        """Lock the vault."""
        self.is_locked = True
        self.entries = []
        if hasattr(self, '_master_password'):
            del self._master_password

    def _save_vault(self, master_password: str):
        """Save vault to disk."""
        if self.is_locked:
            raise PermissionError("Vault is locked")

        vault_data = {
            'entries': [e.to_dict() for e in self.entries],
            'metadata': {
                'version': '1.0',
                'entry_count': len(self.entries),
                'last_modified': datetime.now().isoformat()
            }
        }

        encrypted_data = self.crypto.encrypt_vault(vault_data, master_password)
        encrypted_data['master_hash'] = self.master_password_hash

        with open(self.vault_path, 'w') as f:
            json.dump(encrypted_data, f, indent=2)

    def add_entry(self, entry: PasswordEntry):
        """Add a new password entry."""
        if self.is_locked:
            raise PermissionError("Vault is locked")

        self.entries.append(entry)
        self._save_vault(self._master_password)

    def update_entry(self, entry_id: float, **kwargs):
        """Update an existing entry."""
        if self.is_locked:
            raise PermissionError("Vault is locked")

        for entry in self.entries:
            if entry.id == entry_id:
                entry.update(**kwargs)
                self._save_vault(self._master_password)
                return True
        return False

    def delete_entry(self, entry_id: float) -> bool:
        """Delete an entry."""
        if self.is_locked:
            raise PermissionError("Vault is locked")

        for i, entry in enumerate(self.entries):
            if entry.id == entry_id:
                self.entries.pop(i)
                self._save_vault(self._master_password)
                return True
        return False

    def get_entry(self, entry_id: float) -> Optional[PasswordEntry]:
        """Get a specific entry by ID."""
        if self.is_locked:
            raise PermissionError("Vault is locked")

        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        return None

    def search_entries(self, query: str) -> List[PasswordEntry]:
        """Search entries by title, username, or URL."""
        if self.is_locked:
            raise PermissionError("Vault is locked")

        query = query.lower()
        results = []

        for entry in self.entries:
            if (query in entry.title.lower() or
                query in entry.username.lower() or
                query in entry.url.lower() or
                query in entry.category.lower()):
                results.append(entry)

        return results

    def get_all_entries(self) -> List[PasswordEntry]:
        """Get all entries."""
        if self.is_locked:
            raise PermissionError("Vault is locked")

        return self.entries.copy()

    def get_categories(self) -> List[str]:
        """Get all unique categories."""
        if self.is_locked:
            raise PermissionError("Vault is locked")

        return sorted(list(set(entry.category for entry in self.entries)))

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """Change the master password."""
        if self.is_locked:
            raise PermissionError("Vault is locked")

        if not self.crypto.verify_master_password(old_password, self.master_password_hash):
            return False

        self.master_password_hash = self.crypto.hash_master_password(new_password)
        self._master_password = new_password
        self._save_vault(new_password)
        return True

    def export_to_json(self, output_path: str, include_passwords: bool = True):
        """Export vault to unencrypted JSON."""
        if self.is_locked:
            raise PermissionError("Vault is locked")

        export_data = []
        for entry in self.entries:
            entry_data = entry.to_dict()
            if not include_passwords:
                entry_data['password'] = '***REDACTED***'
            export_data.append(entry_data)

        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)

    def import_from_json(self, input_path: str):
        """Import entries from JSON file."""
        if self.is_locked:
            raise PermissionError("Vault is locked")

        with open(input_path, 'r') as f:
            import_data = json.load(f)

        for entry_data in import_data:
            entry = PasswordEntry.from_dict(entry_data)
            self.entries.append(entry)

        self._save_vault(self._master_password)
