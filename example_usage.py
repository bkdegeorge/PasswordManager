#!/usr/bin/env python3
"""
Example usage of password manager components.
This demonstrates the API without requiring the GUI.

NOTE: Install dependencies first:
    pip install cryptography pyperclip argon2-cffi
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(__file__))

from src.password_generator import PasswordGenerator
from src.password_strength import PasswordStrengthAnalyzer
from src.vault import PasswordVault, PasswordEntry


def demo_password_generation():
    """Demonstrate password generation capabilities."""
    print("\n" + "="*60)
    print("PASSWORD GENERATION DEMO")
    print("="*60)

    generator = PasswordGenerator()

    # Generate random password
    print("\n1. Random Password (16 chars, all types):")
    password = generator.generate_password(16, True, True, True, True)
    print(f"   {password}")

    # Generate passphrase
    print("\n2. Memorable Passphrase (6 words):")
    passphrase = generator.generate_passphrase(6, "-", True, True)
    print(f"   {passphrase}")

    # Generate PIN
    print("\n3. Numeric PIN (6 digits):")
    pin = generator.generate_pin(6)
    print(f"   {pin}")

    return password


def demo_password_strength(password):
    """Demonstrate password strength analysis."""
    print("\n" + "="*60)
    print("PASSWORD STRENGTH ANALYSIS")
    print("="*60)

    analyzer = PasswordStrengthAnalyzer()

    # Analyze the password
    analysis = analyzer.analyze(password)

    print(f"\nAnalyzing: {password}")
    print(f"\nStrength: {analysis['strength']} ({analysis['score']}/100)")
    print(f"Entropy: {analysis['entropy']} bits")
    print(f"Length: {analysis['length']} characters")
    print(f"\nCharacter types:")
    print(f"  - Lowercase: {'✓' if analysis['has_lowercase'] else '✗'}")
    print(f"  - Uppercase: {'✓' if analysis['has_uppercase'] else '✗'}")
    print(f"  - Digits: {'✓' if analysis['has_digits'] else '✗'}")
    print(f"  - Symbols: {'✓' if analysis['has_symbols'] else '✗'}")
    print(f"\nFeedback:")
    for feedback in analysis['feedback']:
        print(f"  • {feedback}")

    # Time to crack
    time_to_crack = analyzer.time_to_crack(password)
    print(f"\nEstimated time to crack: {time_to_crack}")


def demo_vault_operations():
    """Demonstrate vault operations."""
    print("\n" + "="*60)
    print("VAULT OPERATIONS DEMO")
    print("="*60)

    # Use a temporary vault for demo
    vault_path = "/tmp/demo_vault.enc"

    # Clean up if exists
    if os.path.exists(vault_path):
        os.remove(vault_path)

    vault = PasswordVault(vault_path)

    # Create vault
    print("\n1. Creating vault with master password...")
    master_password = "DemoPassword123!@#"
    vault.create_vault(master_password)
    print("   ✓ Vault created")

    # Add entries
    print("\n2. Adding password entries...")

    entry1 = PasswordEntry(
        title="Gmail",
        username="user@gmail.com",
        password="SuperSecure123!",
        url="https://gmail.com",
        category="Email",
        notes="Primary email account"
    )
    vault.add_entry(entry1)
    print("   ✓ Added Gmail entry")

    entry2 = PasswordEntry(
        title="GitHub",
        username="devuser",
        password="GitHubPassword456!",
        url="https://github.com",
        category="Work",
        notes="Development account"
    )
    vault.add_entry(entry2)
    print("   ✓ Added GitHub entry")

    entry3 = PasswordEntry(
        title="Bank Account",
        username="john.doe",
        password="BankSecure789!",
        url="https://mybank.com",
        category="Finance",
        notes="Online banking"
    )
    vault.add_entry(entry3)
    print("   ✓ Added Bank entry")

    # List all entries
    print("\n3. Listing all entries:")
    all_entries = vault.get_all_entries()
    for entry in all_entries:
        print(f"   • {entry.title} ({entry.category})")
        print(f"     Username: {entry.username}")
        print(f"     URL: {entry.url}")

    # Search entries
    print("\n4. Searching for 'git':")
    results = vault.search_entries("git")
    for entry in results:
        print(f"   • Found: {entry.title}")

    # Get categories
    print("\n5. Available categories:")
    categories = vault.get_categories()
    for category in categories:
        print(f"   • {category}")

    # Update entry
    print("\n6. Updating GitHub password...")
    github_entry = results[0]
    vault.update_entry(github_entry.id, password="NewGitHubPassword999!")
    print("   ✓ Password updated")

    # Lock and unlock
    print("\n7. Locking vault...")
    vault.lock_vault()
    print("   ✓ Vault locked")

    print("\n8. Unlocking vault...")
    success = vault.unlock_vault(master_password)
    if success:
        print("   ✓ Vault unlocked")
    else:
        print("   ✗ Failed to unlock")

    # Export
    print("\n9. Exporting vault...")
    export_path = "/tmp/vault_export.json"
    vault.export_to_json(export_path, include_passwords=True)
    print(f"   ✓ Exported to {export_path}")

    # Clean up
    print("\n10. Cleaning up demo files...")
    os.remove(vault_path)
    os.remove(export_path)
    print("   ✓ Demo files removed")


def main():
    """Run all demos."""
    print("\n" + "="*60)
    print("SECUREVAULT PASSWORD MANAGER - DEMO")
    print("="*60)
    print("\nThis demo shows the core functionality without the GUI.")
    print("Make sure dependencies are installed:")
    print("  pip install cryptography pyperclip argon2-cffi")

    try:
        # Test if dependencies are available
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from argon2 import PasswordHasher

        # Run demos
        password = demo_password_generation()
        demo_password_strength(password)
        demo_vault_operations()

        print("\n" + "="*60)
        print("DEMO COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("\nTo use the GUI application, run:")
        print("  python password_manager.py")
        print("\n")

    except ImportError as e:
        print(f"\n✗ Missing dependency: {e}")
        print("\nPlease install dependencies first:")
        print("  pip install -r requirements.txt")
        sys.exit(1)


if __name__ == '__main__':
    main()
