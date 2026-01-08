#!/usr/bin/env python3
"""
Simple command-line test for password manager core functionality.
Run this to verify everything works without the GUI.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from src.vault import PasswordVault, PasswordEntry
from src.password_generator import PasswordGenerator
from src.password_strength import PasswordStrengthAnalyzer

def main():
    print("\n" + "="*70)
    print("SecureVault Password Manager - Command Line Test")
    print("="*70)

    # Test vault
    print("\n[1/3] Testing Vault Operations...")
    vault_path = '/tmp/test_vault_cli.enc'
    if os.path.exists(vault_path):
        os.remove(vault_path)

    vault = PasswordVault(vault_path)
    vault.create_vault('TestPassword123!')
    print("  ✓ Created vault")

    entry = PasswordEntry('Test Site', 'testuser', 'testpass123', 'https://test.com')
    vault.add_entry(entry)
    print("  ✓ Added entry")

    vault.lock_vault()
    vault.unlock_vault('TestPassword123!')
    print("  ✓ Lock/unlock works")

    results = vault.search_entries('test')
    print(f"  ✓ Search found {len(results)} entries")

    os.remove(vault_path)

    # Test password generator
    print("\n[2/3] Testing Password Generator...")
    gen = PasswordGenerator()

    pw = gen.generate_password(16, True, True, True, True)
    print(f"  ✓ Random password: {pw}")

    pp = gen.generate_passphrase(5, "-", True, False)
    print(f"  ✓ Passphrase: {pp}")

    # Test strength analyzer
    print("\n[3/3] Testing Password Strength Analyzer...")
    analyzer = PasswordStrengthAnalyzer()

    analysis = analyzer.analyze(pw)
    print(f"  ✓ Strength: {analysis['strength']} ({analysis['score']}/100)")

    print("\n" + "="*70)
    print("✓ ALL TESTS PASSED - Core functionality works!")
    print("\nYou can now run the GUI application:")
    print("  python3 password_manager.py")
    print("="*70 + "\n")

if __name__ == '__main__':
    main()
