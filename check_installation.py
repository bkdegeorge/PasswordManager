#!/usr/bin/env python3
"""
Installation checker for SecureVault Password Manager.
Run this to verify all dependencies are correctly installed.
"""

import sys
import os

def check_python_version():
    """Check Python version."""
    print("Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"  ✓ Python {version.major}.{version.minor}.{version.micro} - OK")
        return True
    else:
        print(f"  ✗ Python {version.major}.{version.minor}.{version.micro} - Need 3.8+")
        return False

def check_module(module_name, import_name=None, optional=False):
    """Check if a module is installed."""
    if import_name is None:
        import_name = module_name

    try:
        __import__(import_name)
        print(f"  ✓ {module_name} - Installed")
        return True
    except ImportError:
        if optional:
            print(f"  ⚠ {module_name} - NOT FOUND (optional, will use fallback)")
            print(f"     Recommended: sudo pacman -S python-{module_name}")
        else:
            print(f"  ✗ {module_name} - NOT FOUND (required)")
            print(f"     Install with: sudo pacman -S python-{module_name}")
        return not optional  # Return True if optional (warning only)

def check_tkinter():
    """Check if tkinter is available."""
    try:
        import tkinter
        print(f"  ✓ tkinter - Installed")
        return True
    except ImportError:
        print(f"  ✗ tkinter - NOT FOUND")
        print(f"     Install with:")
        print(f"       Ubuntu/Debian: sudo apt-get install python3-tk")
        print(f"       Fedora/RHEL: sudo dnf install python3-tkinter")
        print(f"       macOS: brew install python-tk")
        return False

def check_source_files():
    """Check if all source files exist."""
    print("\nChecking source files...")
    required_files = [
        'src/__init__.py',
        'src/crypto.py',
        'src/vault.py',
        'src/password_generator.py',
        'src/password_strength.py',
        'src/gui.py',
        'password_manager.py'
    ]

    all_found = True
    for file in required_files:
        if os.path.exists(file):
            print(f"  ✓ {file}")
        else:
            print(f"  ✗ {file} - MISSING")
            all_found = False

    return all_found

def test_import():
    """Test importing the modules."""
    print("\nTesting module imports...")
    try:
        sys.path.insert(0, os.path.dirname(__file__))
        from src import crypto, vault, password_generator, password_strength
        print("  ✓ All modules import successfully")
        return True
    except Exception as e:
        print(f"  ✗ Import failed: {e}")
        return False

def main():
    """Run all checks."""
    print("="*70)
    print("SecureVault Password Manager - Installation Check")
    print("="*70)
    print()

    critical_results = []
    warnings = []

    # Check Python version
    critical_results.append(check_python_version())
    print()

    # Check dependencies
    print("Checking dependencies...")
    critical_results.append(check_module('cryptography'))
    critical_results.append(check_module('pyperclip'))
    
    # argon2-cffi is optional now (has fallback)
    has_argon2 = check_module('argon2-cffi', 'argon2', optional=True)
    if not has_argon2:
        warnings.append("argon2-cffi not installed (using fallback)")
    
    critical_results.append(check_tkinter())
    print()

    # Check source files
    critical_results.append(check_source_files())
    print()

    # Test imports
    critical_results.append(test_import())
    print()

    # Summary
    print("="*70)
    if all(critical_results):
        print("✓ ALL CRITICAL CHECKS PASSED!")
        if warnings:
            print("\n⚠ Warnings:")
            for warning in warnings:
                print(f"  - {warning}")
            print("\nThe application will work but with reduced security.")
            print("Install argon2-cffi for best security: sudo pacman -S python-argon2-cffi")
        print()
        print("You're ready to use SecureVault!")
        print("Run: python3 password_manager.py")
        return_code = 0
    else:
        print("✗ SOME CRITICAL CHECKS FAILED")
        print()
        print("Please fix the issues above before running the application.")
        print("See INSTALL.md or ARCH_INSTALL.md for detailed instructions.")
        return_code = 1
    print("="*70)

    return return_code

if __name__ == '__main__':
    sys.exit(main())
