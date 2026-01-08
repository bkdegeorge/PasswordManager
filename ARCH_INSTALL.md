# Arch Linux Installation Guide

## Quick Install

Run these commands to install the missing dependency:

```bash
cd password-manager

# Install the missing argon2-cffi package
sudo pacman -S python-argon2-cffi

# Verify installation
python3 check_installation.py

# Run the application
python3 password_manager.py
```

## Already Installed

You already have:
- ✓ python-cryptography
- ✓ python-pyperclip
- ✓ tkinter (built into Python)

You only need:
- ✗ python-argon2-cffi

## Manual Installation

If you don't have sudo access, you can use a virtual environment:

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install dependencies
pip install argon2-cffi

# Run the application
python3 password_manager.py
```

## Alternative: Run Without Argon2 (Less Secure)

If you can't install argon2-cffi, you can use the fallback version:

```bash
python3 password_manager_simple.py
```

This uses SHA-256 instead of Argon2 for password hashing. It's less secure against brute-force attacks but will work without dependencies.

## Troubleshooting

### "No module named 'argon2'"

```bash
sudo pacman -S python-argon2-cffi
```

### "sudo: a password is required"

You need to enter your user password to install system packages.

### "No module named 'pip'"

On Arch, use pacman instead of pip for system-wide packages:
```bash
sudo pacman -S python-argon2-cffi
```

Or use a virtual environment (no sudo needed):
```bash
python3 -m venv venv
source venv/bin/activate
pip install argon2-cffi
```
