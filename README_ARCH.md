# SecureVault for Arch Linux - Quick Start

## Status: ✓ WORKING

The password manager is now fully functional on your Arch Linux system!

## What's Installed

✓ Python 3.13.11
✓ python-cryptography (46.0.3-1)
✓ python-pyperclip (1.11.0-1)
✓ tkinter (built-in)
⚠ python-argon2-cffi (NOT installed - using fallback)

## Security Note

The application is currently running with **PBKDF2-SHA256** instead of Argon2id for password hashing. This is secure but not as resistant to brute-force attacks as Argon2.

**For best security**, install argon2-cffi:
```bash
sudo pacman -S python-argon2-cffi
```

## Quick Start

### 1. Run the Test

```bash
cd /home/bennett/password-manager
python3 test_cli.py
```

Expected output: All tests should pass ✓

### 2. Launch the Application

```bash
python3 password_manager.py
```

### 3. Create Your Vault

1. The GUI will open
2. Enter a strong master password (minimum 8 characters)
3. Click "Create New Vault"
4. Confirm your password

**⚠️ IMPORTANT:** Your master password cannot be recovered if forgotten!

### 4. Start Using It

- Click "Add Password" to add your first password
- Click "Generate Password" to create strong passwords
- Use the search bar to find passwords
- Click "Copy" to copy passwords (auto-clears in 30 seconds)

## Installation with Full Security (Recommended)

To get the full Argon2 security:

```bash
# Install argon2-cffi
sudo pacman -S python-argon2-cffi

# Verify installation
python3 check_installation.py

# Should now show all checks passed with no warnings
```

## Files & Locations

- **Application**: `/home/bennett/password-manager/password_manager.py`
- **Vault File**: `~/.password_manager/vault.enc` (created on first use)
- **Test Script**: `/home/bennett/password-manager/test_cli.py`
- **Install Checker**: `/home/bennett/password-manager/check_installation.py`

## Testing

### Run All Tests
```bash
python3 test_cli.py
```

### Check Installation
```bash
python3 check_installation.py
```

### Test Individual Components

**Test vault operations:**
```bash
python3 -c "
import sys; sys.path.insert(0, '/home/bennett/password-manager')
from src.vault import PasswordVault, PasswordEntry
vault = PasswordVault('/tmp/test.enc')
vault.create_vault('TestPass123')
print('✓ Vault works!')
import os; os.remove('/tmp/test.enc')
"
```

**Test password generation:**
```bash
python3 -c "
import sys; sys.path.insert(0, '/home/bennett/password-manager')
from src.password_generator import PasswordGenerator
gen = PasswordGenerator()
print('Password:', gen.generate_password(16))
print('Passphrase:', gen.generate_passphrase(5))
"
```

## Troubleshooting

### GUI Won't Start

**Error: "tkinter not found"**
```bash
# Should not happen on Arch - tkinter is built-in
python3 -c "import tkinter; print('tkinter OK')"
```

**Error: Display issues**
```bash
# Make sure DISPLAY is set
echo $DISPLAY

# If empty, export it
export DISPLAY=:0
```

### Clipboard Not Working

```bash
# Check if xclip is installed
which xclip

# If not found:
sudo pacman -S xclip
```

### Performance Issues

The first time you create/unlock a vault may take 1-2 seconds due to the key derivation (this is intentional for security). Subsequent operations are fast.

## Features Available

✓ Secure encrypted password storage (AES-256-GCM)
✓ Password generation (random, passphrases, PINs)
✓ Password strength analysis
✓ Search and filtering
✓ Categories and organization
✓ Import/Export backups
✓ Auto-clearing clipboard
✓ Master password change

## Development/Advanced

### Create a Virtual Environment

If you want to use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install argon2-cffi  # Now you can use pip
python3 password_manager.py
```

### Backup Your Vault

```bash
# Manual backup
cp ~/.password_manager/vault.enc ~/backups/vault-$(date +%Y%m%d).enc

# Or use the app's export feature:
# Settings → Export Vault (JSON)
```

## What Was Fixed

1. ✓ Made argon2-cffi optional with secure fallback
2. ✓ Fixed vault creation bug (missing _master_password)
3. ✓ Added Arch Linux specific installation docs
4. ✓ Created CLI test script for verification
5. ✓ Updated installation checker to allow optional dependencies

## Need Help?

- **Documentation**: See README.md for full documentation
- **Installation**: See INSTALL.md or ARCH_INSTALL.md
- **Quick Guide**: See QUICKSTART.md

## Next Steps

1. ✓ Run `python3 test_cli.py` to verify everything works
2. ✓ Launch `python3 password_manager.py` to use the GUI
3. ✓ Create your vault with a strong master password
4. ✓ Optional: Install argon2-cffi for maximum security

---

**Your password manager is ready to use!** 🎉
