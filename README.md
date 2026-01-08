# SecureVault - Personal Password Manager

A secure, feature-rich password manager for personal use built with Python. Store passwords/passphrases for websites, generate strong passwords, and manage your credentials safely with military-grade encryption.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)

## Features

### Security
- **AES-256-GCM Encryption** - Military-grade encryption for your password vault
- **Argon2id Key Derivation** - Secure master password hashing resistant to brute-force attacks
- **PBKDF2 with 600,000 iterations** - Strong key derivation from master password
- **Encrypted local storage** - All passwords stored in encrypted file format
- **No cloud sync** - Your data stays on your machine (optional export/import available)
- **Auto-clearing clipboard** - Copied passwords automatically cleared after 30 seconds

### Password Management
- **Secure Password Storage** - Store unlimited passwords with title, username, URL, notes, and categories
- **Search & Filter** - Quickly find passwords by title, username, URL, or category
- **Categories** - Organize passwords into custom categories (Work, Personal, Finance, etc.)
- **Password Strength Analyzer** - Real-time analysis with scoring and feedback
- **Time-to-Crack Estimation** - See how long it would take to crack your passwords

### Password Generation
- **Random Password Generator** - Create strong passwords with customizable options:
  - Length: 8-64 characters
  - Uppercase, lowercase, digits, and symbols
  - Guaranteed character type inclusion

- **Passphrase Generator** - Create memorable passphrases:
  - EFF wordlist-based (2,000+ words)
  - Customizable word count (3-10 words)
  - Multiple separator options (-, _, space, etc.)
  - Optional capitalization and numbers

- **PIN Generator** - Generate secure numeric PINs

### User Interface
- **Modern Desktop GUI** - Clean, intuitive interface built with tkinter
- **Responsive Design** - Resizable window with minimum dimensions
- **Dark Sidebar Navigation** - Easy-to-use navigation menu
- **Password Cards** - Visual card-based password display
- **Quick Actions** - Copy, view, edit, and delete with one click
- **Form Validation** - Input validation and helpful error messages

### Data Management
- **Import/Export** - Backup your vault or transfer between systems (JSON format)
- **Master Password Change** - Change your master password securely
- **Vault Statistics** - View entry count, categories, and vault location

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)

### Setup

1. Clone or download this repository:
```bash
cd password-manager
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Make the main script executable (Linux/Mac):
```bash
chmod +x password_manager.py
```

## Usage

### Starting the Application

Run the password manager:
```bash
python password_manager.py
```

Or on Linux/Mac:
```bash
./password_manager.py
```

### First Time Setup

1. **Create Your Vault**
   - Launch the application
   - Enter a strong master password (minimum 8 characters)
   - Click "Create New Vault"
   - Confirm your master password

   **IMPORTANT**: Your master password cannot be recovered if forgotten. Choose something memorable but secure!

2. **Add Your First Password**
   - Click "Add Password" in the sidebar
   - Fill in the required fields (Title, Username, Password)
   - Optionally add URL, category, and notes
   - Click "Save Password"

### Daily Use

#### Unlocking Your Vault
1. Launch the application
2. Enter your master password
3. Click "Unlock Vault"

#### Finding Passwords
- Use the search bar at the top to filter by title, username, URL, or category
- Scroll through the password list
- Click "Copy" to copy password to clipboard (auto-clears in 30 seconds)
- Click "View" to see/edit details

#### Generating Passwords
1. Click "Generate Password" in sidebar
2. Choose between Password or Passphrase
3. Adjust options (length, character types, etc.)
4. Click "Generate" to create a new password
5. Click "Copy" to use it

#### Managing Your Vault
- **Change Master Password**: Settings → Change Master Password
- **Export Backup**: Settings → Export Vault (JSON)
- **Import Data**: Settings → Import from JSON
- **Lock Vault**: Click "Lock Vault" button at bottom of sidebar

## Security Best Practices

### Master Password
- Use at least 16 characters
- Mix uppercase, lowercase, numbers, and symbols
- Don't reuse passwords from other services
- Consider using a passphrase: "Correct-Horse-Battery-Staple-Style"
- Never share your master password

### Password Generation
- Use at least 16 characters for important accounts
- Enable all character types (upper, lower, digits, symbols)
- Generate unique passwords for each service
- Use passphrases for passwords you need to remember

### Vault Security
- Keep your vault file secure (default: `~/.password_manager/vault.enc`)
- Export backups to encrypted drives only
- Don't store the master password anywhere
- Lock vault when stepping away from computer

## Architecture

### Components

#### Encryption (`src/crypto.py`)
- **CryptoManager**: Handles all encryption/decryption operations
  - AES-256-GCM for data encryption
  - Argon2id for master password hashing
  - PBKDF2-HMAC-SHA256 for key derivation
  - Secure random number generation

#### Password Storage (`src/vault.py`)
- **PasswordEntry**: Data model for password entries
- **PasswordVault**: Manages encrypted storage and retrieval
  - Create/unlock vault with master password
  - Add/update/delete entries
  - Search and filter functionality
  - Import/export capabilities

#### Password Generation (`src/password_generator.py`)
- **PasswordGenerator**: Creates secure passwords and passphrases
  - Random password generation with entropy
  - EFF wordlist-based passphrases
  - PIN generation
  - Cryptographically secure randomness (secrets module)

#### Password Analysis (`src/password_strength.py`)
- **PasswordStrengthAnalyzer**: Analyzes password security
  - Strength scoring (0-100)
  - Entropy calculation
  - Pattern detection (sequential, repeated characters)
  - Common password checking
  - Time-to-crack estimation

#### GUI (`src/gui.py`)
- **PasswordManagerGUI**: Desktop application interface
  - Login/vault creation screen
  - Password list view with search
  - Add/edit password forms
  - Password generator interface
  - Settings and vault management

### File Structure
```
password-manager/
├── password_manager.py      # Main entry point
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── src/
│   ├── __init__.py
│   ├── crypto.py            # Encryption module
│   ├── vault.py             # Storage backend
│   ├── password_generator.py # Password generation
│   ├── password_strength.py # Strength analysis
│   └── gui.py               # Desktop interface
└── tests/                   # Unit tests (optional)
```

### Vault File Format

The encrypted vault is stored as JSON at `~/.password_manager/vault.enc`:
```json
{
  "encrypted_data": "base64-encoded-ciphertext",
  "salt": "base64-encoded-salt",
  "nonce": "base64-encoded-nonce",
  "version": "1.0",
  "master_hash": "argon2id-hash"
}
```

## Dependencies

- **cryptography** (>=41.0.0) - Encryption primitives
- **pyperclip** (>=1.8.2) - Clipboard integration
- **argon2-cffi** (>=23.1.0) - Argon2 password hashing
- **zxcvbn** (>=4.4.28) - Password strength estimation (optional enhancement)

## Troubleshooting

### "Vault not found" error
- The vault file doesn't exist yet
- Click "Create New Vault" to initialize

### "Incorrect master password"
- Double-check your master password
- Master passwords are case-sensitive
- If forgotten, the vault cannot be recovered (this is intentional for security)

### Clipboard not working
- Ensure pyperclip is installed: `pip install pyperclip`
- On Linux, you may need `xclip` or `xsel`: `sudo apt install xclip`

### GUI not displaying correctly
- Ensure Python's tkinter is installed
- On Ubuntu/Debian: `sudo apt install python3-tk`
- Try resizing the window

## Limitations

- Single-user, single-device (no cloud sync)
- No browser extension (copy-paste workflow)
- No mobile apps (desktop only)
- No password sharing features
- No automatic password change detection

## Future Enhancements

Potential features for future versions:
- Browser extension integration
- Mobile apps (iOS/Android)
- Cloud sync with E2E encryption
- TOTP 2FA code generation
- Password breach monitoring
- Secure password sharing
- Auto-fill capabilities
- SSH key management
- Secure notes storage

## Security Disclosure

If you discover a security vulnerability, please email the details to your security contact. Do not open public issues for security vulnerabilities.

## License

MIT License - See LICENSE file for details

## Disclaimer

This password manager is provided as-is for personal use. While it implements industry-standard encryption, no software is 100% secure. Use at your own risk. Always maintain backups of your vault.

## Credits

Built with:
- Python 3
- tkinter (GUI)
- cryptography library
- Argon2 password hashing
- EFF wordlist for passphrases

---

**Remember**: The security of your passwords depends on choosing a strong master password and keeping it secret. Choose wisely!
