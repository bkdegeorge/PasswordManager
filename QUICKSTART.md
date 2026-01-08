# Quick Start Guide

Get up and running with SecureVault in 5 minutes!

## 1. Install Dependencies (2 minutes)

```bash
cd password-manager
pip install -r requirements.txt
```

**Need tkinter?** (Linux only)
```bash
sudo apt-get install python3-tk xclip
```

## 2. Launch Application (10 seconds)

```bash
python3 password_manager.py
```

## 3. Create Your Vault (30 seconds)

1. Enter a strong master password (at least 8 characters)
2. Click **"Create New Vault"**
3. Confirm your master password
4. Done! Your vault is created at `~/.password_manager/vault.enc`

**⚠️ IMPORTANT**: Your master password cannot be recovered if forgotten!

## 4. Add Your First Password (1 minute)

1. Click **"Add Password"** in the sidebar
2. Fill in the form:
   - **Title**: Netflix
   - **Username**: your@email.com
   - **Password**: Click "Generate" or enter your own
   - **URL**: https://netflix.com
   - **Category**: Entertainment
3. Click **"Save Password"**

## 5. Find and Use Passwords (30 seconds)

1. Click **"Passwords"** in sidebar
2. Use search bar to find "Netflix"
3. Click **"Copy"** to copy password to clipboard
4. Paste into Netflix login (Ctrl+V / Cmd+V)
5. Password auto-clears from clipboard in 30 seconds

## 6. Generate Strong Passwords (1 minute)

1. Click **"Generate Password"** in sidebar
2. Choose **Password** or **Passphrase** tab
3. Adjust options:
   - Length slider for passwords
   - Word count for passphrases
4. Click **"Generate"**
5. See strength score and click **"Copy"** to use

## Common Tasks

### Search for a Password
Type in the search box at top → matches appear instantly

### Edit a Password
Click **"View"** button on any entry → modify fields → **"Save Changes"**

### Delete a Password
Click **"Delete"** button → confirm deletion

### Generate a Strong Password
- **For login**: 16+ characters, all types enabled
- **For memorable**: Passphrase with 6+ words
- **For PIN**: 6-8 digits

### Backup Your Vault
Settings → **"Export Vault (JSON)"** → save to secure location

### Change Master Password
Settings → **"Change Master Password"** → enter old & new passwords

### Lock Your Vault
Click **"🔒 Lock Vault"** at bottom of sidebar

## Tips for Success

### Master Password Tips
✓ Use at least 16 characters
✓ Mix upper, lower, numbers, symbols
✓ Make it memorable but unique
✓ Consider a passphrase: "Correct-Horse-Battery-Staple-42"
✗ Don't use passwords from other services
✗ Don't write it down insecurely

### Password Generation Tips
- **Online banking**: 20+ chars, all types
- **Social media**: 16+ chars, all types
- **Less important**: 12+ chars
- **Memorable**: Use passphrases

### Organization Tips
- Use categories: Work, Personal, Finance, Email, etc.
- Add URLs for quick reference
- Use notes for security questions or hints
- Search by partial matches (e.g., "goo" finds "Google")

### Security Tips
- Lock vault when leaving computer
- Export backup monthly to encrypted drive
- Don't share master password
- Use unique passwords for each site
- Check password strength (aim for 70+)

## Troubleshooting

### "Vault not found"
→ Click "Create New Vault" first

### "Incorrect master password"
→ Check caps lock, try again carefully
→ If forgotten, vault cannot be recovered (by design)

### Clipboard not working (Linux)
```bash
sudo apt-get install xclip
```

### GUI not showing (Linux)
```bash
sudo apt-get install python3-tk
```

## Next Steps

- Read [README.md](README.md) for full documentation
- See [INSTALL.md](INSTALL.md) for advanced installation
- Try [example_usage.py](example_usage.py) to see the API

## Emergency Recovery

### Lost Master Password
❌ **Cannot be recovered** - this is by design for security
→ You'll need to create a new vault and re-add passwords

### Vault File Deleted
❌ **Cannot be recovered** without backup
→ Always keep backups: Settings → Export Vault

### Vault File Location
Default: `~/.password_manager/vault.enc`
→ Backup this file regularly!

## Keyboard Shortcuts

- **Ctrl+V / Cmd+V**: Paste copied password
- **Enter**: Submit forms / unlock vault
- **Esc**: Close dialogs

---

**You're all set! 🎉**

Start securing your passwords today with SecureVault.

For help: Check [README.md](README.md) | For installation: See [INSTALL.md](INSTALL.md)
