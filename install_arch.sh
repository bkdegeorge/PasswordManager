#!/bin/bash
# Installation script for Arch Linux

echo "=================================================="
echo "SecureVault - Arch Linux Installation"
echo "=================================================="
echo ""

echo "Installing required system packages..."
echo ""

# Check if packages are already installed
packages_to_install=""

if ! pacman -Q python-cryptography &>/dev/null; then
    packages_to_install="$packages_to_install python-cryptography"
fi

if ! pacman -Q python-pyperclip &>/dev/null; then
    packages_to_install="$packages_to_install python-pyperclip"
fi

if ! pacman -Q python-argon2-cffi &>/dev/null; then
    packages_to_install="$packages_to_install python-argon2-cffi"
fi

if [ -n "$packages_to_install" ]; then
    echo "The following packages will be installed:"
    echo "$packages_to_install"
    echo ""
    echo "Run this command:"
    echo "sudo pacman -S $packages_to_install"
    echo ""
    echo "Then run this script again to verify."
    exit 1
else
    echo "✓ All required packages are already installed!"
    echo ""
fi

# Verify installation
echo "Verifying installation..."
python3 check_installation.py

if [ $? -eq 0 ]; then
    echo ""
    echo "=================================================="
    echo "✓ Installation complete!"
    echo "=================================================="
    echo ""
    echo "You can now run:"
    echo "  python3 password_manager.py"
    echo ""
else
    echo ""
    echo "Installation verification failed."
    echo "Please check the errors above."
    exit 1
fi
