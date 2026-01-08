# Installation Guide

## Quick Start

### 1. Install Python Dependencies

The password manager requires Python 3.8+ and several dependencies. Install them using:

```bash
# Using pip
pip install -r requirements.txt

# Or install individually
pip install cryptography>=41.0.0
pip install pyperclip>=1.8.2
pip install argon2-cffi>=23.1.0
```

### 2. Platform-Specific Requirements

#### Linux (Ubuntu/Debian)
```bash
# Install tkinter for GUI
sudo apt-get update
sudo apt-get install python3-tk

# Install clipboard support
sudo apt-get install xclip
```

#### Linux (Fedora/RHEL)
```bash
sudo dnf install python3-tkinter
sudo dnf install xclip
```

#### macOS
```bash
# Python from Homebrew includes tkinter
brew install python-tk

# pyperclip works out of the box on macOS
```

#### Windows
- Python from python.org includes tkinter
- pyperclip works out of the box on Windows
- Run as: `python password_manager.py`

### 3. Verify Installation

Test that all modules load correctly:

```bash
cd password-manager
python3 -c "from src import crypto, vault, password_generator, password_strength; print('Success!')"
```

### 4. Run the Application

```bash
# Make executable (Linux/Mac)
chmod +x password_manager.py
./password_manager.py

# Or run directly
python3 password_manager.py
```

## Troubleshooting

### "No module named 'cryptography'"
```bash
pip install cryptography
```

### "No module named 'argon2'"
```bash
pip install argon2-cffi
```

### "ModuleNotFoundError: No module named 'tkinter'"
This means Python's tkinter module isn't installed.

**Ubuntu/Debian:**
```bash
sudo apt-get install python3-tk
```

**macOS:**
```bash
brew install python-tk@3.x  # Replace x with your Python version
```

### Clipboard Issues on Linux

If copy-to-clipboard doesn't work:
```bash
# Install xclip or xsel
sudo apt-get install xclip
# or
sudo apt-get install xsel
```

### Permission Denied Error
```bash
chmod +x password_manager.py
```

## Virtual Environment (Recommended)

For a clean installation, use a virtual environment:

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# Linux/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run application
python password_manager.py
```

## Development Setup

For development with testing:

```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov black flake8

# Run tests (if implemented)
pytest tests/

# Format code
black src/

# Lint code
flake8 src/
```

## Docker Setup (Optional)

If you prefer Docker:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3-tk \
    xclip \
    && rm -rf /var/lib/apt/lists/*

# Copy files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Note: GUI apps in Docker require X11 forwarding
CMD ["python3", "password_manager.py"]
```

Run with X11 forwarding:
```bash
docker build -t password-manager .
xhost +local:docker
docker run -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix password-manager
```

## Uninstallation

To remove the password manager:

```bash
# Remove the application directory
rm -rf password-manager/

# Remove the vault (WARNING: This deletes all passwords!)
rm -rf ~/.password_manager/

# Uninstall Python packages (if not used elsewhere)
pip uninstall cryptography pyperclip argon2-cffi
```

## Next Steps

Once installed, see [README.md](README.md) for usage instructions.
