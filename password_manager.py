#!/usr/bin/env python3
"""
SecureVault - Personal Password Manager
Main application entry point
"""

import sys
import tkinter as tk
from tkinter import simpledialog

# Make simpledialog available globally
tk.simpledialog = simpledialog

from src.gui_modern import main

if __name__ == '__main__':
    main()
