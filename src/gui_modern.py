"""
Modern Desktop GUI for password manager using tkinter.
Features a clean, contemporary design with improved UX.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pyperclip
import threading
from datetime import datetime
from .vault import PasswordVault, PasswordEntry
from .password_generator import PasswordGenerator
from .password_strength import PasswordStrengthAnalyzer


class ModernPasswordManagerGUI:
    """Modern GUI application for password manager with improved UX."""

    def __init__(self, root):
        self.root = root
        self.root.title("SecureVault")
        self.root.geometry("1200x750")
        self.root.minsize(1000, 650)

        self.vault = PasswordVault()
        self.generator = PasswordGenerator()
        self.analyzer = PasswordStrengthAnalyzer()

        self.clipboard_timer = None
        self.current_entries = []

        # Modern color scheme - clean and professional
        self.colors = {
            'bg': '#f5f7fa',              # Light gray-blue background
            'card_bg': '#ffffff',          # Pure white for cards
            'fg': '#2d3748',              # Dark gray text
            'fg_light': '#718096',        # Light gray text
            'primary': '#667eea',         # Modern purple-blue
            'primary_hover': '#5a67d8',   # Darker primary
            'success': '#48bb78',         # Green
            'danger': '#f56565',          # Red
            'warning': '#ed8936',         # Orange
            'sidebar': '#1a202c',         # Very dark gray (almost black)
            'sidebar_hover': '#2d3748',   # Sidebar hover
            'sidebar_fg': '#e2e8f0',      # Light text for sidebar
            'border': '#e2e8f0',          # Light border
            'input_bg': '#ffffff',        # Input background
            'shadow': '#00000015',        # Subtle shadow
        }

        self.setup_styles()
        self.show_login_screen()

    def setup_styles(self):
        """Configure modern ttk styles."""
        style = ttk.Style()
        style.theme_use('clam')

        # Modern button styles with rounded appearance
        style.configure('Primary.TButton',
                       background=self.colors['primary'],
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'),
                       padding=(20, 12))

        style.map('Primary.TButton',
                 background=[('active', self.colors['primary_hover']),
                           ('pressed', self.colors['primary_hover'])])

        style.configure('Success.TButton',
                       background=self.colors['success'],
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'),
                       padding=(20, 12))

        style.map('Success.TButton',
                 background=[('active', '#38a169')])

        style.configure('Danger.TButton',
                       background=self.colors['danger'],
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10),
                       padding=(16, 10))

        style.map('Danger.TButton',
                 background=[('active', '#e53e3e')])

        # Entry style
        style.configure('Modern.TEntry',
                       fieldbackground=self.colors['input_bg'],
                       borderwidth=1,
                       relief='solid')

    def create_card(self, parent, **kwargs):
        """Create a modern card-style frame with shadow effect."""
        card = tk.Frame(parent,
                       bg=self.colors['card_bg'],
                       highlightbackground=self.colors['border'],
                       highlightthickness=1,
                       **kwargs)
        return card

    def create_rounded_button(self, parent, text, command, style='primary', **kwargs):
        """Create a modern rounded-looking button."""
        colors = {
            'primary': (self.colors['primary'], self.colors['primary_hover'], 'white'),
            'success': (self.colors['success'], '#38a169', 'white'),
            'danger': (self.colors['danger'], '#e53e3e', 'white'),
            'secondary': ('#e2e8f0', '#cbd5e0', self.colors['fg']),
        }

        bg, hover_bg, fg = colors.get(style, colors['primary'])

        btn = tk.Button(parent,
                       text=text,
                       command=command,
                       bg=bg,
                       fg=fg,
                       activebackground=hover_bg,
                       activeforeground=fg,
                       relief='flat',
                       font=('Segoe UI', 10, 'bold'),
                       cursor='hand2',
                       padx=24,
                       pady=12,
                       borderwidth=0,
                       **kwargs)

        # Hover effects
        btn.bind('<Enter>', lambda e: btn.config(bg=hover_bg))
        btn.bind('<Leave>', lambda e: btn.config(bg=bg))

        return btn

    def clear_window(self):
        """Clear all widgets from window."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        """Display modern login/create vault screen."""
        self.clear_window()
        self.root.config(bg=self.colors['bg'])

        # Container
        container = tk.Frame(self.root, bg=self.colors['bg'])
        container.place(relx=0.5, rely=0.5, anchor='center')

        # Card
        card = self.create_card(container, padx=60, pady=50)
        card.pack()

        # Lock icon (using Unicode)
        icon = tk.Label(card, text="🔐", font=('Segoe UI', 48),
                       bg=self.colors['card_bg'])
        icon.pack(pady=(0, 20))

        # Title
        title = tk.Label(card, text="SecureVault",
                        font=('Segoe UI', 32, 'bold'),
                        bg=self.colors['card_bg'],
                        fg=self.colors['fg'])
        title.pack(pady=(0, 5))

        subtitle = tk.Label(card, text="Secure Password Manager",
                          font=('Segoe UI', 12),
                          bg=self.colors['card_bg'],
                          fg=self.colors['fg_light'])
        subtitle.pack(pady=(0, 30))

        # Master password input
        label = tk.Label(card, text="Master Password",
                        font=('Segoe UI', 10, 'bold'),
                        bg=self.colors['card_bg'],
                        fg=self.colors['fg'])
        label.pack(anchor='w', pady=(0, 8))

        self.master_password_entry = tk.Entry(card, show='•',
                                              font=('Segoe UI', 12),
                                              width=30,
                                              bg=self.colors['input_bg'],
                                              fg=self.colors['fg'],
                                              relief='solid',
                                              borderwidth=1,
                                              highlightthickness=2,
                                              highlightbackground=self.colors['border'],
                                              highlightcolor=self.colors['primary'])
        self.master_password_entry.pack(pady=(0, 25), ipady=8)
        self.master_password_entry.bind('<Return>', lambda e: self.unlock_vault())
        self.master_password_entry.focus()

        # Buttons
        btn_frame = tk.Frame(card, bg=self.colors['card_bg'])
        btn_frame.pack(pady=(0, 10))

        unlock_btn = self.create_rounded_button(btn_frame, "Unlock Vault",
                                                self.unlock_vault, 'primary')
        unlock_btn.pack(side='left', padx=5)

        create_btn = self.create_rounded_button(btn_frame, "Create New Vault",
                                               self.create_vault, 'success')
        create_btn.pack(side='left', padx=5)

    def create_vault(self):
        """Create a new vault with modern dialog."""
        password = self.master_password_entry.get()

        if not password:
            messagebox.showerror("Error", "Please enter a master password")
            return

        if len(password) < 8:
            messagebox.showerror("Error", "Master password must be at least 8 characters")
            return

        # Show password strength
        analysis = self.analyzer.analyze(password)
        if analysis['score'] < 50:
            if not messagebox.askyesno("Weak Password",
                                      f"Your master password is {analysis['strength']} (score: {analysis['score']}/100).\n\n"
                                      "This may be vulnerable to attacks. Create vault anyway?"):
                return

        # Confirm password
        confirm_password = tk.simpledialog.askstring(
            "Confirm Password",
            "Re-enter master password:",
            show='•'
        )

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        try:
            self.vault.create_vault(password)
            messagebox.showinfo("Success", "Vault created successfully!")
            self.show_main_screen()
        except FileExistsError:
            messagebox.showerror("Error", "Vault already exists. Use 'Unlock Vault' instead.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create vault: {str(e)}")

    def unlock_vault(self):
        """Unlock existing vault."""
        password = self.master_password_entry.get()

        if not password:
            messagebox.showerror("Error", "Please enter master password")
            return

        try:
            if self.vault.unlock_vault(password):
                self.show_main_screen()
            else:
                messagebox.showerror("Error", "Incorrect master password")
                self.master_password_entry.delete(0, 'end')
                self.master_password_entry.focus()
        except FileNotFoundError:
            response = messagebox.askyesno(
                "Vault Not Found",
                "No vault found. Would you like to create a new one?"
            )
            if response:
                self.create_vault()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unlock vault: {str(e)}")

    def show_main_screen(self):
        """Display modern main interface."""
        self.clear_window()
        self.root.config(bg=self.colors['bg'])

        # Main container with sidebar
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill='both', expand=True)

        # Modern sidebar
        self.create_sidebar(main_container)

        # Content area with padding
        content_container = tk.Frame(main_container, bg=self.colors['bg'])
        content_container.pack(side='left', fill='both', expand=True, padx=30, pady=30)

        self.content_frame = content_container

        # Show passwords view by default
        self.show_passwords_view()

    def create_sidebar(self, parent):
        """Create modern sidebar navigation."""
        sidebar = tk.Frame(parent, bg=self.colors['sidebar'], width=240)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)

        # Logo area
        logo_frame = tk.Frame(sidebar, bg=self.colors['sidebar'])
        logo_frame.pack(pady=30)

        icon = tk.Label(logo_frame, text="🔐", font=('Segoe UI', 32),
                       bg=self.colors['sidebar'])
        icon.pack()

        title = tk.Label(logo_frame, text="SecureVault",
                        font=('Segoe UI', 16, 'bold'),
                        bg=self.colors['sidebar'],
                        fg=self.colors['sidebar_fg'])
        title.pack(pady=(10, 0))

        # Separator
        sep = tk.Frame(sidebar, bg=self.colors['sidebar_hover'], height=1)
        sep.pack(fill='x', padx=20, pady=20)

        # Navigation buttons
        nav_items = [
            ("🏠  All Passwords", self.show_passwords_view),
            ("➕  Add Password", self.show_add_password_view),
            ("🎲  Generate", self.show_generator_view),
            ("⚙️  Settings", self.show_settings_view),
        ]

        for text, command in nav_items:
            self.create_nav_button(sidebar, text, command)

        # Lock button at bottom
        lock_frame = tk.Frame(sidebar, bg=self.colors['sidebar'])
        lock_frame.pack(side='bottom', fill='x', padx=20, pady=30)

        lock_btn = tk.Button(lock_frame, text="🔒  Lock Vault",
                            command=self.lock_vault,
                            bg=self.colors['danger'],
                            fg='white',
                            activebackground='#e53e3e',
                            activeforeground='white',
                            relief='flat',
                            font=('Segoe UI', 11, 'bold'),
                            cursor='hand2',
                            pady=12,
                            borderwidth=0)
        lock_btn.pack(fill='x')

        lock_btn.bind('<Enter>', lambda e: lock_btn.config(bg='#e53e3e'))
        lock_btn.bind('<Leave>', lambda e: lock_btn.config(bg=self.colors['danger']))

    def create_nav_button(self, parent, text, command):
        """Create a modern navigation button."""
        btn = tk.Button(parent, text=text,
                       command=command,
                       bg=self.colors['sidebar'],
                       fg=self.colors['sidebar_fg'],
                       activebackground=self.colors['sidebar_hover'],
                       activeforeground='white',
                       relief='flat',
                       font=('Segoe UI', 11),
                       cursor='hand2',
                       anchor='w',
                       padx=20,
                       pady=15,
                       borderwidth=0)
        btn.pack(fill='x', padx=10, pady=2)

        # Hover effect
        btn.bind('<Enter>', lambda e: btn.config(bg=self.colors['sidebar_hover']))
        btn.bind('<Leave>', lambda e: btn.config(bg=self.colors['sidebar']))

    def clear_content(self):
        """Clear content area."""
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def show_passwords_view(self):
        """Display modern password list."""
        self.clear_content()

        # Header
        header_frame = tk.Frame(self.content_frame, bg=self.colors['bg'])
        header_frame.pack(fill='x', pady=(0, 25))

        title = tk.Label(header_frame, text="Your Passwords",
                        font=('Segoe UI', 24, 'bold'),
                        bg=self.colors['bg'],
                        fg=self.colors['fg'])
        title.pack(side='left')

        # Search bar
        search_frame = tk.Frame(header_frame, bg=self.colors['bg'])
        search_frame.pack(side='right')

        search_icon = tk.Label(search_frame, text="🔍",
                              font=('Segoe UI', 12),
                              bg=self.colors['bg'])
        search_icon.pack(side='left', padx=(0, 8))

        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_passwords)
        search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                              font=('Segoe UI', 11),
                              width=30,
                              bg=self.colors['card_bg'],
                              fg=self.colors['fg'],
                              relief='solid',
                              borderwidth=1,
                              highlightthickness=2,
                              highlightbackground=self.colors['border'],
                              highlightcolor=self.colors['primary'])
        search_entry.pack(side='left', ipady=6)

        # Stats card
        entries = self.vault.get_all_entries()
        stats_card = self.create_card(self.content_frame)
        stats_card.pack(fill='x', pady=(0, 20))

        stats_inner = tk.Frame(stats_card, bg=self.colors['card_bg'], padx=20, pady=15)
        stats_inner.pack(fill='x')

        stats_text = f"📊  Total: {len(entries)} passwords  •  🗂️  Categories: {len(self.vault.get_categories())}"
        stats_label = tk.Label(stats_inner, text=stats_text,
                              font=('Segoe UI', 10),
                              bg=self.colors['card_bg'],
                              fg=self.colors['fg_light'])
        stats_label.pack()

        # Passwords list container
        list_card = self.create_card(self.content_frame)
        list_card.pack(fill='both', expand=True)

        # Scrollbar
        scrollbar = tk.Scrollbar(list_card)
        scrollbar.pack(side='right', fill='y')

        # Canvas for scrolling
        self.password_canvas = tk.Canvas(list_card, bg=self.colors['card_bg'],
                                        yscrollcommand=scrollbar.set,
                                        highlightthickness=0)
        self.password_canvas.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.password_canvas.yview)

        # Inner frame
        self.password_list_frame = tk.Frame(self.password_canvas, bg=self.colors['card_bg'])
        self.password_canvas.create_window((0, 0), window=self.password_list_frame,
                                          anchor='nw')

        self.refresh_password_list()

        # Update scroll region
        self.password_list_frame.bind(
            '<Configure>',
            lambda e: self.password_canvas.configure(
                scrollregion=self.password_canvas.bbox('all')
            )
        )

        # Mouse wheel scrolling
        self.password_canvas.bind_all('<Button-4>', lambda e: self.password_canvas.yview_scroll(-1, 'units'))
        self.password_canvas.bind_all('<Button-5>', lambda e: self.password_canvas.yview_scroll(1, 'units'))

    def refresh_password_list(self, entries=None):
        """Refresh the password list display with modern cards."""
        for widget in self.password_list_frame.winfo_children():
            widget.destroy()

        if entries is None:
            entries = self.vault.get_all_entries()

        self.current_entries = entries

        if not entries:
            empty_frame = tk.Frame(self.password_list_frame, bg=self.colors['card_bg'])
            empty_frame.pack(fill='both', expand=True, pady=100)

            icon = tk.Label(empty_frame, text="🔑",
                           font=('Segoe UI', 48),
                           bg=self.colors['card_bg'])
            icon.pack()

            msg = tk.Label(empty_frame,
                          text="No passwords yet\n\nClick 'Add Password' to get started!",
                          font=('Segoe UI', 12),
                          bg=self.colors['card_bg'],
                          fg=self.colors['fg_light'],
                          justify='center')
            msg.pack(pady=10)
            return

        for entry in sorted(entries, key=lambda x: x.title.lower()):
            self.create_password_card_modern(entry)

    def create_password_card_modern(self, entry: PasswordEntry):
        """Create a modern password card."""
        # Card container
        card_container = tk.Frame(self.password_list_frame, bg=self.colors['card_bg'])
        card_container.pack(fill='x', padx=20, pady=8)

        # Inner card with border
        card = tk.Frame(card_container,
                       bg='white',
                       highlightbackground=self.colors['border'],
                       highlightthickness=1)
        card.pack(fill='x')

        inner = tk.Frame(card, bg='white', padx=20, pady=16)
        inner.pack(fill='x')

        # Left side - info
        info_frame = tk.Frame(inner, bg='white')
        info_frame.pack(side='left', fill='both', expand=True)

        # Title with icon
        title_frame = tk.Frame(info_frame, bg='white')
        title_frame.pack(fill='x', anchor='w')

        title = tk.Label(title_frame, text=entry.title,
                        font=('Segoe UI', 13, 'bold'),
                        bg='white',
                        fg=self.colors['fg'])
        title.pack(side='left')

        # Category badge
        if entry.category:
            badge = tk.Label(title_frame, text=entry.category,
                           font=('Segoe UI', 8, 'bold'),
                           bg=self.colors['primary'],
                           fg='white',
                           padx=8, pady=2)
            badge.pack(side='left', padx=10)

        # Username
        username = tk.Label(info_frame, text=f"👤 {entry.username}",
                          font=('Segoe UI', 10),
                          bg='white',
                          fg=self.colors['fg_light'])
        username.pack(fill='x', anchor='w', pady=(4, 0))

        # URL if present
        if entry.url:
            url = tk.Label(info_frame, text=f"🔗 {entry.url}",
                          font=('Segoe UI', 9),
                          bg='white',
                          fg=self.colors['primary'],
                          cursor='hand2')
            url.pack(fill='x', anchor='w', pady=(2, 0))

        # Right side - actions
        action_frame = tk.Frame(inner, bg='white')
        action_frame.pack(side='right', padx=(15, 0))

        # Modern action buttons
        copy_btn = tk.Button(action_frame, text="📋 Copy",
                           command=lambda: self.copy_password(entry.password),
                           bg=self.colors['primary'],
                           fg='white',
                           activebackground=self.colors['primary_hover'],
                           activeforeground='white',
                           relief='flat',
                           font=('Segoe UI', 9, 'bold'),
                           cursor='hand2',
                           padx=12, pady=6,
                           borderwidth=0)
        copy_btn.pack(side='left', padx=3)

        view_btn = tk.Button(action_frame, text="👁️ View",
                           command=lambda: self.view_entry(entry),
                           bg=self.colors['success'],
                           fg='white',
                           activebackground='#38a169',
                           activeforeground='white',
                           relief='flat',
                           font=('Segoe UI', 9, 'bold'),
                           cursor='hand2',
                           padx=12, pady=6,
                           borderwidth=0)
        view_btn.pack(side='left', padx=3)

        delete_btn = tk.Button(action_frame, text="🗑️",
                             command=lambda: self.delete_entry(entry),
                             bg='#f7fafc',
                             fg=self.colors['danger'],
                             activebackground='#edf2f7',
                             activeforeground=self.colors['danger'],
                             relief='flat',
                             font=('Segoe UI', 10),
                             cursor='hand2',
                             padx=10, pady=6,
                             borderwidth=0)
        delete_btn.pack(side='left', padx=3)

        # Hover effects
        for btn in [copy_btn, view_btn]:
            original_bg = btn.cget('bg')
            hover_bg = btn.cget('activebackground')
            btn.bind('<Enter>', lambda e, b=btn, c=hover_bg: b.config(bg=c))
            btn.bind('<Leave>', lambda e, b=btn, c=original_bg: b.config(bg=c))

        delete_btn.bind('<Enter>', lambda e: delete_btn.config(bg='#fed7d7', fg=self.colors['danger']))
        delete_btn.bind('<Leave>', lambda e: delete_btn.config(bg='#f7fafc', fg=self.colors['danger']))

    def filter_passwords(self, *args):
        """Filter passwords based on search query."""
        query = self.search_var.get()
        if not query:
            self.refresh_password_list()
        else:
            results = self.vault.search_entries(query)
            self.refresh_password_list(results)

    def copy_password(self, password: str):
        """Copy password to clipboard with modern notification."""
        pyperclip.copy(password)

        # Show modern toast notification
        self.show_toast("✓ Password copied to clipboard\nWill auto-clear in 30 seconds")

        # Auto-clear after 30 seconds
        if self.clipboard_timer:
            self.clipboard_timer.cancel()

        def clear_clipboard():
            if pyperclip.paste() == password:
                pyperclip.copy('')

        self.clipboard_timer = threading.Timer(30.0, clear_clipboard)
        self.clipboard_timer.start()

    def show_toast(self, message):
        """Show a modern toast notification."""
        toast = tk.Toplevel(self.root)
        toast.overrideredirect(True)
        toast.attributes('-topmost', True)

        frame = tk.Frame(toast, bg=self.colors['success'], padx=20, pady=12)
        frame.pack()

        label = tk.Label(frame, text=message,
                        font=('Segoe UI', 10),
                        bg=self.colors['success'],
                        fg='white',
                        justify='left')
        label.pack()

        # Position at top-right
        toast.update_idletasks()
        x = self.root.winfo_x() + self.root.winfo_width() - toast.winfo_width() - 20
        y = self.root.winfo_y() + 20
        toast.geometry(f'+{x}+{y}')

        # Auto-close after 3 seconds
        toast.after(3000, toast.destroy)

    def view_entry(self, entry: PasswordEntry):
        """View/edit entry with modern dialog."""
        dialog = tk.Toplevel(self.root)
        dialog.title(f"{entry.title}")
        dialog.geometry("550x650")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.config(bg=self.colors['bg'])

        # Main container
        main = tk.Frame(dialog, bg=self.colors['bg'], padx=30, pady=30)
        main.pack(fill='both', expand=True)

        # Title
        title_label = tk.Label(main, text=f"Edit: {entry.title}",
                              font=('Segoe UI', 18, 'bold'),
                              bg=self.colors['bg'],
                              fg=self.colors['fg'])
        title_label.pack(pady=(0, 20))

        # Form card
        form_card = self.create_card(main, padx=25, pady=25)
        form_card.pack(fill='both', expand=True)

        fields = {}

        def create_field(label_text, default_value, show=None):
            lbl = tk.Label(form_card, text=label_text,
                          font=('Segoe UI', 10, 'bold'),
                          bg=self.colors['card_bg'],
                          fg=self.colors['fg'])
            lbl.pack(anchor='w', pady=(10, 5))

            entry_widget = tk.Entry(form_card,
                                   font=('Segoe UI', 11),
                                   bg=self.colors['input_bg'],
                                   fg=self.colors['fg'],
                                   relief='solid',
                                   borderwidth=1,
                                   highlightthickness=2,
                                   highlightbackground=self.colors['border'],
                                   highlightcolor=self.colors['primary'],
                                   show=show)
            entry_widget.insert(0, default_value)
            entry_widget.pack(fill='x', ipady=6)
            return entry_widget

        fields['title'] = create_field("Title", entry.title)
        fields['username'] = create_field("Username", entry.username)

        # Password with show/hide
        pwd_frame = tk.Frame(form_card, bg=self.colors['card_bg'])
        pwd_frame.pack(fill='x', pady=(10, 0))

        pwd_label = tk.Label(pwd_frame, text="Password",
                            font=('Segoe UI', 10, 'bold'),
                            bg=self.colors['card_bg'],
                            fg=self.colors['fg'])
        pwd_label.pack(anchor='w', pady=(0, 5))

        pwd_input_frame = tk.Frame(pwd_frame, bg=self.colors['card_bg'])
        pwd_input_frame.pack(fill='x')

        fields['password'] = tk.Entry(pwd_input_frame,
                                     font=('Segoe UI', 11),
                                     show='•',
                                     bg=self.colors['input_bg'],
                                     fg=self.colors['fg'],
                                     relief='solid',
                                     borderwidth=1,
                                     highlightthickness=2,
                                     highlightbackground=self.colors['border'],
                                     highlightcolor=self.colors['primary'])
        fields['password'].insert(0, entry.password)
        fields['password'].pack(side='left', fill='x', expand=True, ipady=6)

        show_var = tk.BooleanVar()
        def toggle_password():
            fields['password'].config(show='' if show_var.get() else '•')

        show_btn = tk.Checkbutton(pwd_input_frame, text="👁️",
                                 variable=show_var,
                                 command=toggle_password,
                                 bg=self.colors['card_bg'],
                                 font=('Segoe UI', 12),
                                 cursor='hand2')
        show_btn.pack(side='left', padx=10)

        fields['url'] = create_field("URL", entry.url)
        fields['category'] = create_field("Category", entry.category)

        # Notes
        notes_label = tk.Label(form_card, text="Notes",
                              font=('Segoe UI', 10, 'bold'),
                              bg=self.colors['card_bg'],
                              fg=self.colors['fg'])
        notes_label.pack(anchor='w', pady=(10, 5))

        fields['notes'] = tk.Text(form_card,
                                 font=('Segoe UI', 10),
                                 height=4,
                                 bg=self.colors['input_bg'],
                                 fg=self.colors['fg'],
                                 relief='solid',
                                 borderwidth=1,
                                 highlightthickness=2,
                                 highlightbackground=self.colors['border'],
                                 highlightcolor=self.colors['primary'])
        fields['notes'].insert('1.0', entry.notes)
        fields['notes'].pack(fill='x', pady=(0, 10))

        # Buttons
        btn_frame = tk.Frame(form_card, bg=self.colors['card_bg'])
        btn_frame.pack(pady=15)

        def save_changes():
            self.vault.update_entry(
                entry.id,
                title=fields['title'].get(),
                username=fields['username'].get(),
                password=fields['password'].get(),
                url=fields['url'].get(),
                category=fields['category'].get(),
                notes=fields['notes'].get('1.0', 'end-1c')
            )
            self.show_toast("✓ Changes saved successfully!")
            dialog.destroy()
            self.refresh_password_list()

        save_btn = self.create_rounded_button(btn_frame, "💾  Save Changes",
                                             save_changes, 'primary')
        save_btn.pack(side='left', padx=5)

        cancel_btn = self.create_rounded_button(btn_frame, "Cancel",
                                               dialog.destroy, 'secondary')
        cancel_btn.pack(side='left', padx=5)

    def delete_entry(self, entry: PasswordEntry):
        """Delete a password entry with confirmation."""
        if messagebox.askyesno("Confirm Delete",
                              f"Are you sure you want to delete '{entry.title}'?\n\nThis action cannot be undone."):
            self.vault.delete_entry(entry.id)
            self.show_toast("✓ Password deleted")
            self.refresh_password_list()

    def show_add_password_view(self):
        """Show modern form to add new password."""
        self.clear_content()

        # Header
        title = tk.Label(self.content_frame, text="Add New Password",
                        font=('Segoe UI', 24, 'bold'),
                        bg=self.colors['bg'],
                        fg=self.colors['fg'])
        title.pack(pady=(0, 25))

        # Form card
        form_card = self.create_card(self.content_frame, padx=40, pady=35)
        form_card.pack(fill='both', expand=True)

        fields = {}

        def create_input(label_text, placeholder="", width=400):
            label = tk.Label(form_card, text=label_text,
                           font=('Segoe UI', 10, 'bold'),
                           bg=self.colors['card_bg'],
                           fg=self.colors['fg'])
            label.pack(anchor='w', pady=(15, 5))

            entry = tk.Entry(form_card,
                           font=('Segoe UI', 11),
                           width=50,
                           bg=self.colors['input_bg'],
                           fg=self.colors['fg'],
                           relief='solid',
                           borderwidth=1,
                           highlightthickness=2,
                           highlightbackground=self.colors['border'],
                           highlightcolor=self.colors['primary'])
            entry.pack(fill='x', ipady=8, pady=(0, 5))
            return entry

        fields['title'] = create_input("Title *")
        fields['username'] = create_input("Username *")

        # Password with generator
        pwd_label = tk.Label(form_card, text="Password *",
                           font=('Segoe UI', 10, 'bold'),
                           bg=self.colors['card_bg'],
                           fg=self.colors['fg'])
        pwd_label.pack(anchor='w', pady=(15, 5))

        pwd_frame = tk.Frame(form_card, bg=self.colors['card_bg'])
        pwd_frame.pack(fill='x')

        fields['password'] = tk.Entry(pwd_frame,
                                     font=('Segoe UI', 11),
                                     show='•',
                                     bg=self.colors['input_bg'],
                                     fg=self.colors['fg'],
                                     relief='solid',
                                     borderwidth=1,
                                     highlightthickness=2,
                                     highlightbackground=self.colors['border'],
                                     highlightcolor=self.colors['primary'])
        fields['password'].pack(side='left', fill='x', expand=True, ipady=8)

        def generate_and_fill():
            pw = self.generator.generate_password(16, True, True, True, True)
            fields['password'].delete(0, 'end')
            fields['password'].insert(0, pw)
            fields['password'].config(show='')
            analyze_strength()

        gen_btn = self.create_rounded_button(pwd_frame, "🎲 Generate",
                                            generate_and_fill, 'success')
        gen_btn.pack(side='left', padx=10)

        # Password strength
        strength_frame = tk.Frame(form_card, bg=self.colors['card_bg'])
        strength_frame.pack(fill='x', pady=8)

        strength_label = tk.Label(strength_frame, text="",
                                 font=('Segoe UI', 9),
                                 bg=self.colors['card_bg'])
        strength_label.pack(side='left')

        def analyze_strength(*args):
            password = fields['password'].get()
            if password:
                analysis = self.analyzer.analyze(password)
                color = self.analyzer.get_strength_color(analysis['score'])
                strength_label.config(
                    text=f"💪 Strength: {analysis['strength']} ({analysis['score']}/100)",
                    fg=color
                )
            else:
                strength_label.config(text="", fg='gray')

        fields['password'].bind('<KeyRelease>', analyze_strength)

        fields['url'] = create_input("URL (optional)")
        fields['category'] = create_input("Category")

        # Notes
        notes_label = tk.Label(form_card, text="Notes (optional)",
                             font=('Segoe UI', 10, 'bold'),
                             bg=self.colors['card_bg'],
                             fg=self.colors['fg'])
        notes_label.pack(anchor='w', pady=(15, 5))

        fields['notes'] = tk.Text(form_card,
                                font=('Segoe UI', 10),
                                height=4,
                                bg=self.colors['input_bg'],
                                fg=self.colors['fg'],
                                relief='solid',
                                borderwidth=1,
                                highlightthickness=2,
                                highlightbackground=self.colors['border'],
                                highlightcolor=self.colors['primary'])
        fields['notes'].pack(fill='x', pady=(0, 20))

        # Save button
        def save_entry():
            title = fields['title'].get().strip()
            username = fields['username'].get().strip()
            password = fields['password'].get()

            if not all([title, username, password]):
                messagebox.showerror("Error", "Please fill in all required fields (*)")
                return

            entry = PasswordEntry(
                title=title,
                username=username,
                password=password,
                url=fields['url'].get().strip(),
                notes=fields['notes'].get('1.0', 'end-1c').strip(),
                category=fields['category'].get() or 'General'
            )

            self.vault.add_entry(entry)
            self.show_toast("✓ Password saved successfully!")
            self.show_passwords_view()

        save_btn = self.create_rounded_button(form_card, "💾  Save Password",
                                             save_entry, 'primary')
        save_btn.pack(pady=10)

    def show_generator_view(self):
        """Show modern password generator interface."""
        self.clear_content()

        # Header
        title = tk.Label(self.content_frame, text="Password Generator",
                        font=('Segoe UI', 24, 'bold'),
                        bg=self.colors['bg'],
                        fg=self.colors['fg'])
        title.pack(pady=(0, 25))

        # Generator card
        gen_card = self.create_card(self.content_frame, padx=40, pady=35)
        gen_card.pack(fill='both', expand=True)

        # Tabs
        tab_frame = tk.Frame(gen_card, bg=self.colors['card_bg'])
        tab_frame.pack(fill='x', pady=(0, 25))

        current_tab = tk.StringVar(value='password')

        def create_tab_button(text, value):
            btn = tk.Button(tab_frame, text=text,
                           font=('Segoe UI', 11, 'bold'),
                           cursor='hand2',
                           relief='flat',
                           padx=20, pady=10,
                           borderwidth=0)

            def select_tab():
                current_tab.set(value)
                if value == 'password':
                    show_password_tab()
                    btn.config(bg=self.colors['primary'], fg='white')
                    pass_btn.config(bg=self.colors['primary'], fg='white')
                    phrase_btn.config(bg='#e2e8f0', fg=self.colors['fg'])
                else:
                    show_passphrase_tab()
                    btn.config(bg=self.colors['primary'], fg='white')
                    phrase_btn.config(bg=self.colors['primary'], fg='white')
                    pass_btn.config(bg='#e2e8f0', fg=self.colors['fg'])

            btn.config(command=select_tab)
            return btn

        pass_btn = create_tab_button("🔑 Password", 'password')
        pass_btn.pack(side='left', padx=5)
        pass_btn.config(bg=self.colors['primary'], fg='white')

        phrase_btn = create_tab_button("📝 Passphrase", 'passphrase')
        phrase_btn.pack(side='left', padx=5)
        phrase_btn.config(bg='#e2e8f0', fg=self.colors['fg'])

        # Result display
        result_card = tk.Frame(gen_card, bg='#f7fafc',
                             relief='solid', borderwidth=1,
                             highlightbackground=self.colors['border'],
                             highlightthickness=1)
        result_card.pack(fill='x', pady=(0, 25))

        result_inner = tk.Frame(result_card, bg='#f7fafc', padx=20, pady=20)
        result_inner.pack(fill='x')

        result_var = tk.StringVar(value="Click 'Generate' to create a password")
        result_label = tk.Label(result_inner, textvariable=result_var,
                               font=('Courier New', 13),
                               bg='#f7fafc',
                               fg=self.colors['fg'],
                               wraplength=600)
        result_label.pack()

        # Options frames
        password_options = tk.Frame(gen_card, bg=self.colors['card_bg'])
        passphrase_options = tk.Frame(gen_card, bg=self.colors['card_bg'])

        # Password options
        length_var = tk.IntVar(value=16)
        upper_var = tk.BooleanVar(value=True)
        lower_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        symbols_var = tk.BooleanVar(value=True)

        tk.Label(password_options, text="Length:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['card_bg']).pack(anchor='w', pady=(5, 5))

        length_scale = tk.Scale(password_options, from_=8, to=64,
                               variable=length_var, orient='horizontal',
                               length=500, bg=self.colors['card_bg'],
                               font=('Segoe UI', 10),
                               highlightthickness=0)
        length_scale.pack(fill='x', pady=(0, 15))

        for text, var in [("Uppercase (A-Z)", upper_var),
                         ("Lowercase (a-z)", lower_var),
                         ("Digits (0-9)", digits_var),
                         ("Symbols (!@#$...)", symbols_var)]:
            cb = tk.Checkbutton(password_options, text=text,
                              variable=var,
                              bg=self.colors['card_bg'],
                              font=('Segoe UI', 10),
                              cursor='hand2')
            cb.pack(anchor='w', pady=3)

        # Passphrase options
        words_var = tk.IntVar(value=6)
        separator_var = tk.StringVar(value='-')
        capitalize_var = tk.BooleanVar(value=True)
        number_var = tk.BooleanVar(value=True)

        tk.Label(passphrase_options, text="Number of words:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['card_bg']).pack(anchor='w', pady=(5, 5))

        words_scale = tk.Scale(passphrase_options, from_=3, to=10,
                              variable=words_var, orient='horizontal',
                              length=500, bg=self.colors['card_bg'],
                              font=('Segoe UI', 10),
                              highlightthickness=0)
        words_scale.pack(fill='x', pady=(0, 15))

        tk.Label(passphrase_options, text="Separator:",
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['card_bg']).pack(anchor='w', pady=(10, 5))

        sep_frame = tk.Frame(passphrase_options, bg=self.colors['card_bg'])
        sep_frame.pack(anchor='w')

        for sep, label in [('-', 'Dash'), ('_', 'Underscore'),
                          (' ', 'Space'), ('.', 'Dot'), ('', 'None')]:
            rb = tk.Radiobutton(sep_frame, text=label, value=sep,
                              variable=separator_var,
                              bg=self.colors['card_bg'],
                              font=('Segoe UI', 10),
                              cursor='hand2')
            rb.pack(side='left', padx=10)

        for text, var in [("Capitalize words", capitalize_var),
                         ("Add number at end", number_var)]:
            cb = tk.Checkbutton(passphrase_options, text=text,
                              variable=var,
                              bg=self.colors['card_bg'],
                              font=('Segoe UI', 10),
                              cursor='hand2')
            cb.pack(anchor='w', pady=(10, 3))

        def show_password_tab():
            passphrase_options.pack_forget()
            password_options.pack(fill='x', pady=(0, 20))
            generate()

        def show_passphrase_tab():
            password_options.pack_forget()
            passphrase_options.pack(fill='x', pady=(0, 20))
            generate()

        password_options.pack(fill='x', pady=(0, 20))

        # Strength indicator
        strength_label = tk.Label(gen_card, text="",
                                 font=('Segoe UI', 11),
                                 bg=self.colors['card_bg'])
        strength_label.pack(pady=10)

        # Generate function
        def generate():
            try:
                if current_tab.get() == 'password':
                    generated = self.generator.generate_password(
                        length=length_var.get(),
                        use_upper=upper_var.get(),
                        use_lower=lower_var.get(),
                        use_digits=digits_var.get(),
                        use_symbols=symbols_var.get()
                    )
                else:
                    generated = self.generator.generate_passphrase(
                        num_words=words_var.get(),
                        separator=separator_var.get(),
                        capitalize=capitalize_var.get(),
                        add_number=number_var.get()
                    )

                result_var.set(generated)

                analysis = self.analyzer.analyze(generated)
                color = self.analyzer.get_strength_color(analysis['score'])
                strength_label.config(
                    text=f"💪 Strength: {analysis['strength']} ({analysis['score']}/100)",
                    fg=color
                )

            except ValueError as e:
                messagebox.showerror("Error", str(e))

        # Buttons
        btn_frame = tk.Frame(gen_card, bg=self.colors['card_bg'])
        btn_frame.pack(pady=15)

        gen_btn = self.create_rounded_button(btn_frame, "🎲  Generate",
                                            generate, 'primary')
        gen_btn.pack(side='left', padx=5)

        copy_btn = self.create_rounded_button(btn_frame, "📋  Copy",
                                             lambda: self.copy_password(result_var.get()),
                                             'success')
        copy_btn.pack(side='left', padx=5)

        # Generate initial password
        generate()

    def show_settings_view(self):
        """Show modern settings interface."""
        self.clear_content()

        # Header
        title = tk.Label(self.content_frame, text="Settings",
                        font=('Segoe UI', 24, 'bold'),
                        bg=self.colors['bg'],
                        fg=self.colors['fg'])
        title.pack(pady=(0, 25))

        # Settings card
        settings_card = self.create_card(self.content_frame, padx=40, pady=35)
        settings_card.pack(fill='both', expand=True)

        # Vault statistics
        stats_section = tk.Label(settings_card, text="📊 Vault Statistics",
                                font=('Segoe UI', 16, 'bold'),
                                bg=self.colors['card_bg'],
                                fg=self.colors['fg'])
        stats_section.pack(anchor='w', pady=(0, 15))

        entries = self.vault.get_all_entries()
        stats = [
            f"Total Passwords: {len(entries)}",
            f"Categories: {len(self.vault.get_categories())}",
            f"Vault Location: {self.vault.vault_path}"
        ]

        for stat in stats:
            stat_label = tk.Label(settings_card, text=f"  • {stat}",
                                 font=('Segoe UI', 10),
                                 bg=self.colors['card_bg'],
                                 fg=self.colors['fg_light'])
            stat_label.pack(anchor='w', pady=2)

        # Separator
        sep = tk.Frame(settings_card, bg=self.colors['border'], height=1)
        sep.pack(fill='x', pady=25)

        # Security section
        security_section = tk.Label(settings_card, text="🔒 Security",
                                   font=('Segoe UI', 16, 'bold'),
                                   bg=self.colors['card_bg'],
                                   fg=self.colors['fg'])
        security_section.pack(anchor='w', pady=(0, 15))

        def change_password():
            dialog = tk.Toplevel(self.root)
            dialog.title("Change Master Password")
            dialog.geometry("450x350")
            dialog.transient(self.root)
            dialog.grab_set()
            dialog.config(bg=self.colors['bg'])

            main = tk.Frame(dialog, bg=self.colors['bg'], padx=30, pady=30)
            main.pack(fill='both', expand=True)

            card = self.create_card(main, padx=25, pady=25)
            card.pack(fill='both', expand=True)

            def create_pwd_field(label_text):
                lbl = tk.Label(card, text=label_text,
                             font=('Segoe UI', 10, 'bold'),
                             bg=self.colors['card_bg'])
                lbl.pack(anchor='w', pady=(10, 5))

                entry = tk.Entry(card, show='•',
                               font=('Segoe UI', 11),
                               bg=self.colors['input_bg'],
                               relief='solid',
                               borderwidth=1,
                               highlightthickness=2,
                               highlightbackground=self.colors['border'],
                               highlightcolor=self.colors['primary'])
                entry.pack(fill='x', ipady=8)
                return entry

            old_pw = create_pwd_field("Current Password")
            new_pw = create_pwd_field("New Password")
            confirm_pw = create_pwd_field("Confirm New Password")

            def save_new_password():
                if new_pw.get() != confirm_pw.get():
                    messagebox.showerror("Error", "New passwords don't match")
                    return

                if len(new_pw.get()) < 8:
                    messagebox.showerror("Error", "Password must be at least 8 characters")
                    return

                if self.vault.change_master_password(old_pw.get(), new_pw.get()):
                    self.show_toast("✓ Master password changed!")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Current password is incorrect")

            btn_frame = tk.Frame(card, bg=self.colors['card_bg'])
            btn_frame.pack(pady=20)

            save_btn = self.create_rounded_button(btn_frame, "Save",
                                                 save_new_password, 'primary')
            save_btn.pack(side='left', padx=5)

            cancel_btn = self.create_rounded_button(btn_frame, "Cancel",
                                                   dialog.destroy, 'secondary')
            cancel_btn.pack(side='left', padx=5)

        change_pwd_btn = self.create_rounded_button(settings_card,
                                                    "🔑 Change Master Password",
                                                    change_password, 'secondary')
        change_pwd_btn.pack(anchor='w', pady=10)

        # Separator
        sep2 = tk.Frame(settings_card, bg=self.colors['border'], height=1)
        sep2.pack(fill='x', pady=25)

        # Backup section
        backup_section = tk.Label(settings_card, text="💾 Backup & Export",
                                 font=('Segoe UI', 16, 'bold'),
                                 bg=self.colors['card_bg'],
                                 fg=self.colors['fg'])
        backup_section.pack(anchor='w', pady=(0, 15))

        def export_vault():
            filepath = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")]
            )
            if filepath:
                try:
                    self.vault.export_to_json(filepath, include_passwords=True)
                    self.show_toast("✓ Vault exported successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Export failed: {str(e)}")

        def import_vault():
            filepath = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json")]
            )
            if filepath:
                try:
                    self.vault.import_from_json(filepath)
                    self.show_toast("✓ Passwords imported successfully!")
                    self.refresh_password_list()
                except Exception as e:
                    messagebox.showerror("Error", f"Import failed: {str(e)}")

        export_btn = self.create_rounded_button(settings_card,
                                               "📤 Export Vault",
                                               export_vault, 'secondary')
        export_btn.pack(anchor='w', pady=5)

        import_btn = self.create_rounded_button(settings_card,
                                               "📥 Import Passwords",
                                               import_vault, 'secondary')
        import_btn.pack(anchor='w', pady=5)

    def lock_vault(self):
        """Lock the vault and return to login screen."""
        if messagebox.askyesno("Lock Vault", "Are you sure you want to lock the vault?"):
            if self.clipboard_timer:
                self.clipboard_timer.cancel()
            self.vault.lock_vault()
            self.show_login_screen()


def main():
    """Main entry point."""
    root = tk.Tk()
    app = ModernPasswordManagerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
