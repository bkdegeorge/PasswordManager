"""
Desktop GUI for password manager using tkinter.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pyperclip
import threading
from datetime import datetime
from .vault import PasswordVault, PasswordEntry
from .password_generator import PasswordGenerator
from .password_strength import PasswordStrengthAnalyzer


class PasswordManagerGUI:
    """Main GUI application for password manager."""

    def __init__(self, root):
        self.root = root
        self.root.title("SecureVault - Password Manager")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)

        self.vault = PasswordVault()
        self.generator = PasswordGenerator()
        self.analyzer = PasswordStrengthAnalyzer()

        self.clipboard_timer = None
        self.current_entries = []

        # Configure colors
        self.colors = {
            'bg': '#f0f0f0',
            'fg': '#333333',
            'primary': '#4a90e2',
            'success': '#5cb85c',
            'danger': '#d9534f',
            'warning': '#f0ad4e',
            'sidebar': '#2c3e50',
            'sidebar_fg': '#ecf0f1'
        }

        self.setup_styles()
        self.show_login_screen()

    def setup_styles(self):
        """Configure ttk styles."""
        style = ttk.Style()
        style.theme_use('clam')

        # Configure button styles
        style.configure('Primary.TButton',
                       background=self.colors['primary'],
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       padding=10)

        style.map('Primary.TButton',
                 background=[('active', '#357abd')])

        style.configure('Danger.TButton',
                       background=self.colors['danger'],
                       foreground='white',
                       borderwidth=0,
                       padding=10)

        style.configure('Success.TButton',
                       background=self.colors['success'],
                       foreground='white',
                       borderwidth=0,
                       padding=10)

    def clear_window(self):
        """Clear all widgets from window."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        """Display login/create vault screen."""
        self.clear_window()

        # Center frame
        center_frame = tk.Frame(self.root, bg=self.colors['bg'])
        center_frame.place(relx=0.5, rely=0.5, anchor='center')

        # Title
        title = tk.Label(center_frame, text="SecureVault",
                        font=('Arial', 32, 'bold'),
                        bg=self.colors['bg'],
                        fg=self.colors['primary'])
        title.pack(pady=20)

        subtitle = tk.Label(center_frame, text="Password Manager",
                          font=('Arial', 14),
                          bg=self.colors['bg'],
                          fg=self.colors['fg'])
        subtitle.pack(pady=5)

        # Master password entry
        tk.Label(center_frame, text="Master Password:",
                font=('Arial', 12),
                bg=self.colors['bg']).pack(pady=(30, 5))

        self.master_password_entry = tk.Entry(center_frame, show='*',
                                              font=('Arial', 12), width=30)
        self.master_password_entry.pack(pady=5)
        self.master_password_entry.bind('<Return>', lambda e: self.unlock_vault())

        # Buttons frame
        button_frame = tk.Frame(center_frame, bg=self.colors['bg'])
        button_frame.pack(pady=20)

        unlock_btn = ttk.Button(button_frame, text="Unlock Vault",
                               style='Primary.TButton',
                               command=self.unlock_vault)
        unlock_btn.pack(side='left', padx=5)

        create_btn = ttk.Button(button_frame, text="Create New Vault",
                               style='Success.TButton',
                               command=self.create_vault)
        create_btn.pack(side='left', padx=5)

    def create_vault(self):
        """Create a new vault."""
        password = self.master_password_entry.get()

        if not password:
            messagebox.showerror("Error", "Please enter a master password")
            return

        if len(password) < 8:
            messagebox.showerror("Error", "Master password must be at least 8 characters")
            return

        # Confirm password
        confirm_password = tk.simpledialog.askstring(
            "Confirm Password",
            "Re-enter master password:",
            show='*'
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
        """Display main password manager interface."""
        self.clear_window()

        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg'])
        main_container.pack(fill='both', expand=True)

        # Sidebar
        self.create_sidebar(main_container)

        # Content area
        self.content_frame = tk.Frame(main_container, bg=self.colors['bg'])
        self.content_frame.pack(side='left', fill='both', expand=True)

        # Show passwords view by default
        self.show_passwords_view()

    def create_sidebar(self, parent):
        """Create sidebar navigation."""
        sidebar = tk.Frame(parent, bg=self.colors['sidebar'], width=200)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)

        # Title
        title = tk.Label(sidebar, text="SecureVault",
                        font=('Arial', 16, 'bold'),
                        bg=self.colors['sidebar'],
                        fg=self.colors['sidebar_fg'])
        title.pack(pady=20)

        # Navigation buttons
        nav_buttons = [
            ("Passwords", self.show_passwords_view),
            ("Add Password", self.show_add_password_view),
            ("Generate Password", self.show_generator_view),
            ("Settings", self.show_settings_view),
        ]

        for text, command in nav_buttons:
            btn = tk.Button(sidebar, text=text,
                          command=command,
                          bg=self.colors['sidebar'],
                          fg=self.colors['sidebar_fg'],
                          activebackground='#34495e',
                          activeforeground='white',
                          relief='flat',
                          font=('Arial', 11),
                          pady=15,
                          cursor='hand2')
            btn.pack(fill='x', padx=10, pady=5)

        # Lock button at bottom
        lock_btn = tk.Button(sidebar, text="🔒 Lock Vault",
                            command=self.lock_vault,
                            bg=self.colors['danger'],
                            fg='white',
                            activebackground='#c9302c',
                            relief='flat',
                            font=('Arial', 11, 'bold'),
                            pady=15,
                            cursor='hand2')
        lock_btn.pack(side='bottom', fill='x', padx=10, pady=20)

    def clear_content(self):
        """Clear content area."""
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def show_passwords_view(self):
        """Display list of all passwords."""
        self.clear_content()

        # Header
        header_frame = tk.Frame(self.content_frame, bg=self.colors['bg'])
        header_frame.pack(fill='x', padx=20, pady=20)

        title = tk.Label(header_frame, text="Your Passwords",
                        font=('Arial', 20, 'bold'),
                        bg=self.colors['bg'])
        title.pack(side='left')

        # Search bar
        search_frame = tk.Frame(header_frame, bg=self.colors['bg'])
        search_frame.pack(side='right')

        tk.Label(search_frame, text="Search:", bg=self.colors['bg']).pack(side='left')
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_passwords)
        search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                              font=('Arial', 11), width=30)
        search_entry.pack(side='left', padx=5)

        # Passwords list
        list_frame = tk.Frame(self.content_frame, bg='white')
        list_frame.pack(fill='both', expand=True, padx=20, pady=10)

        # Scrollbar
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side='right', fill='y')

        # Canvas for scrolling
        self.password_canvas = tk.Canvas(list_frame, bg='white',
                                        yscrollcommand=scrollbar.set)
        self.password_canvas.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.password_canvas.yview)

        # Inner frame
        self.password_list_frame = tk.Frame(self.password_canvas, bg='white')
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

    def refresh_password_list(self, entries=None):
        """Refresh the password list display."""
        # Clear existing
        for widget in self.password_list_frame.winfo_children():
            widget.destroy()

        if entries is None:
            entries = self.vault.get_all_entries()

        self.current_entries = entries

        if not entries:
            no_entries = tk.Label(self.password_list_frame,
                                text="No passwords yet. Click 'Add Password' to get started!",
                                font=('Arial', 12),
                                bg='white',
                                fg='gray')
            no_entries.pack(pady=50)
            return

        for entry in sorted(entries, key=lambda x: x.title.lower()):
            self.create_password_card(entry)

    def create_password_card(self, entry: PasswordEntry):
        """Create a card widget for a password entry."""
        card = tk.Frame(self.password_list_frame, bg='white',
                       relief='solid', borderwidth=1)
        card.pack(fill='x', padx=10, pady=5)

        # Left side - info
        info_frame = tk.Frame(card, bg='white')
        info_frame.pack(side='left', fill='both', expand=True, padx=15, pady=10)

        title = tk.Label(info_frame, text=entry.title,
                        font=('Arial', 14, 'bold'),
                        bg='white', anchor='w')
        title.pack(fill='x')

        username = tk.Label(info_frame, text=f"Username: {entry.username}",
                          font=('Arial', 10),
                          bg='white', fg='gray', anchor='w')
        username.pack(fill='x')

        if entry.url:
            url = tk.Label(info_frame, text=f"URL: {entry.url}",
                          font=('Arial', 9),
                          bg='white', fg='blue', anchor='w')
            url.pack(fill='x')

        # Category badge
        category = tk.Label(info_frame, text=entry.category,
                          font=('Arial', 8),
                          bg=self.colors['primary'], fg='white',
                          padx=8, pady=2)
        category.pack(side='left', pady=(5, 0))

        # Right side - actions
        action_frame = tk.Frame(card, bg='white')
        action_frame.pack(side='right', padx=10, pady=10)

        copy_btn = tk.Button(action_frame, text="📋 Copy",
                           command=lambda: self.copy_password(entry.password),
                           bg=self.colors['primary'], fg='white',
                           relief='flat', padx=10, pady=5,
                           cursor='hand2')
        copy_btn.pack(side='left', padx=2)

        view_btn = tk.Button(action_frame, text="👁 View",
                           command=lambda: self.view_entry(entry),
                           bg=self.colors['success'], fg='white',
                           relief='flat', padx=10, pady=5,
                           cursor='hand2')
        view_btn.pack(side='left', padx=2)

        delete_btn = tk.Button(action_frame, text="🗑 Delete",
                             command=lambda: self.delete_entry(entry),
                             bg=self.colors['danger'], fg='white',
                             relief='flat', padx=10, pady=5,
                             cursor='hand2')
        delete_btn.pack(side='left', padx=2)

    def filter_passwords(self, *args):
        """Filter passwords based on search query."""
        query = self.search_var.get()
        if not query:
            self.refresh_password_list()
        else:
            results = self.vault.search_entries(query)
            self.refresh_password_list(results)

    def copy_password(self, password: str):
        """Copy password to clipboard with auto-clear."""
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!\nWill auto-clear in 30 seconds.")

        # Auto-clear after 30 seconds
        if self.clipboard_timer:
            self.clipboard_timer.cancel()

        def clear_clipboard():
            if pyperclip.paste() == password:
                pyperclip.copy('')

        self.clipboard_timer = threading.Timer(30.0, clear_clipboard)
        self.clipboard_timer.start()

    def view_entry(self, entry: PasswordEntry):
        """View/edit entry details."""
        dialog = tk.Toplevel(self.root)
        dialog.title(f"View/Edit: {entry.title}")
        dialog.geometry("500x600")
        dialog.transient(self.root)
        dialog.grab_set()

        # Form
        form_frame = tk.Frame(dialog, bg='white', padx=20, pady=20)
        form_frame.pack(fill='both', expand=True)

        fields = {}

        # Title
        tk.Label(form_frame, text="Title:", font=('Arial', 10, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))
        fields['title'] = tk.Entry(form_frame, font=('Arial', 11), width=40)
        fields['title'].insert(0, entry.title)
        fields['title'].pack(fill='x', pady=(0, 15))

        # Username
        tk.Label(form_frame, text="Username:", font=('Arial', 10, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))
        fields['username'] = tk.Entry(form_frame, font=('Arial', 11), width=40)
        fields['username'].insert(0, entry.username)
        fields['username'].pack(fill='x', pady=(0, 15))

        # Password
        tk.Label(form_frame, text="Password:", font=('Arial', 10, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))

        password_frame = tk.Frame(form_frame, bg='white')
        password_frame.pack(fill='x', pady=(0, 15))

        fields['password'] = tk.Entry(password_frame, font=('Arial', 11), show='*')
        fields['password'].insert(0, entry.password)
        fields['password'].pack(side='left', fill='x', expand=True)

        show_var = tk.BooleanVar()
        def toggle_password():
            fields['password'].config(show='' if show_var.get() else '*')

        show_check = tk.Checkbutton(password_frame, text="Show",
                                   variable=show_var, command=toggle_password,
                                   bg='white')
        show_check.pack(side='left', padx=5)

        # URL
        tk.Label(form_frame, text="URL:", font=('Arial', 10, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))
        fields['url'] = tk.Entry(form_frame, font=('Arial', 11), width=40)
        fields['url'].insert(0, entry.url)
        fields['url'].pack(fill='x', pady=(0, 15))

        # Category
        tk.Label(form_frame, text="Category:", font=('Arial', 10, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))
        categories = self.vault.get_categories() + ['General', 'Work', 'Personal', 'Finance']
        fields['category'] = ttk.Combobox(form_frame, values=sorted(set(categories)),
                                         font=('Arial', 11))
        fields['category'].set(entry.category)
        fields['category'].pack(fill='x', pady=(0, 15))

        # Notes
        tk.Label(form_frame, text="Notes:", font=('Arial', 10, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))
        fields['notes'] = tk.Text(form_frame, font=('Arial', 10),
                                 height=5, width=40)
        fields['notes'].insert('1.0', entry.notes)
        fields['notes'].pack(fill='x', pady=(0, 15))

        # Buttons
        button_frame = tk.Frame(form_frame, bg='white')
        button_frame.pack(pady=20)

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
            messagebox.showinfo("Success", "Entry updated successfully!")
            dialog.destroy()
            self.refresh_password_list()

        save_btn = ttk.Button(button_frame, text="Save Changes",
                             style='Primary.TButton',
                             command=save_changes)
        save_btn.pack(side='left', padx=5)

        cancel_btn = ttk.Button(button_frame, text="Cancel",
                               command=dialog.destroy)
        cancel_btn.pack(side='left', padx=5)

    def delete_entry(self, entry: PasswordEntry):
        """Delete a password entry."""
        if messagebox.askyesno("Confirm Delete",
                              f"Are you sure you want to delete '{entry.title}'?"):
            self.vault.delete_entry(entry.id)
            messagebox.showinfo("Success", "Entry deleted successfully!")
            self.refresh_password_list()

    def show_add_password_view(self):
        """Show form to add new password."""
        self.clear_content()

        # Header
        title = tk.Label(self.content_frame, text="Add New Password",
                        font=('Arial', 20, 'bold'),
                        bg=self.colors['bg'])
        title.pack(pady=20)

        # Form
        form_frame = tk.Frame(self.content_frame, bg='white',
                             relief='solid', borderwidth=1)
        form_frame.pack(fill='both', expand=True, padx=50, pady=20)

        inner_frame = tk.Frame(form_frame, bg='white', padx=30, pady=30)
        inner_frame.pack(fill='both', expand=True)

        fields = {}

        # Title
        tk.Label(inner_frame, text="Title:*", font=('Arial', 11, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))
        fields['title'] = tk.Entry(inner_frame, font=('Arial', 12), width=50)
        fields['title'].pack(fill='x', pady=(0, 15))

        # Username
        tk.Label(inner_frame, text="Username:*", font=('Arial', 11, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))
        fields['username'] = tk.Entry(inner_frame, font=('Arial', 12), width=50)
        fields['username'].pack(fill='x', pady=(0, 15))

        # Password with generator
        tk.Label(inner_frame, text="Password:*", font=('Arial', 11, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))

        password_frame = tk.Frame(inner_frame, bg='white')
        password_frame.pack(fill='x', pady=(0, 15))

        fields['password'] = tk.Entry(password_frame, font=('Arial', 12), show='*')
        fields['password'].pack(side='left', fill='x', expand=True)

        def generate_and_fill():
            pw = self.generator.generate_password(16, True, True, True, True)
            fields['password'].delete(0, 'end')
            fields['password'].insert(0, pw)
            analyze_strength()

        gen_btn = tk.Button(password_frame, text="Generate",
                          command=generate_and_fill,
                          bg=self.colors['success'], fg='white',
                          relief='flat', padx=10, cursor='hand2')
        gen_btn.pack(side='left', padx=5)

        # Password strength indicator
        strength_frame = tk.Frame(inner_frame, bg='white')
        strength_frame.pack(fill='x', pady=(0, 15))

        strength_label = tk.Label(strength_frame, text="Strength: ",
                                 font=('Arial', 10), bg='white')
        strength_label.pack(side='left')

        strength_value = tk.Label(strength_frame, text="Not analyzed",
                                 font=('Arial', 10, 'bold'), bg='white')
        strength_value.pack(side='left')

        def analyze_strength(*args):
            password = fields['password'].get()
            if password:
                analysis = self.analyzer.analyze(password)
                color = self.analyzer.get_strength_color(analysis['score'])
                strength_value.config(
                    text=f"{analysis['strength']} ({analysis['score']}/100)",
                    fg=color
                )
            else:
                strength_value.config(text="Not analyzed", fg='gray')

        fields['password'].bind('<KeyRelease>', analyze_strength)

        # URL
        tk.Label(inner_frame, text="URL:", font=('Arial', 11, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))
        fields['url'] = tk.Entry(inner_frame, font=('Arial', 12), width=50)
        fields['url'].pack(fill='x', pady=(0, 15))

        # Category
        tk.Label(inner_frame, text="Category:", font=('Arial', 11, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))
        categories = ['General', 'Work', 'Personal', 'Finance', 'Social Media',
                     'Email', 'Shopping', 'Entertainment']
        fields['category'] = ttk.Combobox(inner_frame, values=categories,
                                         font=('Arial', 12))
        fields['category'].set('General')
        fields['category'].pack(fill='x', pady=(0, 15))

        # Notes
        tk.Label(inner_frame, text="Notes:", font=('Arial', 11, 'bold'),
                bg='white').pack(anchor='w', pady=(0, 5))
        fields['notes'] = tk.Text(inner_frame, font=('Arial', 11),
                                 height=4, width=50)
        fields['notes'].pack(fill='x', pady=(0, 15))

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
                category=fields['category'].get()
            )

            self.vault.add_entry(entry)
            messagebox.showinfo("Success", "Password saved successfully!")
            self.show_passwords_view()

        save_btn = ttk.Button(inner_frame, text="Save Password",
                             style='Primary.TButton',
                             command=save_entry)
        save_btn.pack(pady=20)

    def show_generator_view(self):
        """Show password generator interface."""
        self.clear_content()

        # Header
        title = tk.Label(self.content_frame, text="Password Generator",
                        font=('Arial', 20, 'bold'),
                        bg=self.colors['bg'])
        title.pack(pady=20)

        # Generator frame
        gen_frame = tk.Frame(self.content_frame, bg='white',
                            relief='solid', borderwidth=1)
        gen_frame.pack(fill='both', expand=True, padx=50, pady=20)

        inner = tk.Frame(gen_frame, bg='white', padx=30, pady=30)
        inner.pack(fill='both', expand=True)

        # Tabs for password vs passphrase
        tab_frame = tk.Frame(inner, bg='white')
        tab_frame.pack(fill='x', pady=(0, 20))

        current_tab = tk.StringVar(value='password')

        def show_password_tab():
            current_tab.set('password')
            passphrase_options.pack_forget()
            password_options.pack(fill='x', pady=20)
            generate()

        def show_passphrase_tab():
            current_tab.set('passphrase')
            password_options.pack_forget()
            passphrase_options.pack(fill='x', pady=20)
            generate()

        password_tab = tk.Button(tab_frame, text="Password",
                                command=show_password_tab,
                                bg=self.colors['primary'], fg='white',
                                relief='flat', padx=20, pady=10,
                                font=('Arial', 11, 'bold'))
        password_tab.pack(side='left', padx=5)

        passphrase_tab = tk.Button(tab_frame, text="Passphrase",
                                   command=show_passphrase_tab,
                                   bg='lightgray', fg='black',
                                   relief='flat', padx=20, pady=10,
                                   font=('Arial', 11))
        passphrase_tab.pack(side='left', padx=5)

        # Result display
        result_frame = tk.Frame(inner, bg='#f9f9f9', relief='solid',
                               borderwidth=1, padx=20, pady=20)
        result_frame.pack(fill='x', pady=20)

        result_var = tk.StringVar(value="Click 'Generate' to create a password")
        result_label = tk.Label(result_frame, textvariable=result_var,
                               font=('Courier', 14), bg='#f9f9f9',
                               wraplength=600)
        result_label.pack()

        # Password options
        password_options = tk.Frame(inner, bg='white')

        length_var = tk.IntVar(value=16)
        upper_var = tk.BooleanVar(value=True)
        lower_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        symbols_var = tk.BooleanVar(value=True)

        tk.Label(password_options, text="Length:", bg='white',
                font=('Arial', 11)).pack(anchor='w')
        length_scale = tk.Scale(password_options, from_=8, to=64,
                               variable=length_var, orient='horizontal',
                               length=400, bg='white')
        length_scale.pack(fill='x', pady=5)

        tk.Checkbutton(password_options, text="Uppercase (A-Z)",
                      variable=upper_var, bg='white',
                      font=('Arial', 10)).pack(anchor='w', pady=2)
        tk.Checkbutton(password_options, text="Lowercase (a-z)",
                      variable=lower_var, bg='white',
                      font=('Arial', 10)).pack(anchor='w', pady=2)
        tk.Checkbutton(password_options, text="Digits (0-9)",
                      variable=digits_var, bg='white',
                      font=('Arial', 10)).pack(anchor='w', pady=2)
        tk.Checkbutton(password_options, text="Symbols (!@#$...)",
                      variable=symbols_var, bg='white',
                      font=('Arial', 10)).pack(anchor='w', pady=2)

        # Passphrase options
        passphrase_options = tk.Frame(inner, bg='white')

        words_var = tk.IntVar(value=6)
        separator_var = tk.StringVar(value='-')
        capitalize_var = tk.BooleanVar(value=True)
        number_var = tk.BooleanVar(value=True)

        tk.Label(passphrase_options, text="Number of words:", bg='white',
                font=('Arial', 11)).pack(anchor='w')
        words_scale = tk.Scale(passphrase_options, from_=3, to=10,
                              variable=words_var, orient='horizontal',
                              length=400, bg='white')
        words_scale.pack(fill='x', pady=5)

        tk.Label(passphrase_options, text="Separator:", bg='white',
                font=('Arial', 11)).pack(anchor='w', pady=(10, 0))
        sep_frame = tk.Frame(passphrase_options, bg='white')
        sep_frame.pack(anchor='w')
        for sep in ['-', '_', ' ', '.', '']:
            tk.Radiobutton(sep_frame, text=f"'{sep}'" if sep else "'none'",
                          variable=separator_var, value=sep,
                          bg='white', font=('Arial', 10)).pack(side='left', padx=5)

        tk.Checkbutton(passphrase_options, text="Capitalize words",
                      variable=capitalize_var, bg='white',
                      font=('Arial', 10)).pack(anchor='w', pady=2)
        tk.Checkbutton(passphrase_options, text="Add number at end",
                      variable=number_var, bg='white',
                      font=('Arial', 10)).pack(anchor='w', pady=2)

        password_options.pack(fill='x', pady=20)

        # Strength indicator
        strength_frame = tk.Frame(inner, bg='white')
        strength_frame.pack(fill='x', pady=10)

        strength_label = tk.Label(strength_frame, text="Strength: ",
                                 font=('Arial', 11), bg='white')
        strength_label.pack(side='left')

        strength_value = tk.Label(strength_frame, text="",
                                 font=('Arial', 11, 'bold'), bg='white')
        strength_value.pack(side='left')

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

                # Analyze strength
                analysis = self.analyzer.analyze(generated)
                color = self.analyzer.get_strength_color(analysis['score'])
                strength_value.config(
                    text=f"{analysis['strength']} ({analysis['score']}/100)",
                    fg=color
                )

            except ValueError as e:
                messagebox.showerror("Error", str(e))

        # Buttons
        button_frame = tk.Frame(inner, bg='white')
        button_frame.pack(pady=20)

        gen_btn = ttk.Button(button_frame, text="🔄 Generate",
                            style='Primary.TButton',
                            command=generate)
        gen_btn.pack(side='left', padx=5)

        copy_btn = ttk.Button(button_frame, text="📋 Copy",
                             style='Success.TButton',
                             command=lambda: self.copy_password(result_var.get()))
        copy_btn.pack(side='left', padx=5)

    def show_settings_view(self):
        """Show settings and vault management."""
        self.clear_content()

        # Header
        title = tk.Label(self.content_frame, text="Settings",
                        font=('Arial', 20, 'bold'),
                        bg=self.colors['bg'])
        title.pack(pady=20)

        # Settings frame
        settings_frame = tk.Frame(self.content_frame, bg='white',
                                 relief='solid', borderwidth=1)
        settings_frame.pack(fill='both', expand=True, padx=50, pady=20)

        inner = tk.Frame(settings_frame, bg='white', padx=30, pady=30)
        inner.pack(fill='both', expand=True)

        # Vault statistics
        tk.Label(inner, text="Vault Statistics",
                font=('Arial', 14, 'bold'), bg='white').pack(anchor='w', pady=(0, 10))

        entries = self.vault.get_all_entries()
        stats_text = f"""
        Total Passwords: {len(entries)}
        Categories: {len(self.vault.get_categories())}
        Vault Location: {self.vault.vault_path}
        """

        stats = tk.Label(inner, text=stats_text, font=('Arial', 10),
                        bg='white', justify='left')
        stats.pack(anchor='w', pady=(0, 20))

        # Change master password
        tk.Label(inner, text="Change Master Password",
                font=('Arial', 14, 'bold'), bg='white').pack(anchor='w', pady=(20, 10))

        def change_password():
            dialog = tk.Toplevel(self.root)
            dialog.title("Change Master Password")
            dialog.geometry("400x300")
            dialog.transient(self.root)

            frame = tk.Frame(dialog, bg='white', padx=20, pady=20)
            frame.pack(fill='both', expand=True)

            tk.Label(frame, text="Current Password:", bg='white').pack(anchor='w')
            old_pw = tk.Entry(frame, show='*', font=('Arial', 11), width=30)
            old_pw.pack(fill='x', pady=(0, 10))

            tk.Label(frame, text="New Password:", bg='white').pack(anchor='w')
            new_pw = tk.Entry(frame, show='*', font=('Arial', 11), width=30)
            new_pw.pack(fill='x', pady=(0, 10))

            tk.Label(frame, text="Confirm New Password:", bg='white').pack(anchor='w')
            confirm_pw = tk.Entry(frame, show='*', font=('Arial', 11), width=30)
            confirm_pw.pack(fill='x', pady=(0, 20))

            def save_new_password():
                if new_pw.get() != confirm_pw.get():
                    messagebox.showerror("Error", "New passwords don't match")
                    return

                if len(new_pw.get()) < 8:
                    messagebox.showerror("Error", "Password must be at least 8 characters")
                    return

                if self.vault.change_master_password(old_pw.get(), new_pw.get()):
                    messagebox.showinfo("Success", "Master password changed successfully!")
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Current password is incorrect")

            ttk.Button(frame, text="Change Password",
                      style='Primary.TButton',
                      command=save_new_password).pack()

        change_btn = ttk.Button(inner, text="Change Master Password",
                               command=change_password)
        change_btn.pack(anchor='w', pady=5)

        # Export/Import
        tk.Label(inner, text="Backup & Restore",
                font=('Arial', 14, 'bold'), bg='white').pack(anchor='w', pady=(20, 10))

        def export_vault():
            filepath = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")]
            )
            if filepath:
                try:
                    self.vault.export_to_json(filepath, include_passwords=True)
                    messagebox.showinfo("Success", "Vault exported successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Export failed: {str(e)}")

        def import_vault():
            filepath = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json")]
            )
            if filepath:
                try:
                    self.vault.import_from_json(filepath)
                    messagebox.showinfo("Success", "Passwords imported successfully!")
                    self.refresh_password_list()
                except Exception as e:
                    messagebox.showerror("Error", f"Import failed: {str(e)}")

        export_btn = ttk.Button(inner, text="Export Vault (JSON)",
                               command=export_vault)
        export_btn.pack(anchor='w', pady=5)

        import_btn = ttk.Button(inner, text="Import from JSON",
                               command=import_vault)
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
    app = PasswordManagerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
