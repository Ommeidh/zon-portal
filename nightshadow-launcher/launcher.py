#!/usr/bin/env python3
"""
NightShadow Launcher
Zon Productions
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import requests
import os
import sys
import json
import zipfile
from pathlib import Path

# Configuration
API_URL = "https://zon-productions.com"
CONFIG_FILE = Path.home() / ".nightshadow" / "config.json"
INSTALL_DIR = Path.home() / ".nightshadow" / "game"

# Matrix theme colors
COLORS = {
    'bg': '#000000',
    'bg_dark': '#001100',
    'fg': '#00ff41',
    'fg_dim': '#008f11',
    'fg_bright': '#00ff41',
    'error': '#ff0040',
    'button_bg': '#001a00',
    'button_hover': '#003300',
    'entry_bg': '#000a00',
}


class MatrixStyle:
    """Apply Matrix theme to widgets."""

    @staticmethod
    def configure_root(root):
        root.configure(bg=COLORS['bg'])

    @staticmethod
    def label(parent, text="", **kwargs):
        kwargs.setdefault("bg", COLORS["bg"])
        kwargs.setdefault("fg", COLORS["fg"])
        kwargs.setdefault("font", ("Consolas", 10))
        return tk.Label(parent, text=text, **kwargs)

    @staticmethod
    def title(parent, text="", **kwargs):
        kwargs.setdefault("bg", COLORS["bg"])
        kwargs.setdefault("fg", COLORS["fg_bright"])
        kwargs.setdefault("font", ("Consolas", 16, "bold"))
        return tk.Label(parent, text=text, **kwargs)

    @staticmethod
    def subtitle(parent, text="", **kwargs):
        kwargs.setdefault("bg", COLORS["bg"])
        kwargs.setdefault("fg", COLORS["fg_dim"])
        kwargs.setdefault("font", ("Consolas", 9))
        return tk.Label(parent, text=text, **kwargs)

    @staticmethod
    def entry(parent, show=None, **kwargs):
        kwargs.setdefault("bg", COLORS["entry_bg"])
        kwargs.setdefault("fg", COLORS["fg"])
        kwargs.setdefault("insertbackground", COLORS["fg"])
        kwargs.setdefault("font", ("Consolas", 11))
        kwargs.setdefault("relief", "flat")
        kwargs.setdefault("highlightthickness", 1)
        kwargs.setdefault("highlightcolor", COLORS["fg"])
        kwargs.setdefault("highlightbackground", COLORS["fg_dim"])
        return tk.Entry(parent, show=show, **kwargs)

    @staticmethod
    def button(parent, text="", command=None, **kwargs):
        kwargs.setdefault("bg", COLORS["button_bg"])
        kwargs.setdefault("fg", COLORS["fg"])
        kwargs.setdefault("activebackground", COLORS["button_hover"])
        kwargs.setdefault("activeforeground", COLORS["fg_bright"])
        kwargs.setdefault("font", ("Consolas", 10, "bold"))
        kwargs.setdefault("relief", "flat")
        kwargs.setdefault("cursor", "hand2")
        kwargs.setdefault("padx", 20)
        kwargs.setdefault("pady", 8)
        kwargs.setdefault("highlightthickness", 1)
        kwargs.setdefault("highlightcolor", COLORS["fg"])
        kwargs.setdefault("highlightbackground", COLORS["fg_dim"])

        btn = tk.Button(parent, text=text, command=command, **kwargs)

        def on_enter(e):
            btn.configure(bg=COLORS["button_hover"])
        def on_leave(e):
            btn.configure(bg=COLORS["button_bg"])

        btn.bind("<Enter>", on_enter)
        btn.bind("<Leave>", on_leave)
        return btn

    @staticmethod
    def frame(parent, **kwargs):
        kwargs.setdefault("bg", COLORS["bg"])
        return tk.Frame(parent, **kwargs)
    """Apply Matrix theme to widgets."""
    
    @staticmethod
    def configure_root(root):
        root.configure(bg=COLORS['bg'])
        
    @staticmethod
    def label(parent, text="", **kwargs):
        fg = kwargs.pop("fg", COLORS["fg"])        # take fg out of kwargs if present
        bg = kwargs.pop("bg", COLORS["bg"])        # same for bg
        font = kwargs.pop("font", ("Consolas", 10))
        return tk.Label(parent, text=text, fg=fg, bg=bg, font=font, **kwargs)
    
    
    @staticmethod
    def title(parent, text="", **kwargs):
        return tk.Label(
            parent,
            text=text,
            bg=COLORS['bg'],
            fg=COLORS['fg_bright'],
            font=('Consolas', 16, 'bold'),
            **kwargs
        )
    
    @staticmethod
    def subtitle(parent, text="", **kwargs):
        return tk.Label(
            parent,
            text=text,
            bg=COLORS['bg'],
            fg=COLORS['fg_dim'],
            font=('Consolas', 9),
            **kwargs
        )
    
    @staticmethod
    def entry(parent, show=None, **kwargs):
        entry = tk.Entry(
            parent,
            bg=COLORS['entry_bg'],
            fg=COLORS['fg'],
            insertbackground=COLORS['fg'],
            font=('Consolas', 11),
            relief='flat',
            highlightthickness=1,
            highlightcolor=COLORS['fg'],
            highlightbackground=COLORS['fg_dim'],
            show=show,
            **kwargs
        )
        return entry
    
    @staticmethod
    def button(parent, text="", command=None, **kwargs):
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=COLORS['button_bg'],
            fg=COLORS['fg'],
            activebackground=COLORS['button_hover'],
            activeforeground=COLORS['fg_bright'],
            font=('Consolas', 10, 'bold'),
            relief='flat',
            cursor='hand2',
            padx=20,
            pady=8,
            highlightthickness=1,
            highlightcolor=COLORS['fg'],
            highlightbackground=COLORS['fg_dim'],
            **kwargs
        )
        
        def on_enter(e):
            btn.configure(bg=COLORS['button_hover'])
        def on_leave(e):
            btn.configure(bg=COLORS['button_bg'])
        
        btn.bind('<Enter>', on_enter)
        btn.bind('<Leave>', on_leave)
        
        return btn
    
    @staticmethod
    def frame(parent, **kwargs):
        return tk.Frame(parent, bg=COLORS['bg'], **kwargs)


class NightShadowLauncher:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("NightShadow Launcher")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        self.root.configure(bg=COLORS['bg'])
        
        # Center window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() - 500) // 2
        y = (self.root.winfo_screenheight() - 400) // 2
        self.root.geometry(f"500x400+{x}+{y}")
        
        # State
        self.logged_in = False
        self.username = None
        self.token = None
        self.game_info = None
        self.saved_email = None
        self.saved_password = None
        
        # Ensure directories exist
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        
        # Load saved credentials
        self.load_config()
        
        # Build UI
        self.build_ui()
        
        # Check for saved session
        if self.token:
            self.show_main_screen()
        else:
            self.show_login_screen()
    
    def load_config(self):
        """Load saved configuration."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    config = json.load(f)
                    self.token = config.get('token')
                    self.username = config.get('username')
                    self.saved_email = config.get('email')
                    self.saved_password = config.get('password')  # In production, use keyring
            except:
                self.saved_email = None
                self.saved_password = None
    
    def save_config(self, email=None, password=None):
        """Save configuration."""
        config = {
            'token': self.token,
            'username': self.username,
            'email': email or getattr(self, 'saved_email', None),
            'password': password or getattr(self, 'saved_password', None),
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)
    
    def clear_config(self):
        """Clear saved configuration."""
        self.token = None
        self.username = None
        self.saved_email = None
        self.saved_password = None
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
    
    def build_ui(self):
        """Build the main container."""
        self.main_frame = MatrixStyle.frame(self.root)
        self.main_frame.pack(fill='both', expand=True, padx=20, pady=20)
    
    def clear_frame(self):
        """Clear all widgets from main frame."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def show_login_screen(self):
        """Show login screen."""
        self.clear_frame()
        
        # Title
        MatrixStyle.title(self.main_frame, text="NIGHTSHADOW").pack(pady=(20, 0))
        MatrixStyle.subtitle(self.main_frame, text="// ZON PRODUCTIONS").pack(pady=(0, 30))
        
        # Login form
        form_frame = MatrixStyle.frame(self.main_frame)
        form_frame.pack(pady=20)
        
        # Email
        MatrixStyle.label(form_frame, text="EMAIL:").grid(row=0, column=0, sticky='w', pady=5)
        self.email_entry = MatrixStyle.entry(form_frame, width=30)
        self.email_entry.grid(row=0, column=1, pady=5, padx=(10, 0))
        
        # Password
        MatrixStyle.label(form_frame, text="PASSWORD:").grid(row=1, column=0, sticky='w', pady=5)
        self.password_entry = MatrixStyle.entry(form_frame, width=30, show="•")
        self.password_entry.grid(row=1, column=1, pady=5, padx=(10, 0))
        
        # Bind Enter key
        self.password_entry.bind('<Return>', lambda e: self.do_login())
        self.email_entry.bind('<Return>', lambda e: self.password_entry.focus())
        
        # Status label
        self.status_label = MatrixStyle.label(self.main_frame, text="")
        self.status_label.pack(pady=10)
        
        # Login button
        self.login_btn = MatrixStyle.button(self.main_frame, text="[AUTHENTICATE]", command=self.do_login)
        self.login_btn.pack(pady=20)
        
        # Register link
        register_label = MatrixStyle.label(
            self.main_frame, 
            text="No account? Register at zon-productions.com",
            fg=COLORS['fg_dim']
        )
        register_label.pack(pady=10)
        
        # Focus email field
        self.email_entry.focus()
    
    def do_login(self):
        """Perform login."""
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        
        if not email or not password:
            self.status_label.configure(text="Enter email and password", fg=COLORS['error'])
            return
        
        self.status_label.configure(text="Authenticating...", fg=COLORS['fg_dim'])
        self.login_btn.configure(state='disabled')
        self.root.update()
        
        def login_thread():
            try:
                response = requests.post(
                    f"{API_URL}/api/login",
                    json={'email': email, 'password': password},
                    timeout=10,
                    print("login status:", response.status_code)
                    print("content-type:", response.headers.get("Content-Type"))
                    print("len:", len(response.content))
                    print("head:", response.text[:200])

                )
                
                data = response.json()
                
                if data.get('success'):
                    if data.get('approved'):
                        self.token = data.get('token')
                        self.username = data.get('username')
                        self.saved_email = email
                        self.saved_password = password
                        self.save_config(email, password)
                        self.root.after(0, self.show_main_screen)
                    else:
                        self.root.after(0, lambda: self.status_label.configure(
                            text="Account pending admin approval",
                            fg=COLORS['error']
                        ))
                else:
                    error = data.get('error', 'Login failed')
                    self.root.after(0, lambda: self.status_label.configure(
                        text=error,
                        fg=COLORS['error']
                    ))
            except requests.exceptions.ConnectionError:
                self.root.after(0, lambda: self.status_label.configure(
                    text="Cannot connect to server",
                    fg=COLORS['error']
                ))
            except Exception as e:
                self.root.after(0, lambda: self.status_label.configure(
                    text=f"Error: {str(e)[:30]}",
                    fg=COLORS['error']
                ))
            finally:
                self.root.after(0, lambda: self.login_btn.configure(state='normal'))
        
        threading.Thread(target=login_thread, daemon=True).start()
    
    def show_main_screen(self):
        """Show main screen after login."""
        self.clear_frame()
        self.logged_in = True
        
        # Header
        header_frame = MatrixStyle.frame(self.main_frame)
        header_frame.pack(fill='x', pady=(10, 20))
        
        MatrixStyle.title(header_frame, text="NIGHTSHADOW").pack(side='left')
        
        # User info
        user_frame = MatrixStyle.frame(header_frame)
        user_frame.pack(side='right')
        MatrixStyle.label(user_frame, text=f"[{self.username}]", fg=COLORS['fg_dim']).pack(side='left')
        logout_btn = MatrixStyle.button(user_frame, text="LOGOUT", command=self.do_logout)
        logout_btn.configure(padx=10, pady=3, font=('Consolas', 8))
        logout_btn.pack(side='left', padx=(10, 0))
        
        # Separator
        sep = tk.Frame(self.main_frame, bg=COLORS['fg_dim'], height=1)
        sep.pack(fill='x', pady=10)
        
        # Game info section
        info_frame = MatrixStyle.frame(self.main_frame)
        info_frame.pack(fill='x', pady=20)
        
        MatrixStyle.label(info_frame, text="> GAME STATUS", fg=COLORS['fg_bright']).pack(anchor='w')
        
        self.game_status_label = MatrixStyle.label(info_frame, text="Checking...")
        self.game_status_label.pack(anchor='w', pady=(10, 0))
        
        self.game_size_label = MatrixStyle.label(info_frame, text="", fg=COLORS['fg_dim'])
        self.game_size_label.pack(anchor='w')
        
        self.game_updated_label = MatrixStyle.label(info_frame, text="", fg=COLORS['fg_dim'])
        self.game_updated_label.pack(anchor='w')
        
        # Progress bar
        self.progress_frame = MatrixStyle.frame(self.main_frame)
        self.progress_frame.pack(fill='x', pady=20)
        
        self.progress_label = MatrixStyle.label(self.progress_frame, text="")
        self.progress_label.pack(anchor='w')
        
        style = ttk.Style()
        style.theme_use('default')
        style.configure(
            "Matrix.Horizontal.TProgressbar",
            troughcolor=COLORS['bg_dark'],
            background=COLORS['fg'],
            darkcolor=COLORS['fg'],
            lightcolor=COLORS['fg'],
            bordercolor=COLORS['fg_dim'],
        )
        
        self.progress_bar = ttk.Progressbar(
            self.progress_frame,
            style="Matrix.Horizontal.TProgressbar",
            length=460,
            mode='determinate'
        )
        self.progress_bar.pack(pady=(5, 0))
        self.progress_bar.pack_forget()  # Hide initially
        
        # Buttons
        btn_frame = MatrixStyle.frame(self.main_frame)
        btn_frame.pack(pady=30)
        
        self.download_btn = MatrixStyle.button(btn_frame, text="[DOWNLOAD]", command=self.do_download)
        self.download_btn.pack(side='left', padx=5)
        
        self.play_btn = MatrixStyle.button(btn_frame, text="[PLAY]", command=self.do_play)
        self.play_btn.pack(side='left', padx=5)
        self.play_btn.configure(state='disabled')
        
        # Check game info
        self.refresh_game_info()
    
    def refresh_game_info(self):
        """Refresh game info from server."""
        def info_thread():
            try:
                response = requests.get(f"{API_URL}/api/game-info", timeout=10)
                data = response.json()
                
                if data.get('available'):
                    self.game_info = data
                    self.root.after(0, lambda: self.update_game_display(data))
                else:
                    self.root.after(0, lambda: self.game_status_label.configure(
                        text="Game not available",
                        fg=COLORS['error']
                    ))
            except Exception as e:
                self.root.after(0, lambda: self.game_status_label.configure(
                    text=f"Error: {str(e)[:30]}",
                    fg=COLORS['error']
                ))
        
        threading.Thread(target=info_thread, daemon=True).start()
    
    def update_game_display(self, data):
        """Update game info display."""
        self.game_status_label.configure(text="● AVAILABLE", fg=COLORS['fg_bright'])
        self.game_size_label.configure(text=f"Size: {data['size_formatted']}")
        
        # Parse and format date
        updated = data.get('last_updated', '')[:10]
        self.game_updated_label.configure(text=f"Updated: {updated}")
        
        # Check if game is installed
        game_exe = INSTALL_DIR / "NightShadow.exe"
        if game_exe.exists():
            self.play_btn.configure(state='normal')
            self.download_btn.configure(text="[UPDATE]")
    
    def do_download(self):
        """Download the game."""
        if not self.game_info:
            return
        
        if not self.saved_email or not self.saved_password:
            self.progress_label.configure(text="Please login again", fg=COLORS['error'])
            return
        
        self.download_btn.configure(state='disabled')
        self.progress_bar.pack(pady=(5, 0))
        self.progress_bar['value'] = 0
        self.progress_label.configure(text="Authenticating...")
        
        def download_thread():
            try:
                # Use API download with credentials
                response = requests.post(
                    f"{API_URL}/api/download",
                    json={
                        'email': self.saved_email,
                        'password': self.saved_password
                    },
                    stream=True,
                    timeout=30
                )
                
                if response.status_code == 401:
                    self.root.after(0, lambda: self.progress_label.configure(
                        text="Invalid credentials - please login again",
                        fg=COLORS['error']
                    ))
                    self.root.after(0, lambda: self.download_btn.configure(state='normal'))
                    self.root.after(0, self.do_logout)
                    return
                
                if response.status_code == 403:
                    self.root.after(0, lambda: self.progress_label.configure(
                        text="Account not approved",
                        fg=COLORS['error']
                    ))
                    self.root.after(0, lambda: self.download_btn.configure(state='normal'))
                    return
                
                if response.status_code != 200:
                    self.root.after(0, lambda: self.progress_label.configure(
                        text=f"Download failed: {response.status_code}",
                        fg=COLORS['error']
                    ))
                    self.root.after(0, lambda: self.download_btn.configure(state='normal'))
                    return
                
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                
                self.root.after(0, lambda: self.progress_label.configure(text="Downloading..."))
                
                zip_path = INSTALL_DIR / "NightShadow.zip"
                
                with open(zip_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=1024*1024):  # 1MB chunks
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            
                            if total_size > 0:
                                percent = (downloaded / total_size) * 100
                                downloaded_mb = downloaded / (1024*1024)
                                total_mb = total_size / (1024*1024)
                                
                                self.root.after(0, lambda p=percent, d=downloaded_mb, t=total_mb: self.update_progress(p, d, t))
                
                # Extract
                self.root.after(0, lambda: self.progress_label.configure(text="Extracting..."))
                
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(INSTALL_DIR)
                
                # Clean up zip
                zip_path.unlink()
                
                self.root.after(0, self.download_complete)
                
            except Exception as e:
                self.root.after(0, lambda: self.progress_label.configure(
                    text=f"Error: {str(e)[:40]}",
                    fg=COLORS['error']
                ))
                self.root.after(0, lambda: self.download_btn.configure(state='normal'))
        
        threading.Thread(target=download_thread, daemon=True).start()
    
    def update_progress(self, percent, downloaded, total):
        """Update progress bar."""
        self.progress_bar['value'] = percent
        self.progress_label.configure(
            text=f"Downloading: {downloaded:.0f} MB / {total:.0f} MB ({percent:.1f}%)"
        )
    
    def download_complete(self):
        """Called when download is complete."""
        self.progress_label.configure(text="Download complete!", fg=COLORS['fg_bright'])
        self.progress_bar['value'] = 100
        self.download_btn.configure(state='normal', text="[UPDATE]")
        self.play_btn.configure(state='normal')
    
    def do_play(self):
        """Launch the game."""
        # Look for common executable names
        possible_exes = [
            INSTALL_DIR / "NightShadow.exe",
            INSTALL_DIR / "nightshadow.exe",
            INSTALL_DIR / "Game.exe",
        ]
        
        # Also check subdirectories
        for subdir in INSTALL_DIR.iterdir():
            if subdir.is_dir():
                possible_exes.extend([
                    subdir / "NightShadow.exe",
                    subdir / "nightshadow.exe",
                    subdir / "Game.exe",
                ])
        
        for exe in possible_exes:
            if exe.exists():
                os.startfile(str(exe))
                return
        
        # If no exe found, just open the install directory
        messagebox.showinfo(
            "Game Files",
            f"Game files are located at:\n{INSTALL_DIR}\n\nPlease locate and run the game executable."
        )
        os.startfile(str(INSTALL_DIR))
    
    def do_logout(self):
        """Logout and return to login screen."""
        self.clear_config()
        self.logged_in = False
        self.show_login_screen()
    
    def run(self):
        """Run the application."""
        self.root.mainloop()


def main():
    app = NightShadowLauncher()
    app.run()


if __name__ == "__main__":
    main()
