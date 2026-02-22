import socket
import ssl
import threading
import json
import sys
import subprocess
import tkinter as tk
from tkinter import simpledialog, messagebox, Menu, ttk
import pyaudio
import os
from datetime import datetime
import hashlib
import random
from pynput import keyboard, mouse

# Tray icon support — requires: pip install pystray pillow
try:
    import pystray
    from PIL import Image
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False
    print("pystray/Pillow not installed — system tray disabled. Run: pip install pystray pillow")

# ---------- Configuration ----------
SERVER_TCP_PORT = 5000
SERVER_UDP_PORT = 5001
CONFIG_FILE = 'haven_config.json'
THEMES_DIR  = 'themes'
ICON_FILE   = os.path.join(THEMES_DIR, 'haven.ico')
MAX_TCP_BUFFER = 65536
# -----------------------------------

# Audio settings
CHUNK = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 1
SUPPORTED_RATES = [44100, 48000, 32000, 24000, 16000, 8000]
DEFAULT_RATE = 44100

USER_COLOR_PALETTE = [
    '#ff006e', '#ff4d6d', '#ff6b9d', '#ff8fab',
    '#00ff88', '#06ffa5', '#4ecca3', '#78e08f',
    '#8338ec', '#a855f7', '#c084fc', '#e0aaff',
    '#ffd60a', '#ffb703', '#fb8500', '#ff9500',
    '#06d6a0', '#00b4d8', '#0096c7', '#48cae4',
    '#f72585', '#b5179e', '#7209b7', '#560bad'
]


# ═══════════════════════════════════════════════════════════════════════════════
# TLS helper
# ═══════════════════════════════════════════════════════════════════════════════

def create_tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ═══════════════════════════════════════════════════════════════════════════════
# Challenge-response auth helpers
# ═══════════════════════════════════════════════════════════════════════════════

def compute_password_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

def compute_auth_response(nonce, password_hash):
    return hashlib.sha256(f"{nonce}:{password_hash}".encode()).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════════
# Tray icon helpers
# ═══════════════════════════════════════════════════════════════════════════════

def load_tray_image():
    """
    Load haven.ico from the themes folder as a PIL Image for pystray.
    Falls back to a simple generated icon if the file is missing.
    """
    if TRAY_AVAILABLE:
        if os.path.exists(ICON_FILE):
            try:
                return Image.open(ICON_FILE).convert('RGBA')
            except Exception as e:
                print(f"Could not load tray icon from file: {e}")
        # Fallback: generate a simple coloured circle
        img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
        try:
            from PIL import ImageDraw
            draw = ImageDraw.Draw(img)
            draw.ellipse([4, 4, 60, 60], fill='#00ff88', outline='#06ffa5', width=3)
            draw.ellipse([20, 20, 44, 44], fill='#0a0a1a')
        except Exception:
            pass
        return img
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Theme loader
# ═══════════════════════════════════════════════════════════════════════════════

def load_theme(theme_name='default'):
    path = os.path.join(THEMES_DIR, f'{theme_name}.json')
    if not os.path.exists(path):
        path = os.path.join(THEMES_DIR, 'default.json')
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load theme '{theme_name}': {e}. Using built-in fallback.")
        return _fallback_theme()

def list_themes():
    if not os.path.exists(THEMES_DIR):
        return ['default']
    names = []
    for f in sorted(os.listdir(THEMES_DIR)):
        if f.endswith('.json'):
            names.append(f[:-5])
    return names if names else ['default']

def _fallback_theme():
    return {
        "name": "Fallback",
        "bg_color": "#0a0a1a", "glass_bg": "#1a1a2e", "glass_accent": "#16213e",
        "fg_color": "#eeeeee", "accent_1": "#00ff88", "accent_2": "#ff006e",
        "accent_3": "#8338ec", "accent_4": "#06ffa5",
        "chat_bg": "#1a1a2e", "chat_fg": "#eeeeee", "chat_font": "Consolas", "chat_font_size": 10,
        "entry_bg": "#0a0a1a", "entry_fg": "#eeeeee",
        "userlist_bg": "#16213e", "userlist_card_bg": "#0a0a1a",
        "titlebar_bg": "#16213e", "titlebar_fg": "#eeeeee", "titlebar_sep": "#06ffa5",
        "scrollbar_bg": "#16213e", "scrollbar_trough": "#0a0a1a",
        "send_btn_bg": "#00ff88", "send_btn_fg": "#000000",
        "voice_idle_bg": "#8338ec", "voice_idle_fg": "#ffffff",
        "voice_active_bg": "#ff006e", "voice_active_fg": "#ffffff",
        "header_bg": "#16213e", "header_fg": "#00ff88", "status_fg": "#06ffa5",
        "system_msg_color": "#f5f5dc",
        "login_bg": "#1a1a2e", "login_form_bg": "#16213e", "login_field_bg": "#0f3460",
        "login_fg": "#eeeeee", "login_label_fg": "#aaaaaa", "login_cursor": "#00ff88",
        "login_btn_bg": "#00ff88", "login_btn_fg": "#000000",
        "login_error_bg": "#3d0000", "login_error_fg": "#ff4d4d",
        "login_title_fg": "#00ff88", "login_sub_fg": "#888888",
        "gradient_start": [10, 10, 26], "gradient_end": [50, 20, 66], "gradient_lines": "#00ff88"
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Login screen
# ═══════════════════════════════════════════════════════════════════════════════

class LoginScreen(tk.Toplevel):
    def __init__(self, parent, theme, prefill=None, error_msg=None):
        super().__init__(parent)
        self.result = None
        self.t = theme
        self._drag_x = None
        self._drag_y = None

        self.title("Haven Chat – Connect")
        self.configure(bg=self.t['login_bg'])
        self.resizable(False, False)
        self.overrideredirect(True)
        self.geometry("420x560")

        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 210
        y = (self.winfo_screenheight() // 2) - 280
        self.geometry(f'420x560+{x}+{y}')

        self.grab_set()
        self.lift()
        self.focus_force()

        # Custom title bar matching main window style
        title_bar = tk.Frame(self, bg=self.t['titlebar_bg'], height=35)
        title_bar.pack(fill=tk.X, side=tk.TOP)
        title_bar.pack_propagate(False)

        close_btn = tk.Button(title_bar, text="✕",
                              bg=self.t['titlebar_bg'], fg=self.t['titlebar_fg'],
                              font=('Segoe UI', 14), bd=0,
                              activebackground=self.t['accent_2'], activeforeground='#fff',
                              command=self._cancel, cursor='hand2', padx=8, pady=0)
        close_btn.pack(side=tk.RIGHT, padx=5)

        def start_move(event): self._drag_x = event.x; self._drag_y = event.y
        def stop_move(event):  self._drag_x = None;    self._drag_y = None
        def do_move(event):
            if self._drag_x is not None:
                dx = event.x - self._drag_x; dy = event.y - self._drag_y
                self.geometry(f"+{self.winfo_x()+dx}+{self.winfo_y()+dy}")

        title_bar.bind('<Button-1>',        start_move)
        title_bar.bind('<ButtonRelease-1>', stop_move)
        title_bar.bind('<B1-Motion>',       do_move)

        tk.Frame(self, bg=self.t['titlebar_sep'], height=1).pack(fill=tk.X, side=tk.TOP)

        tk.Label(self, text="🌐 HAVEN CHAT", bg=self.t['login_bg'], fg=self.t['login_title_fg'],
                 font=('Segoe UI', 22, 'bold')).pack(pady=(25, 5))
        tk.Label(self, text="Enter connection details", bg=self.t['login_bg'], fg=self.t['login_sub_fg'],
                 font=('Segoe UI', 10)).pack(pady=(0, 20))

        self.error_var = tk.StringVar(value=error_msg or '')
        self.error_label = tk.Label(self, textvariable=self.error_var,
                                    bg=self.t['login_error_bg'], fg=self.t['login_error_fg'],
                                    font=('Segoe UI', 10, 'bold'),
                                    padx=10, pady=8, wraplength=380)
        if error_msg:
            self.error_label.pack(fill=tk.X, padx=20, pady=(0, 10))

        form = tk.Frame(self, bg=self.t['login_form_bg'])
        form.pack(fill=tk.X, padx=30, pady=10)

        def field(parent, label_text, default='', show=''):
            tk.Label(parent, text=label_text, bg=self.t['login_form_bg'], fg=self.t['login_label_fg'],
                     font=('Segoe UI', 9, 'bold'), anchor='w').pack(fill=tk.X, padx=15, pady=(12, 2))
            e = tk.Entry(parent, bg=self.t['login_field_bg'], fg=self.t['login_fg'],
                         insertbackground=self.t['login_cursor'],
                         font=('Segoe UI', 11), show=show, relief=tk.FLAT, bd=0)
            e.pack(fill=tk.X, padx=15, pady=(0, 4))
            e.configure(highlightthickness=1,
                        highlightbackground=self.t['login_field_bg'],
                        highlightcolor=self.t['login_cursor'])
            if default:
                e.insert(0, default)
            return e

        pf = prefill or {}
        self.ip_entry       = field(form, "SERVER IP ADDRESS", pf.get('server_ip', '127.0.0.1'))
        self.username_entry = field(form, "USERNAME",          pf.get('username', ''))
        self.password_entry = field(form, "PASSWORD",          pf.get('password', ''), show='*')

        cb_frame = tk.Frame(form, bg=self.t['login_form_bg'])
        cb_frame.pack(fill=tk.X, padx=15, pady=(8, 12))
        self.remember_var = tk.BooleanVar(value=pf.get('remember', False))
        tk.Checkbutton(cb_frame, text="Remember password", variable=self.remember_var,
                       bg=self.t['login_form_bg'], fg=self.t['login_fg'],
                       selectcolor=self.t['login_field_bg'],
                       activebackground=self.t['login_form_bg'],
                       activeforeground=self.t['login_cursor'],
                       font=('Segoe UI', 9)).pack(side=tk.LEFT)

        self.connect_btn = tk.Button(self, text="CONNECT ➤",
                                     bg=self.t['login_btn_bg'], fg=self.t['login_btn_fg'],
                                     font=('Segoe UI', 13, 'bold'), relief=tk.FLAT,
                                     command=self._submit, padx=20, pady=12,
                                     cursor='hand2', activebackground=self.t['accent_1'])
        self.connect_btn.pack(pady=20, padx=30, fill=tk.X)

        self.password_entry.bind('<Return>', lambda e: self._submit())
        self.ip_entry.bind('<Return>',       lambda e: self.username_entry.focus())
        self.username_entry.bind('<Return>', lambda e: self.password_entry.focus())
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        def _set_focus():
            self.focus_force()
            if not self.ip_entry.get():
                self.ip_entry.focus_set()
            elif not self.username_entry.get():
                self.username_entry.focus_set()
            else:
                self.password_entry.focus_set()

        self.after(100, _set_focus)

    def show_error(self, msg):
        self.error_var.set(msg)
        self.error_label.pack(fill=tk.X, padx=20, pady=(0, 10))
        self.connect_btn.config(state=tk.NORMAL, text="CONNECT ➤")

    def _submit(self):
        ip       = self.ip_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not ip:
            self.show_error("⚠  Please enter a server IP address."); return
        if not username:
            self.show_error("⚠  Please enter a username."); return
        if not password:
            self.show_error("⚠  Please enter a password."); return
        self.connect_btn.config(state=tk.DISABLED, text="Connecting…")
        self.update_idletasks()
        self.result = {'server_ip': ip, 'username': username,
                       'password': password, 'remember': self.remember_var.get()}
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()


# ═══════════════════════════════════════════════════════════════════════════════
# Theme selector dialog
# ═══════════════════════════════════════════════════════════════════════════════

class ThemeDialog(tk.Toplevel):
    def __init__(self, parent, theme, current_theme_name):
        super().__init__(parent)
        self.result = None
        self.t = theme
        self.title("Choose Theme")
        self.configure(bg=self.t['glass_bg'])
        self.resizable(False, True)
        self.update_idletasks()
        self.geometry("340x500")
        x = (self.winfo_screenwidth() // 2) - 170
        y = (self.winfo_screenheight() // 2) - 250
        self.geometry(f'340x500+{x}+{y}')
        self.transient(parent)
        self.grab_set()

        tk.Label(self, text="Choose Theme", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 14, 'bold')).pack(pady=20)

        # Scrollable container
        outer = tk.Frame(self, bg=self.t['glass_bg'])
        outer.pack(fill=tk.BOTH, expand=True, padx=20)

        canvas = tk.Canvas(outer, bg=self.t['glass_bg'], highlightthickness=0)
        scrollbar = tk.Scrollbar(outer, orient=tk.VERTICAL, command=canvas.yview,
                                 bg=self.t['scrollbar_bg'],
                                 troughcolor=self.t['scrollbar_trough'],
                                 activebackground=self.t['accent_1'])
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        list_frame = tk.Frame(canvas, bg=self.t['glass_bg'])
        canvas_window = canvas.create_window((0, 0), window=list_frame, anchor='nw')

        def on_frame_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def on_canvas_configure(e):
            canvas.itemconfig(canvas_window, width=e.width)
        def on_mousewheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

        list_frame.bind('<Configure>', on_frame_configure)
        canvas.bind('<Configure>', on_canvas_configure)
        canvas.bind('<MouseWheel>', on_mousewheel)
        list_frame.bind('<MouseWheel>', on_mousewheel)

        themes = list_themes()
        for theme_name in themes:
            try:
                t_data  = load_theme(theme_name)
                display = t_data.get('name', theme_name.title())
                desc    = t_data.get('description', '')
            except:
                display = theme_name.title(); desc = ''

            is_current = (theme_name == current_theme_name)
            card = tk.Frame(list_frame, bg=self.t['glass_accent'], highlightthickness=2,
                            highlightbackground=self.t['accent_1'] if is_current else self.t['glass_accent'])
            card.pack(fill=tk.X, pady=6)
            inner = tk.Frame(card, bg=self.t['glass_accent'])
            inner.pack(fill=tk.X, padx=12, pady=10)
            name_label = tk.Label(inner, text=display + (' ✓' if is_current else ''),
                                  bg=self.t['glass_accent'],
                                  fg=self.t['accent_1'] if is_current else self.t['fg_color'],
                                  font=('Segoe UI', 11, 'bold'), anchor='w')
            name_label.pack(anchor='w')
            if desc:
                desc_label = tk.Label(inner, text=desc, bg=self.t['glass_accent'], fg=self.t['accent_4'],
                         font=('Segoe UI', 8), anchor='w', wraplength=260)
                desc_label.pack(anchor='w')
                desc_label.bind('<MouseWheel>', on_mousewheel)
            for w in (card, inner, name_label):
                w.bind('<Button-1>', lambda e, n=theme_name: self._select(n))
                w.bind('<MouseWheel>', on_mousewheel)
            card.configure(cursor='hand2')

        tk.Button(self, text="Cancel", bg=self.t['accent_2'], fg='#fff',
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  command=self.destroy, padx=20, pady=8, cursor='hand2').pack(pady=15)

    def _select(self, name):
        self.result = name
        self.destroy()


# ═══════════════════════════════════════════════════════════════════════════════
# Standard dialogs (theme-aware)
# ═══════════════════════════════════════════════════════════════════════════════

class ModernDialog(simpledialog.Dialog):
    def __init__(self, parent, title, prompt, theme=None, show='', default=''):
        self.prompt = prompt; self.show = show
        self.default_value = default; self.result = None
        self.t = theme or _fallback_theme()
        super().__init__(parent, title)

    def body(self, master):
        master.configure(bg=self.t['glass_bg'])
        tk.Label(master, text=self.prompt, bg=self.t['glass_bg'], fg=self.t['fg_color'],
                 font=('Segoe UI', 11)).grid(row=0, padx=20, pady=10)
        self.entry = tk.Entry(master, bg=self.t['glass_accent'], fg=self.t['fg_color'],
                              insertbackground=self.t['accent_1'], font=('Segoe UI', 11),
                              show=self.show, relief=tk.FLAT, bd=0)
        self.entry.grid(row=1, padx=20, pady=(0, 10))
        self.entry.configure(highlightthickness=2, highlightbackground=self.t['glass_accent'],
                             highlightcolor=self.t['accent_1'])
        if self.default_value:
            self.entry.insert(0, self.default_value)
        return self.entry

    def apply(self):
        self.result = self.entry.get()


class KeybindDialog(tk.Toplevel):
    def __init__(self, parent, current_key, theme=None):
        super().__init__(parent)
        self.result = current_key; self.listening = False
        self.captured_key = None; self.t = theme or _fallback_theme()
        self.title("Set Push-to-Talk Key")
        self.configure(bg=self.t['glass_bg'])
        self.resizable(True, True); self.geometry("450x550")
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 225
        y = (self.winfo_screenheight() // 2) - 275
        self.geometry(f'450x550+{x}+{y}')
        self.transient(parent); self.grab_set()

        tk.Label(self, text="Choose Push-to-Talk Key", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 14, 'bold')).pack(pady=20)
        tk.Label(self, text=f"Current: {self.format_key_display(current_key)}",
                 bg=self.t['glass_bg'], fg=self.t['fg_color'], font=('Segoe UI', 10)).pack(pady=5)

        preset_frame = tk.Frame(self, bg=self.t['glass_bg'])
        preset_frame.pack(pady=15)
        tk.Label(preset_frame, text="PRESETS:", bg=self.t['glass_bg'], fg=self.t['accent_4'],
                 font=('Segoe UI', 9, 'bold')).grid(row=0, column=0, columnspan=2, pady=(0, 10))
        for i, (key, label) in enumerate(zip(['Control_L', 'Alt_L', 'Shift_L', 'space'],
                                              ['Ctrl', 'Alt', 'Shift', 'Space'])):
            tk.Button(preset_frame, text=label, bg=self.t['glass_accent'], fg=self.t['fg_color'],
                      font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                      command=lambda k=key: self.select_key(k),
                      padx=15, pady=10, cursor='hand2',
                      activebackground=self.t['accent_1'],
                      activeforeground='#000').grid(row=1 + i // 2, column=i % 2, padx=10, pady=5)

        tk.Frame(self, bg=self.t['glass_accent'], height=2).pack(fill=tk.X, padx=30, pady=20)
        custom_frame = tk.Frame(self, bg=self.t['glass_bg'])
        custom_frame.pack(pady=10)
        tk.Label(custom_frame, text="CUSTOM KEY/BUTTON:", bg=self.t['glass_bg'], fg=self.t['accent_4'],
                 font=('Segoe UI', 9, 'bold')).pack(pady=(0, 10))
        self.listen_btn = tk.Button(custom_frame, text="🎯 Click to Capture",
                                    bg=self.t['accent_3'], fg='#fff',
                                    font=('Segoe UI', 11, 'bold'), relief=tk.FLAT,
                                    command=self.start_listening, padx=20, pady=12, cursor='hand2',
                                    activebackground=self.t['accent_2'])
        self.listen_btn.pack()
        self.capture_label = tk.Label(custom_frame, text="Press any key or mouse button...",
                                      bg=self.t['glass_bg'], fg=self.t['accent_4'],
                                      font=('Segoe UI', 9, 'italic'))
        self.capture_label.pack(pady=5)
        tk.Button(self, text="Cancel", bg=self.t['accent_2'], fg='#fff',
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  command=self.destroy, padx=20, pady=8, cursor='hand2').pack(pady=15)
        self.kb_listener = None; self.mouse_listener = None

    def format_key_display(self, key):
        if key.startswith('mouse_'):
            return f"Mouse {key.replace('mouse_', '').replace('_', ' ').title()}"
        elif key.startswith('Key.'):
            return key.replace('Key.', '').replace('_', ' ').title()
        return {'Control_L': 'Ctrl', 'Alt_L': 'Alt',
                'Shift_L': 'Shift', 'space': 'Space'}.get(key, key)

    def select_key(self, key):
        self.result = key; self.cleanup_listeners(); self.destroy()

    def start_listening(self):
        if self.listening: return
        self.listening = True
        self.listen_btn.config(text="⏺ LISTENING...", bg=self.t['accent_2'])
        self.capture_label.config(fg=self.t['accent_1'])
        self.kb_listener = keyboard.Listener(on_press=self.on_key_press)
        self.kb_listener.start()
        self.mouse_listener = mouse.Listener(on_click=self.on_mouse_click)
        self.mouse_listener.start()

    def on_key_press(self, key):
        if not self.listening: return
        try:
            key_str = key.char if (hasattr(key, 'char') and key.char) else str(key)
            self.captured_key = key_str; self.finish_capture()
        except: pass

    def on_mouse_click(self, x, y, button, pressed):
        if not self.listening or not pressed: return
        self.captured_key = f'mouse_{str(button).replace("Button.", "")}'; self.finish_capture()

    def finish_capture(self):
        self.listening = False; self.cleanup_listeners()
        if self.captured_key:
            self.result = self.captured_key
            self.listen_btn.config(text=f"✓ {self.format_key_display(self.captured_key)}",
                                   bg=self.t['accent_1'], fg='#000')
            self.capture_label.config(text="Key captured! Close to apply.", fg=self.t['accent_1'])
            self.after(1500, self.destroy)

    def cleanup_listeners(self):
        if self.kb_listener: self.kb_listener.stop(); self.kb_listener = None
        if self.mouse_listener: self.mouse_listener.stop(); self.mouse_listener = None

    def destroy(self):
        self.cleanup_listeners(); super().destroy()


class ColorPickerDialog(tk.Toplevel):
    def __init__(self, parent, current_color, theme=None):
        super().__init__(parent)
        self.result = current_color; self.t = theme or _fallback_theme()
        self.title("Choose Username Color")
        self.configure(bg=self.t['glass_bg'])
        self.resizable(False, False); self.transient(parent); self.grab_set()
        tk.Label(self, text="Choose Your Name Color", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 14, 'bold')).pack(pady=20)
        colors = [
            ['#ff006e', '#ff4d6d', '#ff6b9d', '#ff8fab'],
            ['#00ff88', '#06ffa5', '#4ecca3', '#78e08f'],
            ['#8338ec', '#a855f7', '#c084fc', '#e0aaff'],
            ['#ffd60a', '#ffb703', '#fb8500', '#ff9500'],
            ['#06d6a0', '#00b4d8', '#0096c7', '#48cae4'],
            ['#f72585', '#b5179e', '#7209b7', '#560bad']
        ]
        color_frame = tk.Frame(self, bg=self.t['glass_bg'])
        color_frame.pack(pady=20, padx=30)
        for row_idx, row in enumerate(colors):
            for col_idx, color in enumerate(row):
                btn = tk.Button(color_frame, bg=color, width=4, height=2,
                                relief=tk.FLAT, cursor='hand2',
                                command=lambda c=color: self.select_color(c),
                                activebackground=color)
                if color == current_color:
                    btn.config(relief=tk.RAISED, bd=3)
                btn.grid(row=row_idx, column=col_idx, padx=5, pady=5)
        tk.Button(self, text="Cancel", bg=self.t['accent_2'], fg='#fff',
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  command=self.destroy, padx=20, pady=8, cursor='hand2').pack(pady=15)

    def select_color(self, color):
        self.result = color; self.destroy()


class AudioDeviceDialog(tk.Toplevel):
    def __init__(self, parent, pyaudio_instance, current_settings, theme=None):
        super().__init__(parent)
        self.p = pyaudio_instance; self.result = current_settings.copy()
        self.t = theme or _fallback_theme()
        self.title("Audio Devices & Volume")
        self.configure(bg=self.t['glass_bg'])
        self.resizable(False, False); self.geometry("500x650")
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 250
        y = (self.winfo_screenheight() // 2) - 325
        self.geometry(f'500x650+{x}+{y}')
        self.transient(parent); self.grab_set()

        tk.Label(self, text="🎧 AUDIO SETTINGS", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 16, 'bold')).pack(pady=20)
        self.input_devices = []; self.output_devices = []
        self.get_audio_devices()

        def section(label_text):
            f = tk.Frame(self, bg=self.t['glass_accent'])
            f.pack(fill=tk.X, padx=20, pady=10)
            tk.Label(f, text=label_text, bg=self.t['glass_accent'], fg=self.t['fg_color'],
                     font=('Segoe UI', 11, 'bold')).pack(anchor=tk.W, padx=10, pady=(10, 5))
            return f

        def vol_row(parent, label_text, var, callback):
            row = tk.Frame(parent, bg=self.t['glass_accent'])
            row.pack(fill=tk.X, padx=10, pady=(10, 5))
            tk.Label(row, text=label_text, bg=self.t['glass_accent'], fg=self.t['fg_color'],
                     font=('Segoe UI', 10)).pack(side=tk.LEFT)
            lbl = tk.Label(row, text=f"{int(var.get())}%", bg=self.t['glass_accent'],
                           fg=self.t['accent_1'], font=('Segoe UI', 10, 'bold'))
            lbl.pack(side=tk.RIGHT)
            tk.Scale(parent, from_=0, to=200, orient=tk.HORIZONTAL, variable=var,
                     bg=self.t['glass_accent'], fg=self.t['fg_color'],
                     troughcolor=self.t['bg_color'], activebackground=self.t['accent_1'],
                     highlightthickness=0, bd=0,
                     command=lambda v, l=lbl, dv=var: (l.config(text=f"{int(dv.get())}%"),
                                                        callback())).pack(fill=tk.X, padx=10, pady=(0, 15))

        in_frame = section("INPUT DEVICE (Microphone)")
        self.input_var = tk.StringVar(value=self.result.get('input_device') or
                                      (self.input_devices[0] if self.input_devices else "Default"))
        in_combo = ttk.Combobox(in_frame, textvariable=self.input_var,
                                values=self.input_devices, state='readonly', width=50)
        in_combo.pack(padx=10, pady=5); self.style_combobox(in_combo)
        self.input_volume = tk.DoubleVar(value=self.result.get('input_volume', 100))
        vol_row(in_frame, "Input Volume", self.input_volume,
                lambda: self.result.update({'input_volume': self.input_volume.get()}))
        tk.Button(in_frame, text="🎤 Test Microphone", bg=self.t['glass_bg'], fg=self.t['fg_color'],
                  font=('Segoe UI', 9), relief=tk.FLAT, command=self.test_input_device,
                  padx=15, pady=5, cursor='hand2').pack(pady=(0, 15))

        out_frame = section("OUTPUT DEVICE (Speakers/Headphones)")
        self.output_var = tk.StringVar(value=self.result.get('output_device') or
                                       (self.output_devices[0] if self.output_devices else "Default"))
        out_combo = ttk.Combobox(out_frame, textvariable=self.output_var,
                                 values=self.output_devices, state='readonly', width=50)
        out_combo.pack(padx=10, pady=5); self.style_combobox(out_combo)
        self.output_volume = tk.DoubleVar(value=self.result.get('output_volume', 100))
        vol_row(out_frame, "Output Volume", self.output_volume,
                lambda: self.result.update({'output_volume': self.output_volume.get()}))
        tk.Button(out_frame, text="🔊 Test Speakers", bg=self.t['glass_bg'], fg=self.t['fg_color'],
                  font=('Segoe UI', 9), relief=tk.FLAT, command=self.test_output_device,
                  padx=15, pady=5, cursor='hand2').pack(pady=(0, 15))

        rate_frame = tk.Frame(self, bg=self.t['glass_accent'])
        rate_frame.pack(fill=tk.X, padx=20, pady=10)
        tk.Label(rate_frame, text="SUPPORTED SAMPLE RATES", bg=self.t['glass_accent'],
                 fg=self.t['accent_1'], font=('Segoe UI', 9, 'bold')).pack(anchor=tk.W, padx=10, pady=(10, 5))
        tk.Label(rate_frame, text=f"Auto-detecting: {', '.join(str(r) for r in SUPPORTED_RATES)} Hz",
                 bg=self.t['glass_accent'], fg=self.t['fg_color'],
                 font=('Segoe UI', 8)).pack(anchor=tk.W, padx=10, pady=(0, 10))

        btn_frame = tk.Frame(self, bg=self.t['glass_bg'])
        btn_frame.pack(pady=20)
        tk.Button(btn_frame, text="SAVE SETTINGS", bg=self.t['accent_1'], fg=self.t['send_btn_fg'],
                  font=('Segoe UI', 11, 'bold'), relief=tk.FLAT, command=self.save_settings,
                  padx=30, pady=10, cursor='hand2').pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="CANCEL", bg=self.t['accent_2'], fg='#fff',
                  font=('Segoe UI', 11, 'bold'), relief=tk.FLAT, command=self.destroy,
                  padx=30, pady=10, cursor='hand2').pack(side=tk.LEFT, padx=10)

    def style_combobox(self, combobox):
        style = ttk.Style(); style.theme_use('clam')
        style.configure("TCombobox", fieldbackground='#ffffff', background='#ffffff',
                        foreground='#000000', arrowcolor=self.t['accent_1'],
                        selectbackground=self.t['accent_1'], selectforeground='#000',
                        borderwidth=0, relief=tk.FLAT)
        combobox.configure(style="TCombobox")

    def get_audio_devices(self):
        try:
            self.input_devices.append(f"Default ({self.p.get_default_input_device_info()['name']})")
        except: self.input_devices.append("Default")
        try:
            self.output_devices.append(f"Default ({self.p.get_default_output_device_info()['name']})")
        except: self.output_devices.append("Default")
        for i in range(self.p.get_device_count()):
            try:
                d = self.p.get_device_info_by_index(i)
                if d['maxInputChannels'] > 0:
                    self.input_devices.append(f"Device {i}: {d['name']}")
                if d['maxOutputChannels'] > 0:
                    self.output_devices.append(f"Device {i}: {d['name']}")
            except: continue

    def test_input_device(self):
        try:
            device_name = self.input_var.get(); device_index = None
            if not device_name.startswith("Default"):
                try: device_index = int(device_name.split("Device ")[1].split(":")[0])
                except: pass
            stream = None; used_rate = None
            for rate in SUPPORTED_RATES:
                try:
                    stream = self.p.open(format=FORMAT, channels=CHANNELS, rate=rate,
                                         input=True, input_device_index=device_index,
                                         frames_per_buffer=CHUNK)
                    used_rate = rate; break
                except: continue
            if stream is None: raise Exception("Could not open device at any sample rate")

            test_dialog = tk.Toplevel(self)
            test_dialog.title("Microphone Test")
            test_dialog.configure(bg=self.t['glass_bg']); test_dialog.geometry("300x220")
            x = (self.winfo_screenwidth() // 2) - 150
            y = (self.winfo_screenheight() // 2) - 110
            test_dialog.geometry(f'300x220+{x}+{y}')
            tk.Label(test_dialog, text="🎤 Testing Microphone", bg=self.t['glass_bg'],
                     fg=self.t['accent_1'], font=('Segoe UI', 12, 'bold')).pack(pady=20)
            tk.Label(test_dialog, text=f"Sample Rate: {used_rate} Hz",
                     bg=self.t['glass_bg'], fg=self.t['fg_color'], font=('Segoe UI', 9)).pack(pady=5)
            vu_label = tk.Label(test_dialog, text="●", bg=self.t['glass_bg'],
                                fg=self.t['accent_1'], font=('Segoe UI', 20))
            vu_label.pack(pady=10)

            def update_vu():
                try:
                    data = stream.read(CHUNK, exception_on_overflow=False)
                    max_val = max(abs(int.from_bytes(data[i:i+2], 'little', signed=True))
                                  for i in range(0, len(data), 2))
                    vol = min(100, max_val // 100)
                    vu_label.config(fg=(self.t['accent_1'] if vol < 30
                                        else (self.t['accent_4'] if vol < 70
                                              else self.t['accent_2'])))
                    test_dialog.after(50, update_vu)
                except: pass

            update_vu()

            def close_test():
                try: stream.stop_stream(); stream.close()
                except: pass
                test_dialog.destroy()

            tk.Button(test_dialog, text="STOP TEST", bg=self.t['accent_2'], fg='#fff',
                      font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                      command=close_test, padx=20, pady=5).pack(pady=10)
        except Exception as e:
            messagebox.showerror("Test Failed", f"Could not test microphone: {str(e)}")

    def test_output_device(self):
        try:
            device_name = self.output_var.get(); device_index = None
            if not device_name.startswith("Default"):
                try: device_index = int(device_name.split("Device ")[1].split(":")[0])
                except: pass
            stream = None; used_rate = None
            for rate in SUPPORTED_RATES:
                try:
                    stream = self.p.open(format=FORMAT, channels=CHANNELS, rate=rate,
                                         output=True, output_device_index=device_index,
                                         frames_per_buffer=CHUNK)
                    used_rate = rate; break
                except: continue
            if stream is None: raise Exception("Could not open device at any sample rate")
            try:
                import numpy as np
                samples = (np.sin(2 * np.pi * np.arange(int(used_rate * 0.5)) * 440 / used_rate)).astype(np.float32)
                test_audio = (samples * 32767).astype(np.int16).tobytes()
                vol = self.output_volume.get() / 100
                if vol != 1.0:
                    arr = np.frombuffer(test_audio, dtype=np.int16)
                    test_audio = (arr * vol).astype(np.int16).tobytes()
            except ImportError:
                test_audio = b'\x00\x00' * (used_rate // 10)
                messagebox.showwarning("NumPy Missing", "Install numpy for better test tones")
            stream.write(test_audio); stream.stop_stream(); stream.close()
            messagebox.showinfo("Test Complete", f"Test tone played at {used_rate} Hz!")
        except Exception as e:
            messagebox.showerror("Test Failed", f"Could not test speakers: {str(e)}")

    def save_settings(self):
        self.result['input_device']  = self.input_var.get()
        self.result['output_device'] = self.output_var.get()
        self.result['input_volume']  = self.input_volume.get()
        self.result['output_volume'] = self.output_volume.get()
        for key, var in (('input_device', 'input_device_index'), ('output_device', 'output_device_index')):
            if not self.result[key].startswith("Default"):
                try: self.result[var] = int(self.result[key].split("Device ")[1].split(":")[0])
                except: self.result[var] = None
            else:
                self.result[var] = None
        self.destroy()


# ═══════════════════════════════════════════════════════════════════════════════
# Main client
# ═══════════════════════════════════════════════════════════════════════════════

class HavenClient:
    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self._closing    = False
        self.x           = None
        self.y           = None
        self.user_colors = {}
        self.server_assigned_color = None
        self._tcp_buffer = ''
        self.tray_icon   = None

        config = self.load_config()
        self.ptt_key    = config.get('ptt_key', 'Control_L')
        self.name_color = config.get('name_color', self.generate_random_color())
        self.theme_name = config.get('theme', 'default')
        self.theme      = load_theme(self.theme_name)

        self.audio_settings = {
            'input_device':        config.get('input_device', 'Default'),
            'output_device':       config.get('output_device', 'Default'),
            'input_device_index':  config.get('input_device_index', None),
            'output_device_index': config.get('output_device_index', None),
            'input_volume':        config.get('input_volume', 100),
            'output_volume':       config.get('output_volume', 100),
        }

        self.current_input_rate  = DEFAULT_RATE
        self.current_output_rate = DEFAULT_RATE

        server_ip      = config.get('server_ip', '')
        saved_username = config.get('username', '')
        saved_password = config.get('password', '')

        connected = False
        if server_ip and saved_username and saved_password:
            result = self._attempt_connect(server_ip, saved_username, saved_password)
            if result == 'ok':
                connected = True
            elif result == 'auth_failed':
                connected = self._run_login_loop(config, prefill={
                    'server_ip': server_ip, 'username': saved_username, 'password': ''},
                    error_msg="⚠  Saved password was rejected by the server.")
            else:
                connected = self._run_login_loop(config, prefill={
                    'server_ip': server_ip, 'username': saved_username, 'password': ''},
                    error_msg=f"⚠  Could not connect: {result}")
        else:
            connected = self._run_login_loop(config, prefill={
                'server_ip': server_ip, 'username': saved_username, 'password': ''})

        if not connected:
            self.root.destroy()
            return

        self.root.deiconify()
        self.root.title("Haven Chat")
        self.root.geometry("900x850")
        self.root.minsize(800, 500)
        self.root.overrideredirect(True)
        self.root.lift()
        self.root.focus_force()
        self.root.attributes('-topmost', True)
        self.root.after(100, lambda: self.root.attributes('-topmost', False))
        self.root.configure(bg=self.theme['bg_color'])

        self.build_ui()

        self.p            = pyaudio.PyAudio()
        self.stream_in    = None
        self.stream_out   = None
        self.voice_active = False
        self.active_speakers = set()
        self.speaker_labels  = {}

        # Start system tray BEFORE network threads
        self._start_tray()

        threading.Thread(target=self.receive_tcp, daemon=True).start()
        threading.Thread(target=self.receive_udp, daemon=True).start()

        self.setup_global_hotkey()
        self.root.protocol("WM_DELETE_WINDOW", self.minimize_to_tray)
        self.root.mainloop()

    # ── System Tray ──────────────────────────────────────────────

    def _start_tray(self):
        """Spin up the pystray icon in its own daemon thread."""
        if not TRAY_AVAILABLE:
            return

        img = load_tray_image()
        if img is None:
            return

        menu = pystray.Menu(
            pystray.MenuItem('Haven Chat', self._tray_restore, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Restore', self._tray_restore),
            pystray.MenuItem('Quit',    self._tray_quit),
        )

        self.tray_icon = pystray.Icon('haven_chat', img, 'Haven Chat', menu)

        # Run the tray icon in a background thread — it has its own event loop
        tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
        tray_thread.start()

    def _tray_restore(self, icon=None, item=None):
        """Called from the tray — must schedule UI work on the tkinter thread."""
        self.root.after(0, self._show_window)

    def _tray_quit(self, icon=None, item=None):
        """Quit from the tray menu."""
        self.root.after(0, self.on_close)

    def _show_window(self):
        """Restore the window from tray/hidden state."""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.root.attributes('-topmost', True)
        self.root.after(100, lambda: self.root.attributes('-topmost', False))

    def minimize_to_tray(self):
        """Hide the window — tray icon stays visible for restore."""
        self.root.withdraw()

    # ── Theme ────────────────────────────────────────────────────

    def apply_theme(self, theme_name):
        """Save the new theme and restart the client process cleanly."""
        self.theme_name = theme_name
        self.save_config()
        if self.tray_icon:
            try: self.tray_icon.stop()
            except: pass
        self.running = False
        subprocess.Popen([sys.executable] + sys.argv)
        self.root.destroy()

    # ── Login helpers ────────────────────────────────────────────

    def _run_login_loop(self, config, prefill=None, error_msg=None):
        current_prefill = prefill or {}
        current_error   = error_msg
        while True:
            self.root.deiconify()
            dialog = LoginScreen(self.root, self.theme,
                                 prefill=current_prefill, error_msg=current_error)
            self.root.wait_window(dialog)
            self.root.withdraw()
            if dialog.result is None:
                return False
            data   = dialog.result
            result = self._attempt_connect(data['server_ip'], data['username'], data['password'])
            if result == 'ok':
                config['server_ip'] = data['server_ip']
                config['username']  = data['username']
                if data['remember']:
                    config['password'] = data['password']
                elif 'password' in config:
                    del config['password']
                self.server_ip = data['server_ip']
                self.username  = data['username']
                self.password  = data['password']
                self.saved_password = data['password'] if data['remember'] else None
                self.save_config()
                return True
            elif result == 'auth_failed':
                current_error   = "⚠  Incorrect password. Please try again."
                current_prefill = {'server_ip': data['server_ip'],
                                   'username': data['username'], 'password': ''}
            else:
                current_error   = f"⚠  Connection failed: {result}"
                current_prefill = {'server_ip': data['server_ip'],
                                   'username': data['username'], 'password': ''}

    def _attempt_connect(self, server_ip, username, password):
        try:
            tls_ctx  = create_tls_context()
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(10)
            raw_sock.connect((server_ip, SERVER_TCP_PORT))
            tcp_sock = tls_ctx.wrap_socket(raw_sock, server_hostname=server_ip)

            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(('0.0.0.0', 0))
            udp_port = udp_sock.getsockname()[1]

            password_hash = compute_password_hash(password)

            buffer = ''; nonce = None
            while nonce is None:
                chunk = tcp_sock.recv(4096).decode('utf-8', errors='replace')
                if not chunk:
                    raise ConnectionError("Server closed connection before challenge")
                buffer += chunk
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    if not line: continue
                    try: msg = json.loads(line)
                    except json.JSONDecodeError: continue
                    if msg.get('type') == 'challenge':
                        nonce = msg['nonce']; break
                    elif msg.get('type') == 'error':
                        raise ConnectionError(msg.get('message', 'Server error'))

            if not nonce:
                raise ConnectionError("Did not receive challenge from server")

            auth_response = compute_auth_response(nonce, password_hash)
            tcp_sock.send((json.dumps({
                'type': 'login', 'username': username, 'udp_port': udp_port,
                'auth_response': auth_response, 'user_color': self.name_color
            }) + '\n').encode())

            tcp_sock.settimeout(10)
            while True:
                chunk = tcp_sock.recv(4096).decode('utf-8', errors='replace')
                if not chunk:
                    raise ConnectionError("Server closed connection during auth")
                buffer += chunk
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    if not line: continue
                    try: msg = json.loads(line)
                    except json.JSONDecodeError: continue

                    if msg['type'] == 'auth_ok':
                        tcp_sock.settimeout(None)
                        self.tcp_sock = tcp_sock; self.udp_sock = udp_sock
                        self.udp_port = udp_port; self.server_ip = server_ip
                        self.username = username; self.password  = password
                        self.running  = True; self.authenticated = True
                        self._tcp_buffer = buffer
                        if 'user_color' in msg:
                            self.server_assigned_color = msg['user_color']
                            self.name_color = msg['user_color']
                        return 'ok'
                    elif msg['type'] == 'auth_failed':
                        tcp_sock.close(); udp_sock.close(); return 'auth_failed'
                    elif msg['type'] == 'error':
                        tcp_sock.close(); udp_sock.close()
                        return msg.get('message', 'Server error')

        except ssl.SSLError as e:   return f'TLS error: {e}'
        except socket.timeout:      return 'Connection timed out'
        except ConnectionRefusedError: return 'Connection refused (is the server running?)'
        except Exception as e:      return str(e)

    # ── Config ───────────────────────────────────────────────────

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except: pass
        return {}

    def save_config(self):
        config = {
            'server_ip':           getattr(self, 'server_ip', ''),
            'username':            getattr(self, 'username', ''),
            'ptt_key':             self.ptt_key,
            'name_color':          self.name_color,
            'theme':               self.theme_name,
            'input_device':        self.audio_settings.get('input_device', 'Default'),
            'output_device':       self.audio_settings.get('output_device', 'Default'),
            'input_device_index':  self.audio_settings.get('input_device_index', None),
            'output_device_index': self.audio_settings.get('output_device_index', None),
            'input_volume':        self.audio_settings.get('input_volume', 100),
            'output_volume':       self.audio_settings.get('output_volume', 100),
        }
        if getattr(self, 'saved_password', None):
            config['password'] = self.saved_password
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)

    # ── Color helpers ────────────────────────────────────────────

    def generate_random_color(self):
        return random.choice(USER_COLOR_PALETTE)

    def fade_color(self, color, factor):
        try:
            color = color.lstrip('#')
            if len(color) == 3: color = ''.join([c * 2 for c in color])
            r, g, b = int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
            return f'#{int(r*factor):02x}{int(g*factor):02x}{int(b*factor):02x}'
        except: return color

    # ── GUI ──────────────────────────────────────────────────────

    def build_ui(self):
        t = self.theme

        self.canvas_bg = tk.Canvas(self.root, bg=t['bg_color'], highlightthickness=0)
        self.canvas_bg.place(x=0, y=0, relwidth=1, relheight=1)
        self.draw_background()

        # Title bar
        title_bar = tk.Frame(self.root, bg=t['titlebar_bg'], height=35)
        title_bar.pack(fill=tk.X, side=tk.TOP)
        title_bar.pack_propagate(False)

        app_icon = tk.Label(title_bar, text=" ", bg=t['titlebar_bg'],
                            fg=t['accent_1'], font=('Segoe UI', 14, 'bold'))
        app_icon.pack(side=tk.LEFT, padx=(10, 0), pady=5)

        app_title = tk.Label(title_bar, text="HAVEN",
                             bg=t['titlebar_bg'], fg=t['titlebar_fg'],
                             font=('Segoe UI', 11, 'bold'))
        app_title.pack(side=tk.LEFT, padx=5, pady=5)

        self.settings_btn = tk.Menubutton(title_bar, text="⚙ Settings",
                                          bg=t['titlebar_bg'], fg=t['titlebar_fg'],
                                          font=('Segoe UI', 9),
                                          activebackground=t['accent_3'],
                                          activeforeground=t['fg_color'],
                                          relief=tk.FLAT, bd=0, padx=8, pady=2)
        settings_menu = Menu(self.settings_btn, tearoff=0,
                             bg=t['glass_accent'], fg=t['fg_color'],
                             activebackground=t['accent_1'], activeforeground='#000',
                             relief=tk.FLAT, bd=1)
        settings_menu.add_command(label="Change Username",        command=self.change_username)
        settings_menu.add_command(label="Change Name Color",      command=self.change_name_color)
        settings_menu.add_command(label="Change PTT Key",         command=self.change_ptt_key)
        settings_menu.add_command(label="Audio Devices & Volume", command=self.configure_audio_devices)
        settings_menu.add_command(label="Change Theme",           command=self.change_theme)
        settings_menu.add_separator()
        settings_menu.add_command(label="Clear Saved Password",   command=self.clear_saved_password)
        settings_menu.add_separator()
        settings_menu.add_command(label="About",                  command=self.show_about)
        self.settings_btn.config(menu=settings_menu)
        self.settings_btn.pack(side=tk.LEFT, padx=15, pady=5)

        controls_frame = tk.Frame(title_bar, bg=t['titlebar_bg'])
        controls_frame.pack(side=tk.RIGHT, padx=5)

        # Minimize button now hides to tray
        tk.Button(controls_frame, text="─", bg=t['titlebar_bg'], fg=t['titlebar_fg'],
                  font=('Segoe UI', 14), bd=0,
                  activebackground=t['accent_3'], activeforeground=t['fg_color'],
                  command=self.minimize_to_tray, cursor='hand2',
                  padx=8, pady=0).pack(side=tk.LEFT, padx=2)

        tk.Button(controls_frame, text="✕", bg=t['titlebar_bg'], fg=t['titlebar_fg'],
                  font=('Segoe UI', 14), bd=0,
                  activebackground=t['accent_2'], activeforeground='#fff',
                  command=self.on_close, cursor='hand2',
                  padx=8, pady=0).pack(side=tk.LEFT, padx=2)

        def start_move(event): self.x = event.x; self.y = event.y
        def stop_move(event):  self.x = None;    self.y = None
        def do_move(event):
            if self.x is not None and self.y is not None:
                dx = event.x - self.x; dy = event.y - self.y
                self.root.geometry(f"+{self.root.winfo_x()+dx}+{self.root.winfo_y()+dy}")

        for w in (title_bar, app_title, app_icon):
            w.bind('<Button-1>',        start_move)
            w.bind('<ButtonRelease-1>', stop_move)
            w.bind('<B1-Motion>',       do_move)

        tk.Frame(self.root, bg=t['titlebar_sep'], height=1).pack(fill=tk.X, side=tk.TOP)

        main_frame = tk.Frame(self.root, bg=t['glass_bg'], highlightthickness=1,
                              highlightbackground=t['accent_4'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 2))

        header = tk.Frame(main_frame, bg=t['header_bg'], height=60)
        header.pack(fill=tk.X, padx=2, pady=2)
        header.pack_propagate(False)

        tk.Label(header, text="🌐 Global", bg=t['header_bg'],
                 fg=t['header_fg'], font=('Segoe UI', 18, 'bold')).pack(side=tk.LEFT, padx=20, pady=10)

        self.status_label = tk.Label(header, text="● CONNECTED",
                                     bg=t['header_bg'], fg=t['status_fg'],
                                     font=('Segoe UI', 10))
        self.status_label.pack(side=tk.RIGHT, padx=20)

        content = tk.Frame(main_frame, bg=t['glass_bg'])
        content.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 2))

        left_frame = tk.Frame(content, bg=t['glass_bg'])
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        chat_container = tk.Frame(left_frame, bg=t['chat_bg'], highlightthickness=0)
        chat_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.chat_text = tk.Text(chat_container, bg=t['chat_bg'], fg=t['chat_fg'],
                                 insertbackground=t['accent_1'], wrap=tk.WORD,
                                 state=tk.DISABLED, font=(t['chat_font'], t['chat_font_size']),
                                 relief=tk.FLAT, padx=15, pady=15, spacing3=5)
        self.chat_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(chat_container, command=self.chat_text.yview,
                                 bg=t['scrollbar_bg'], troughcolor=t['scrollbar_trough'],
                                 activebackground=t['accent_1'])
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_text.config(yscrollcommand=scrollbar.set)

        entry_container = tk.Frame(left_frame, bg=t['glass_accent'], height=50)
        entry_container.pack(fill=tk.X)
        entry_container.pack_propagate(False)
        entry_inner = tk.Frame(entry_container, bg=t['glass_accent'])
        entry_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.msg_entry = tk.Entry(entry_inner, bg=t['entry_bg'], fg=t['entry_fg'],
                                  insertbackground=t['accent_1'],
                                  font=('Segoe UI', 11), relief=tk.FLAT, bd=0)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        self.msg_entry.bind('<Return>', self.send_chat)

        tk.Button(entry_inner, text="SEND ➤", bg=t['send_btn_bg'], fg=t['send_btn_fg'],
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT, bd=0,
                  cursor='hand2', activebackground=t['accent_4'],
                  command=self.send_chat, padx=20, pady=8).pack(side=tk.RIGHT)

        voice_container = tk.Frame(left_frame, bg=t['glass_accent'], height=60)
        voice_container.pack(fill=tk.X, pady=(10, 0))
        voice_container.pack_propagate(False)
        voice_inner = tk.Frame(voice_container, bg=t['glass_accent'])
        voice_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.update_voice_button_text()
        self.voice_btn = tk.Button(voice_inner, text=self.voice_btn_text,
                                   bg=t['voice_idle_bg'], fg=t['voice_idle_fg'],
                                   font=('Segoe UI', 11, 'bold'), relief=tk.FLAT,
                                   cursor='hand2', activebackground=t['voice_active_bg'],
                                   bd=0, padx=20, pady=10)
        self.voice_btn.pack(fill=tk.X)
        self.voice_btn.bind('<ButtonPress>',   self.start_voice)
        self.voice_btn.bind('<ButtonRelease>', self.stop_voice)

        right_frame = tk.Frame(content, bg=t['userlist_bg'], width=200)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 10), pady=10)
        right_frame.pack_propagate(False)

        tk.Label(right_frame, text="ONLINE", bg=t['userlist_bg'],
                 fg=t['accent_4'], font=('Segoe UI', 12, 'bold')).pack(pady=(10, 15))

        user_list_container = tk.Frame(right_frame, bg=t['userlist_bg'])
        user_list_container.pack(fill=tk.BOTH, expand=True, padx=10)

        canvas = tk.Canvas(user_list_container, bg=t['userlist_bg'], highlightthickness=0)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar_users = tk.Scrollbar(user_list_container, orient=tk.VERTICAL,
                                       command=canvas.yview, bg=t['scrollbar_bg'],
                                       troughcolor=t['scrollbar_trough'],
                                       activebackground=t['accent_1'])
        scrollbar_users.pack(side=tk.RIGHT, fill=tk.Y)

        self.user_list_frame = tk.Frame(canvas, bg=t['userlist_bg'])
        canvas_window = canvas.create_window((0, 0), window=self.user_list_frame, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar_users.set)
        self.user_list_frame.bind('<Configure>',
                                  lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind('<Configure>',
                    lambda e: canvas.itemconfig(canvas_window, width=e.width))

    def draw_background(self):
        t  = self.theme
        gs = t.get('gradient_start', [10, 10, 26])
        ge = t.get('gradient_end',   [50, 20, 66])
        gl = t.get('gradient_lines', t['accent_1'])
        w, h = 900, 850
        for i in range(h):
            ratio = i / h
            r = int(gs[0] + (ge[0] - gs[0]) * ratio)
            g = int(gs[1] + (ge[1] - gs[1]) * ratio)
            b = int(gs[2] + (ge[2] - gs[2]) * ratio)
            self.canvas_bg.create_line(0, i, w, i, fill=f'#{r:02x}{g:02x}{b:02x}')
        for i in range(5):
            y = (i + 1) * (h / 6)
            self.canvas_bg.create_line(0, y, w, y, fill=gl, width=1, dash=(10, 20), stipple='gray50')

    def show_about(self):
        t = self.theme
        messagebox.showinfo("About Haven Chat",
                            f"Haven Chat v2.1\n\nCurrent theme: {t.get('name', self.theme_name)}\n\n"
                            "A hopefully secure voice and text chat client\nwith vibes and dreams.\n\n"
                            "✨ By downloading, installing, or using this Software, you hereby affirm to uphold truth, justice, equity, and the democratic ideals of the American way. You further acknowledge and agree to defend and respect the sovereignty, self-determination, and human rights of all peoples, including but not limited to those of Ukraine, Palestine, Taiwan, Hong Kong, Tibet, Sudan, and any nation or community striving toward freedom and dignity. You strive to uphold the right of every person to live authentically, free from discrimination or harm, regardless of race, creed, sexual orientation, or gender identity and expression. Use of this Software constitutes your pledge to counter oppression, misinformation, and authoritarianism in all forms, and to act in good faith toward a more just, accepting, tolerant and sustainable world. ✨\n\n")

    def format_key_display(self, key):
        if key.startswith('mouse_'):
            return f"Mouse {key.replace('mouse_', '').replace('_', ' ').title()}"
        elif key.startswith('Key.'):
            return key.replace('Key.', '').replace('_', ' ').title()
        return {'Control_L': 'Ctrl', 'Alt_L': 'Alt',
                'Shift_L': 'Shift', 'space': 'Space'}.get(key, key)

    def update_voice_button_text(self):
        self.voice_btn_text = f"🎤 PUSH TO TALK (Hold {self.format_key_display(self.ptt_key)})"

    # ── Global hotkey ────────────────────────────────────────────

    def setup_global_hotkey(self):
        self.current_keys    = set()
        self.current_buttons = set()
        self.key_map = {
            'Control_L': keyboard.Key.ctrl_l, 'Control_R': keyboard.Key.ctrl,
            'Alt_L':     keyboard.Key.alt_l,  'Alt_R':     keyboard.Key.alt,
            'Shift_L':   keyboard.Key.shift_l,'Shift_R':   keyboard.Key.shift,
            'space':     keyboard.Key.space,
        }
        self.keyboard_listener = keyboard.Listener(
            on_press=self.on_global_key_press, on_release=self.on_global_key_release)
        self.keyboard_listener.start()
        self.mouse_listener = mouse.Listener(on_click=self.on_global_mouse_click)
        self.mouse_listener.start()

    def on_global_key_press(self, key):
        try:
            if self.ptt_key in self.key_map:
                ptt_key = self.key_map[self.ptt_key]
                right_variant = self.key_map.get(self.ptt_key[:-1] + 'R') if self.ptt_key.endswith('_L') else None
                if key == ptt_key or (right_variant and key == right_variant):
                    if key not in self.current_keys:
                        self.current_keys.add(key); self.root.after(0, self.start_voice)
            else:
                key_str = key.char if (hasattr(key, 'char') and key.char) else str(key)
                if key_str == self.ptt_key and key not in self.current_keys:
                    self.current_keys.add(key); self.root.after(0, self.start_voice)
        except AttributeError: pass

    def on_global_key_release(self, key):
        try:
            if self.ptt_key in self.key_map:
                ptt_key = self.key_map[self.ptt_key]
                right_variant = self.key_map.get(self.ptt_key[:-1] + 'R') if self.ptt_key.endswith('_L') else None
                if key == ptt_key or (right_variant and key == right_variant):
                    self.current_keys.discard(key); self.root.after(0, self.stop_voice)
            else:
                key_str = key.char if (hasattr(key, 'char') and key.char) else str(key)
                if key_str == self.ptt_key:
                    self.current_keys.discard(key); self.root.after(0, self.stop_voice)
        except AttributeError: pass

    def on_global_mouse_click(self, x, y, button, pressed):
        if not self.ptt_key.startswith('mouse_'): return
        button_str = f'mouse_{str(button).replace("Button.", "")}'
        if button_str == self.ptt_key:
            if pressed:
                if button not in self.current_buttons:
                    self.current_buttons.add(button); self.root.after(0, self.start_voice)
            else:
                self.current_buttons.discard(button); self.root.after(0, self.stop_voice)

    # ── Network ──────────────────────────────────────────────────

    def receive_tcp(self):
        buffer = getattr(self, '_tcp_buffer', '')
        self._tcp_buffer = ''
        while self.running:
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if not line.strip(): continue
                try: msg = json.loads(line)
                except json.JSONDecodeError: continue
                self.root.after(0, lambda m=msg: self.handle_tcp_message(m))
            try:
                data = self.tcp_sock.recv(4096).decode('utf-8', errors='replace')
                if not data: break
                buffer += data
                if len(buffer) > MAX_TCP_BUFFER:
                    print("TCP buffer overflow — disconnecting"); break
            except ssl.SSLError: break
            except OSError: break
            except Exception: break
        if self.running:
            self.root.after(0, self.connection_lost)

    def connection_lost(self):
        if not self._closing:
            if hasattr(self, 'saved_password'): self.saved_password = None
            self.save_config()
            messagebox.showerror("Connection Lost",
                                 "Lost connection to the server.\nYou will need to reconnect.")
            self.on_close()

    def handle_tcp_message(self, msg):
        t = self.theme
        if msg['type'] == 'auth_ok':
            if 'user_color' in msg:
                self.server_assigned_color = msg['user_color']
                self.name_color = msg['user_color']; self.save_config()
            self.display_system_message("✓ Connected to server")
        elif msg['type'] == 'auth_failed':
            messagebox.showerror("Authentication Failed", "Incorrect password")
            self.root.after(0, self.on_close)
        elif msg['type'] == 'chat':
            self.display_message(msg['user'], msg['text'])
        elif msg['type'] == 'chat_history':
            for chat_msg in msg['history']:
                user = chat_msg['user']; text = chat_msg['text']
                timestamp = chat_msg.get('timestamp'); stored_color = chat_msg.get('color')
                if user == 'System':
                    self.display_message(user, text, timestamp=timestamp, color=t['system_msg_color'])
                else:
                    if user not in self.user_colors and stored_color:
                        self.user_colors[user] = stored_color
                    display_color = stored_color or self.user_colors.get(user, t['accent_2'])
                    self.display_message(user, text, timestamp=timestamp, color=display_color)
            self.display_system_message("✓ Chat history loaded")
        elif msg['type'] == 'userlist_full':
            self.update_userlist_with_colors(msg['users'])
        elif msg['type'] == 'userlist':
            self.update_userlist_with_colors([{'username': u, 'color': t['accent_2']} for u in msg['users']])
        elif msg['type'] == 'user_color_changed':
            self.update_user_color(msg['username'], msg['color'])
        elif msg['type'] == 'voice_start':
            self.set_user_voice_active(msg['user'], True)
        elif msg['type'] == 'voice_stop':
            self.set_user_voice_active(msg['user'], False)
        elif msg['type'] == 'username_changed':
            self.display_system_message(f"✓ Username changed to {msg['new_username']}")
            old_username = self.username; self.username = msg['new_username']
            if 'user_color' in msg:
                self.name_color = msg['user_color']; self.server_assigned_color = msg['user_color']
            self.save_config()
            if old_username in self.speaker_labels:
                self.speaker_labels[old_username].destroy(); del self.speaker_labels[old_username]
            self.add_user_to_list(self.username, self.name_color)
        elif msg['type'] == 'kicked':
            messagebox.showerror("Kicked", "You have been kicked from the server.")
            self.root.after(0, self.on_close)
        elif msg['type'] == 'banned':
            messagebox.showerror("Banned", "You have been banned from the server.")
            self.root.after(0, self.on_close)
        elif msg['type'] == 'error':
            messagebox.showerror("Error", msg['message'])

    def receive_udp(self):
        while self.running:
            try:
                data, addr = self.udp_sock.recvfrom(4096)
                if self.stream_out is None:
                    try:
                        device_index = self.audio_settings.get('output_device_index', None)
                        for rate in SUPPORTED_RATES:
                            try:
                                self.stream_out = self.p.open(
                                    format=FORMAT, channels=CHANNELS, rate=rate,
                                    output=True, output_device_index=device_index,
                                    frames_per_buffer=CHUNK)
                                self.current_output_rate = rate; break
                            except: continue
                    except Exception as e:
                        print(f"Failed to open output stream: {e}"); continue
                volume = self.audio_settings.get('output_volume', 100) / 100
                if volume != 1.0:
                    try:
                        import numpy as np
                        audio_data = np.frombuffer(data, dtype=np.int16)
                        data = (audio_data * volume).astype(np.int16).tobytes()
                    except ImportError: pass
                self.stream_out.write(data)
            except OSError: break
            except Exception as e: print(f"Error in receive_udp: {e}"); break

    def send_chat(self, event=None):
        text = self.msg_entry.get().strip()
        if text and self.authenticated:
            try:
                self.tcp_sock.send((json.dumps({'type': 'chat', 'text': text}) + '\n').encode())
                self.msg_entry.delete(0, tk.END)
                self.display_message(self.username, text, align='right')
            except: messagebox.showerror("Error", "Failed to send message")

    def display_message(self, user, text, align='left', timestamp=None, color=None):
        t = self.theme
        self.chat_text.config(state=tk.NORMAL)
        if timestamp is None: timestamp = datetime.now().strftime('%H:%M')
        if align == 'right':
            self.chat_text.insert(tk.END, f'{text}  ', 'right_text')
            self.chat_text.insert(tk.END, f'[{timestamp} - {user}]\n', 'right_meta')
            self.chat_text.tag_config('right_text', justify='right',
                                      foreground=self.name_color, font=('Segoe UI', 10))
            self.chat_text.tag_config('right_meta', justify='right',
                                      foreground=t['accent_4'], font=('Segoe UI', 8))
        else:
            self.chat_text.insert(tk.END, f'[{timestamp}] ', 'timestamp')
            if user == 'System':
                self.chat_text.insert(tk.END, f'{user}: ', 'username_system')
                self.chat_text.tag_config('username_system', foreground=t['system_msg_color'],
                                          font=('Segoe UI', 10, 'bold'))
            else:
                user_color = color or self.user_colors.get(user, t['accent_2'])
                tag_name = f'username_{user}'
                self.chat_text.insert(tk.END, f'{user}: ', tag_name)
                self.chat_text.tag_config(tag_name, foreground=user_color, font=('Segoe UI', 10, 'bold'))
            self.chat_text.insert(tk.END, f'{text}\n', 'message')
            self.chat_text.tag_config('timestamp', foreground=t['accent_4'], font=('Consolas', 8))
            self.chat_text.tag_config('message',   foreground=t['chat_fg'],  font=('Segoe UI', 10))
        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.see(tk.END)

    def display_system_message(self, text):
        t = self.theme
        self.chat_text.config(state=tk.NORMAL)
        timestamp = datetime.now().strftime('%H:%M')
        self.chat_text.insert(tk.END, f'[{timestamp}] ', 'sys_time')
        self.chat_text.insert(tk.END, f'{text}\n', 'system')
        self.chat_text.tag_config('sys_time', foreground=t['accent_4'], font=('Consolas', 8))
        self.chat_text.tag_config('system',   foreground=t['system_msg_color'], font=('Segoe UI', 10, 'italic'))
        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.see(tk.END)

    def update_userlist_with_colors(self, users_with_colors):
        for widget in self.user_list_frame.winfo_children():
            widget.destroy()
        self.speaker_labels.clear()
        for user_data in users_with_colors:
            self.user_colors[user_data['username']] = user_data.get('color', self.theme['accent_2'])
        for username, color in self.user_colors.items():
            if any(u['username'] == username for u in users_with_colors):
                self.add_user_to_list(username, color)
        if self.username not in self.user_colors:
            self.user_colors[self.username] = self.name_color

    def add_user_to_list(self, username, color):
        t = self.theme
        card = tk.Frame(self.user_list_frame, bg=t['userlist_card_bg'],
                        highlightthickness=1, highlightbackground=t['accent_4'])
        card.pack(fill=tk.X, pady=5)
        label = tk.Label(card, text=f"● {username}", bg=t['userlist_card_bg'], fg=color,
                         font=('Segoe UI', 10), anchor='w', padx=10, pady=8)
        label.pack(fill=tk.X)
        self.speaker_labels[username] = label
        if username in self.active_speakers:
            self.set_user_voice_active(username, True)

    def update_user_color(self, username, new_color):
        self.user_colors[username] = new_color
        if username in self.speaker_labels:
            prefix = "🔴" if username in self.active_speakers else "●"
            self.speaker_labels[username].config(fg=new_color, text=f"{prefix} {username}")
        if username == self.username:
            self.name_color = new_color; self.server_assigned_color = new_color
            self.save_config(); self.display_system_message("✓ Your name color updated")

    def set_user_voice_active(self, username, active):
        if active: self.active_speakers.add(username)
        else:      self.active_speakers.discard(username)
        if username in self.speaker_labels:
            label      = self.speaker_labels[username]
            user_color = self.user_colors.get(username, self.theme['fg_color'])
            if active:
                label.config(fg=user_color, font=('Segoe UI', 10, 'bold'), text=f"🔴 {username}")
                self.pulse_speaker(label, username)
            else:
                label.config(fg=user_color, font=('Segoe UI', 10), text=f"● {username}")

    def pulse_speaker(self, label, username):
        if username in self.active_speakers and label.winfo_exists():
            user_color = self.user_colors.get(username, self.theme['accent_2'])
            current_fg = label.cget('fg')
            new_fg = user_color if current_fg != user_color else self.fade_color(user_color, 0.7)
            label.config(fg=new_fg)
            self.root.after(500, lambda: self.pulse_speaker(label, username))

    # ── Settings actions ─────────────────────────────────────────

    def change_theme(self):
        dialog = ThemeDialog(self.root, self.theme, self.theme_name)
        self.root.wait_window(dialog)
        if dialog.result and dialog.result != self.theme_name:
            self.apply_theme(dialog.result)

    def change_username(self):
        dialog = ModernDialog(self.root, "Change Username", "New username:", theme=self.theme)
        new_name = dialog.result
        if new_name and new_name != self.username:
            try:
                self.tcp_sock.send((json.dumps({'type': 'change_username',
                                                'new_username': new_name,
                                                'user_color': self.name_color}) + '\n').encode())
            except: messagebox.showerror("Error", "Failed to change username")

    def change_name_color(self):
        dialog = ColorPickerDialog(self.root, self.name_color, theme=self.theme)
        self.root.wait_window(dialog)
        if dialog.result and dialog.result != self.name_color:
            old_color = self.name_color; self.name_color = dialog.result
            try:
                self.tcp_sock.send((json.dumps({'type': 'change_username',
                                                'new_username': self.username,
                                                'user_color': self.name_color}) + '\n').encode())
            except:
                messagebox.showerror("Error", "Failed to update color")
                self.name_color = old_color; return
            self.save_config()

    def change_ptt_key(self):
        dialog = KeybindDialog(self.root, self.ptt_key, theme=self.theme)
        self.root.wait_window(dialog)
        if dialog.result and dialog.result != self.ptt_key:
            if hasattr(self, 'keyboard_listener'): self.keyboard_listener.stop()
            if hasattr(self, 'mouse_listener'):    self.mouse_listener.stop()
            self.ptt_key = dialog.result
            self.setup_global_hotkey()
            self.update_voice_button_text()
            self.voice_btn.config(text=self.voice_btn_text)
            self.save_config()
            self.display_system_message(
                f"✓ Push-to-talk key changed to {self.format_key_display(dialog.result)}")

    def configure_audio_devices(self):
        dialog = AudioDeviceDialog(self.root, self.p, self.audio_settings, theme=self.theme)
        self.root.wait_window(dialog)
        if dialog.result:
            old_settings = self.audio_settings.copy()
            self.audio_settings = dialog.result
            if (old_settings.get('input_device_index')  != self.audio_settings.get('input_device_index') or
                    old_settings.get('output_device_index') != self.audio_settings.get('output_device_index')):
                self.restart_audio_streams()
            self.save_config()
            self.display_system_message("✓ Audio settings updated")

    def restart_audio_streams(self):
        for stream in [self.stream_in, self.stream_out]:
            if stream:
                try: stream.stop_stream(); stream.close()
                except: pass
        self.stream_in = None; self.stream_out = None

    def clear_saved_password(self):
        self.saved_password = None; self.save_config()
        messagebox.showinfo("Password Cleared", "Saved password has been cleared.")

    # ── Voice ────────────────────────────────────────────────────

    def start_voice(self, event=None):
        if self.voice_active or not self.authenticated: return
        self.voice_active = True
        self.voice_btn.config(bg=self.theme['voice_active_bg'], fg=self.theme['voice_active_fg'],
                              text="🔴 TRANSMITTING...")
        try: self.tcp_sock.send((json.dumps({'type': 'voice_start'}) + '\n').encode())
        except: pass
        if self.stream_in is None:
            try:
                device_index = self.audio_settings.get('input_device_index', None)
                opened = False; last_error = None
                for rate in SUPPORTED_RATES:
                    try:
                        self.stream_in = self.p.open(format=FORMAT, channels=CHANNELS, rate=rate,
                                                      input=True, input_device_index=device_index,
                                                      frames_per_buffer=CHUNK)
                        self.current_input_rate = rate; opened = True; break
                    except Exception as e: last_error = e
                if not opened: raise Exception(f"Failed to open mic. Last error: {last_error}")
            except Exception as e:
                messagebox.showerror("Audio Error", f"Failed to open microphone: {str(e)}")
                self.voice_active = False
                self.voice_btn.config(bg=self.theme['voice_idle_bg'], fg=self.theme['voice_idle_fg'],
                                      text=self.voice_btn_text)
                return
        threading.Thread(target=self.send_audio, daemon=True).start()

    def stop_voice(self, event=None):
        if not self.voice_active: return
        self.voice_active = False
        self.voice_btn.config(bg=self.theme['voice_idle_bg'], fg=self.theme['voice_idle_fg'],
                              text=self.voice_btn_text)
        try: self.tcp_sock.send((json.dumps({'type': 'voice_stop'}) + '\n').encode())
        except: pass

    def send_audio(self):
        while self.voice_active and self.running:
            try:
                data = self.stream_in.read(CHUNK, exception_on_overflow=False)
                volume = self.audio_settings.get('input_volume', 100) / 100
                if volume != 1.0:
                    try:
                        import numpy as np
                        audio_data = np.frombuffer(data, dtype=np.int16)
                        data = (audio_data * volume).astype(np.int16).tobytes()
                    except ImportError: pass
                self.udp_sock.sendto(data, (self.server_ip, SERVER_UDP_PORT))
            except Exception as e: print(f"Error sending audio: {e}"); break

    # ── Cleanup ──────────────────────────────────────────────────

    def on_close(self):
        if self._closing: return
        self._closing = True
        self.running  = False

        # Stop the tray icon first so it doesn't linger
        if self.tray_icon:
            try: self.tray_icon.stop()
            except: pass

        for attr in ('keyboard_listener', 'mouse_listener'):
            listener = getattr(self, attr, None)
            if listener:
                try: listener.stop()
                except: pass

        for stream in [getattr(self, 'stream_in', None), getattr(self, 'stream_out', None)]:
            if stream:
                try: stream.stop_stream(); stream.close()
                except: pass

        if hasattr(self, 'p'):
            try: self.p.terminate()
            except: pass

        for sock in [getattr(self, 'tcp_sock', None), getattr(self, 'udp_sock', None)]:
            if sock:
                try: sock.close()
                except: pass

        self.root.destroy()


if __name__ == '__main__':
    HavenClient()
