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
import re
import urllib.request
import urllib.parse
import io
import webbrowser
from datetime import datetime
import hashlib
import random
from pynput import keyboard, mouse

# ═══════════════════════════════════════════════════════════════════════════════
# PYINSTALLER BUILD NOTE
# Directory layout (dev):
#   root/
#     haven_client.py        ← this file
#     haven_config.json      ← auto-created on first run
#     themes/
#       haven.ico
#       default.json
#       angel.json  ...etc
#     bin/
#       haven_crypto.py
#     server/                ← NOT bundled with client
#       haven_server.py
#
# Build command (from root/):
#   pyinstaller --onefile --noconsole --icon=themes/haven.ico \
#       --add-data "themes;themes" \
#       --add-data "bin/haven_crypto.py;." \
#       --name Haven haven_client.py
#
# Notes:
#   • --add-data "themes;themes"           bundles the whole themes/ folder
#   • --add-data "bin/haven_crypto.py;."   drops crypto module flat into _MEIPASS
#     (resource_path and the sys.path insert both handle _MEIPASS correctly)
#   • haven_config.json is written next to the .exe at runtime — not bundled
#   • The server/ folder is never part of the client build
# ═══════════════════════════════════════════════════════════════════════════════


# Tray icon support — requires: pip install pystray pillow
try:
    import pystray
    from PIL import Image, ImageTk
    TRAY_AVAILABLE = True
    PIL_AVAILABLE  = True
except ImportError:
    try:
        from PIL import Image, ImageTk
        PIL_AVAILABLE = True
    except ImportError:
        PIL_AVAILABLE = False
    TRAY_AVAILABLE = False
    print("pystray/Pillow not installed — system tray disabled. Run: pip install pystray pillow")

# Password hashing is handled by haven_crypto (Argon2id or PBKDF2).
# No direct argon2 import needed here.

# ── PQ Hybrid Crypto ──────────────────────────────────────────────────────────
# Add bin/ directory to path so haven_crypto.py can be found in both dev and
# PyInstaller --onefile mode (where _MEIPASS flattens all files together).
if not getattr(sys, 'frozen', False):
    _bin_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bin')
    if _bin_dir not in sys.path:
        sys.path.insert(0, _bin_dir)

try:
    from haven_crypto import (
        generate_kyber_keypair, kyber_encapsulate,
        generate_x25519_keypair, x25519_exchange,
        derive_session_key, SessionCrypto,
        compute_wire_password_hash, compute_auth_response as _crypto_auth_response,
        pack_client_hello, unpack_server_hello,
        hash_password as _crypto_hash_pw,
        verify_password as _crypto_verify_pw,
        CRYPTO_AVAILABLE, ARGON2_AVAILABLE as _ARGON2,
    )
    HAVEN_CRYPTO = True
    print(f"  ✓ haven_crypto loaded (cryptography={'yes' if CRYPTO_AVAILABLE else 'stdlib'}, argon2={'yes' if _ARGON2 else 'no'})")
except ImportError as e:
    HAVEN_CRYPTO = False
    # No silent fallback — encryption is mandatory.
    # We define stubs so the module loads, but _attempt_connect will refuse to connect.
    def compute_wire_password_hash(p): return __import__('hashlib').sha256(p.encode()).hexdigest()
    def _crypto_auth_response(n, h): return __import__('hashlib').sha256(f"{n}:{h}".encode()).hexdigest()
    def _crypto_hash_pw(p): raise RuntimeError("haven_crypto not loaded")
    def _crypto_verify_pw(p, s): raise RuntimeError("haven_crypto not loaded")
    print(f"\n  ✗ FATAL: haven_crypto not found — {e}")
    print(f"  Haven requires haven_crypto.py in the bin/ directory.")
    print(f"  Connection to server will be refused until this is resolved.\n")

# ---------- Configuration ----------
SERVER_TCP_PORT = 5000
SERVER_UDP_PORT = 5001
CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'haven_config.json'
) if not getattr(sys, 'frozen', False) else os.path.join(
    os.path.dirname(sys.executable), 'haven_config.json'
)
MAX_TCP_BUFFER = 131072  # larger for encrypted payloads
# -----------------------------------

# ═══════════════════════════════════════════════════════════════════════════════
# PyInstaller resource path helper
# ═══════════════════════════════════════════════════════════════════════════════

def resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller --onefile.
    In dev: relative to the directory containing haven_client.py (root).
    In PyInstaller --onefile: relative to _MEIPASS (all bundled flat).
    """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, relative_path)

def get_exe_path():
    if getattr(sys, 'frozen', False):
        return [sys.executable]
    else:
        return [sys.executable, sys.argv[0]]

THEMES_DIR = resource_path('themes')
ICON_FILE  = os.path.join(THEMES_DIR, 'haven.ico')

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

IMAGE_EXTS = ('.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp')
URL_RE     = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)

EMOJI_CATEGORIES = {
    "😀": ["😀","😁","😂","🤣","😃","😄","😅","😆","😉","😊","😋","😎","😍","🥰","😘",
           "😗","😙","😚","🙂","🤗","🤩","🤔","🤨","😐","😑","😶","🙄","😏","😣","😥",
           "😮","🤐","😯","😪","😫","🥱","😴","😌","😛","😜","😝","🤤","😒","😓","😔",
           "😕","🙃","🤑","😲","☹️","🙁","😖","😞","😟","😤","😢","😭","😦","😧","😨",
           "😩","🤯","😬","😰","😱","🥵","🥶","😳","🤪","😵","😡","😠","🤬","😷","🤒"],
    "👍": ["👍","👎","👌","🤌","✌️","🤞","🤟","🤘","🤙","👈","👉","👆","🖕","👇","☝️",
           "👋","🤚","🖐️","✋","🖖","👏","🙌","🤲","🤝","🙏","✍️","💪","🦾","🦿","🦵"],
    "❤️": ["❤️","🧡","💛","💚","💙","💜","🖤","🤍","🤎","💔","❣️","💕","💞","💓","💗",
           "💖","💘","💝","💟","☮️"],
    "🔥": ["🔥","💯","✨","⚡","🌈","🎉","🎊","🎈","🎁","🏆","🥇","🎯","🎮","🕹️","🎲",
           "🃏","🎴","🀄","🎭","🎨","🎬","🎤","🎧","🎵","🎶","🎸","🎹","🎺","🎻","🥁",
           "💻","📱","⌨️","🖥️","🖨️","🖱️","💾","💿","📀","📷"],
    "🌍": ["🌍","🌎","🌏","🌙","🌟","⭐","🌠","☀️","🌤️","⛅","🌥️","🌦️","🌧️","⛈️","🌩️",
           "🌨️","❄️","☃️","⛄","🌊","🌀","🌈","🌂","🐶","🐱","🐭","🐹","🐰","🦊","🐻",
           "🐼","🐨","🐯","🦁","🐸","🐵","🙈","🙉","🙊","🐔","🐧","🐦"],
    "🍕": ["🍕","🍔","🍟","🌭","🍿","🧂","🥓","🥚","🍳","🧇","🥞","🧈","🍞","🥐","🥖",
           "🥨","🧀","🥗","🥙","🌮","🌯","🥫","🍝","🍜","🍲","🍛","🍣","🍱","🍤","🍙",
           "🍚","🍘","🍥","🥮","🍡","🧁","🍰","🎂","🍮","🍭","🍬","🍫","🍩","🍪"],
}


# ═══════════════════════════════════════════════════════════════════════════════
# Password helpers — Argon2id for local config storage (quantum-resistant KDF)
# Wire protocol uses challenge-response with SHA-256 (unchanged server compat)
# ═══════════════════════════════════════════════════════════════════════════════

def hash_password_for_storage(password: str) -> str:
    """Hash a password for LOCAL config storage only. Never sent over the wire.
    Delegates to haven_crypto (Argon2id or PBKDF2) when available,
    falls back to PBKDF2-SHA256 via stdlib."""
    if HAVEN_CRYPTO:
        return _crypto_hash_pw(password)
    salt = os.urandom(16)
    dk   = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000, dklen=32)
    return "pbkdf2:" + salt.hex() + ":" + dk.hex()


def verify_stored_password(password: str, stored: str) -> bool:
    """Verify a plaintext password against a stored hash."""
    if HAVEN_CRYPTO:
        return _crypto_verify_pw(password, stored)
    import hmac as _hmac
    if stored.startswith("pbkdf2:"):
        parts = stored.split(":")
        if len(parts) != 3: return False
        salt = bytes.fromhex(parts[1]); expected = bytes.fromhex(parts[2])
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000, dklen=32)
        return _hmac.compare_digest(dk, expected)
    return _hmac.compare_digest(stored, hashlib.sha256(password.encode()).hexdigest())


# ─── Link preview / image fetch ───────────────────────────────────────────────

def is_image_url(url: str) -> bool:
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in IMAGE_EXTS)

def fetch_link_preview(url: str) -> dict:
    result = {'title': '', 'description': '', 'image_url': '', 'url': url}
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (HavenChat/2.2)'})
        with urllib.request.urlopen(req, timeout=6) as r:
            if 'text/html' not in r.headers.get('Content-Type', ''):
                return result
            raw = r.read(65536).decode('utf-8', errors='replace')
        for pat in [r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']',
                    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:title["\']',
                    r'<title[^>]*>([^<]+)</title>']:
            m = re.search(pat, raw, re.IGNORECASE)
            if m: result['title'] = m.group(1).strip()[:120]; break
        for pat in [r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']',
                    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:description["\']',
                    r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']']:
            m = re.search(pat, raw, re.IGNORECASE)
            if m: result['description'] = m.group(1).strip()[:200]; break
        for pat in [r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']',
                    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']']:
            m = re.search(pat, raw, re.IGNORECASE)
            if m: result['image_url'] = m.group(1).strip(); break
    except Exception:
        pass
    return result

def fetch_image_bytes(url: str, max_bytes: int = 2_000_000):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (HavenChat/2.2)'})
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.read(max_bytes)
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# TLS helper
# ═══════════════════════════════════════════════════════════════════════════════

def create_tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ═══════════════════════════════════════════════════════════════════════════════
# Challenge-response auth helpers (wire protocol — server unchanged)
# ═══════════════════════════════════════════════════════════════════════════════

def compute_password_hash(password):
    """Wire hash (SHA-256 of password). Used only on the wire, never stored."""
    return compute_wire_password_hash(password)

def compute_auth_response(nonce, password_hash):
    """Compute challenge-response for wire auth."""
    return _crypto_auth_response(nonce, password_hash)


# ═══════════════════════════════════════════════════════════════════════════════
# Tray icon helpers
# ═══════════════════════════════════════════════════════════════════════════════

def load_tray_image():
    if TRAY_AVAILABLE:
        if os.path.exists(ICON_FILE):
            try:
                return Image.open(ICON_FILE).convert('RGBA')
            except Exception as e:
                print(f"Could not load tray icon from file: {e}")
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
# Window icon helper — applies haven.ico to any window
# ═══════════════════════════════════════════════════════════════════════════════

def apply_window_icon(window):
    """Replace the default tkinter feather icon with haven.ico on any window."""
    if os.path.exists(ICON_FILE):
        try:
            window.iconbitmap(ICON_FILE)
            return
        except Exception:
            pass
    # PIL fallback (Linux / macOS)
    if PIL_AVAILABLE and os.path.exists(ICON_FILE):
        try:
            img   = Image.open(ICON_FILE).resize((32, 32))
            photo = ImageTk.PhotoImage(img)
            window.iconphoto(True, photo)
            window._icon_ref = photo
        except Exception:
            pass


def make_scrollbar(parent, theme, orient=tk.VERTICAL, command=None):
    """
    Create a themed ttk.Scrollbar that respects theme colors on Windows.
    tk.Scrollbar ignores bg/troughcolor on Windows (uses native rendering).
    We configure the built-in Vertical.TScrollbar / Horizontal.TScrollbar styles
    directly — custom style names require registered layouts which vary by platform.
    """
    t = theme
    s = ttk.Style()
    try:
        s.theme_use('clam')
    except Exception:
        pass

    for sn in ('Vertical.TScrollbar', 'Horizontal.TScrollbar'):
        s.configure(sn,
                    background=t['scrollbar_bg'],
                    troughcolor=t['scrollbar_trough'],
                    arrowcolor=t['fg_color'],
                    bordercolor=t['scrollbar_bg'],
                    darkcolor=t['scrollbar_bg'],
                    lightcolor=t['scrollbar_bg'],
                    gripcount=0,
                    relief=tk.FLAT)
        s.map(sn, background=[('active', t['accent_1']), ('pressed', t['accent_1'])])

    sb = ttk.Scrollbar(parent, orient=orient)
    if command:
        sb.configure(command=command)
    return sb


# ═══════════════════════════════════════════════════════════════════════════════
# Themed custom titlebar helper
# Used by ALL setting dialogs so they look consistent and feather-icon free.
# ═══════════════════════════════════════════════════════════════════════════════

def build_themed_titlebar(window, theme, title_text, on_close=None):
    """
    Attach a matching themed titlebar to *window*.
    window.overrideredirect(True) must already be set.
    Returns the titlebar Frame.
    """
    t = theme
    close_cmd = on_close if on_close else window.destroy

    tb = tk.Frame(window, bg=t['titlebar_bg'], height=35)
    tb.pack(fill=tk.X, side=tk.TOP)
    tb.pack_propagate(False)

    # Title text only — no icon in sub-window titlebars
    tk.Label(tb, text=title_text, bg=t['titlebar_bg'], fg=t['titlebar_fg'],
             font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(12, 10), pady=5)
    tk.Button(tb, text="✕", bg=t['titlebar_bg'], fg=t['titlebar_fg'],
              font=('Segoe UI', 14), bd=0,
              activebackground=t['accent_2'], activeforeground='#fff',
              command=close_cmd, cursor='hand2',
              padx=8, pady=0).pack(side=tk.RIGHT, padx=5)

    tk.Frame(window, bg=t['titlebar_sep'], height=1).pack(fill=tk.X, side=tk.TOP)

    # Drag support
    window._dx = window._dy = None
    def _s(e): window._dx = e.x; window._dy = e.y
    def _e(e): window._dx = None; window._dy = None
    def _m(e):
        if window._dx is not None:
            window.geometry(f"+{window.winfo_x()+e.x-window._dx}+{window.winfo_y()+e.y-window._dy}")
    tb.bind('<Button-1>', _s); tb.bind('<ButtonRelease-1>', _e); tb.bind('<B1-Motion>', _m)
    return tb


# ═══════════════════════════════════════════════════════════════════════════════
# Emoji picker
# ═══════════════════════════════════════════════════════════════════════════════

class EmojiPicker(tk.Toplevel):
    """Floating emoji picker that calls callback(emoji) on selection."""
    def __init__(self, parent, theme, callback, anchor):
        super().__init__(parent)
        self.t = theme; self.cb = callback
        self.overrideredirect(True)
        self.configure(bg=self.t['glass_bg'])
        anchor.update_idletasks()
        ax = anchor.winfo_rootx(); ay = anchor.winfo_rooty()
        self.geometry(f"320x330+{max(0, ax - 260)}+{max(0, ay - 338)}")
        self.lift()

        tab = tk.Frame(self, bg=self.t['glass_accent'])
        tab.pack(fill=tk.X)
        self._body = tk.Frame(self, bg=self.t['glass_bg'])
        self._body.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        cats = list(EMOJI_CATEGORIES.keys())
        self._show(cats[0])
        for cat in cats:
            tk.Button(tab, text=cat, font=('Segoe UI', 13),
                      bg=self.t['glass_accent'], fg=self.t['fg_color'],
                      relief=tk.FLAT, bd=0, cursor='hand2', padx=4, pady=4,
                      command=lambda c=cat: self._show(c),
                      activebackground=self.t['accent_3']).pack(side=tk.LEFT)

        self.bind('<FocusOut>', lambda e: self.after(150, self._chk))
        self.focus_set()

    def _chk(self):
        try:
            if self.focus_get() is None: self.destroy()
        except Exception: self.destroy()

    def _show(self, cat):
        for w in self._body.winfo_children(): w.destroy()
        cv = tk.Canvas(self._body, bg=self.t['glass_bg'], highlightthickness=0)
        sb = make_scrollbar(self._body, self.t, orient=tk.VERTICAL, command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y); cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        grid = tk.Frame(cv, bg=self.t['glass_bg'])
        cw   = cv.create_window((0, 0), window=grid, anchor='nw')
        grid.bind('<Configure>', lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind('<Configure>',   lambda e: cv.itemconfig(cw, width=e.width))
        cv.bind('<MouseWheel>',  lambda e: cv.yview_scroll(int(-1*(e.delta/120)), "units"))
        cols = 8
        for i, em in enumerate(EMOJI_CATEGORIES[cat]):
            tk.Button(grid, text=em, font=('Segoe UI', 16),
                      bg=self.t['glass_bg'], fg=self.t['fg_color'],
                      relief=tk.FLAT, bd=0, padx=2, pady=2, cursor='hand2',
                      activebackground=self.t['glass_accent'],
                      command=lambda e=em: self._pick(e)).grid(row=i//cols, column=i%cols, padx=1, pady=1)

    def _pick(self, em): self.cb(em); self.destroy()


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

        self.title("Haven - Connect")
        self.configure(bg=self.t['login_bg'])
        self.resizable(False, False)
        self.overrideredirect(True)
        self.geometry("420x560")

        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 210
        y = (self.winfo_screenheight() // 2) - 280
        self.geometry(f'420x560+{x}+{y}')

        # Apply haven.ico even to overrideredirect windows (may not show on all platforms)
        apply_window_icon(self)

        self.grab_set()
        self.lift()
        self.focus_force()

        # Custom title bar
        title_bar = tk.Frame(self, bg=self.t['titlebar_bg'], height=35)
        title_bar.pack(fill=tk.X, side=tk.TOP)
        title_bar.pack_propagate(False)

        tk.Label(title_bar, text="Haven", bg=self.t['titlebar_bg'],
                 fg=self.t['titlebar_fg'], font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT, padx=(12, 0), pady=5)

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

        tk.Label(self, text="HAVEN", bg=self.t['login_bg'], fg=self.t['login_title_fg'],
                 font=('Segoe UI', 22, 'bold')).pack(pady=(25, 5))
        tk.Label(self, text="Welcome Home", bg=self.t['login_bg'], fg=self.t['login_sub_fg'],
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
        self.configure(bg=self.t['glass_bg'],
                       highlightthickness=2,
                       highlightbackground=self.t['accent_1'])
        self.resizable(False, True)
        self.overrideredirect(True)
        self.update_idletasks()
        self.geometry("340x520")
        x = (self.winfo_screenwidth() // 2) - 170
        y = (self.winfo_screenheight() // 2) - 260
        self.geometry(f'340x520+{x}+{y}')
        self.transient(parent)
        self.grab_set()
        apply_window_icon(self)

        build_themed_titlebar(self, theme, "Choose Theme")

        tk.Label(self, text="Choose Theme", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 14, 'bold')).pack(pady=16)

        outer = tk.Frame(self, bg=self.t['glass_bg'])
        outer.pack(fill=tk.BOTH, expand=True, padx=20)

        canvas = tk.Canvas(outer, bg=self.t['glass_bg'], highlightthickness=0)
        scrollbar = make_scrollbar(outer, theme, orient=tk.VERTICAL, command=canvas.yview)
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
# Standard dialogs (theme-aware, no feather icon)
# ═══════════════════════════════════════════════════════════════════════════════

class ModernInputDialog(tk.Toplevel):
    """
    A fully themed input dialog that replaces simpledialog.Dialog.
    Supports custom titlebar (no feather), haven.ico, and theme colors.
    """
    def __init__(self, parent, title, prompt, theme=None, show='', default=''):
        super().__init__(parent)
        self.result = None
        self.t = theme or _fallback_theme()

        self.configure(bg=self.t['glass_bg'],
                       highlightthickness=2,
                       highlightbackground=self.t['accent_1'])
        self.resizable(False, False)
        self.overrideredirect(True)
        self.geometry("400x220")
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 200
        y = (self.winfo_screenheight() // 2) - 110
        self.geometry(f'400x220+{x}+{y}')
        self.transient(parent)
        self.grab_set()
        apply_window_icon(self)

        build_themed_titlebar(self, self.t, title)

        tk.Label(self, text=prompt, bg=self.t['glass_bg'], fg=self.t['fg_color'],
                 font=('Segoe UI', 11)).pack(padx=30, pady=(20, 10))

        entry_frame = tk.Frame(self, bg=self.t['glass_accent'], highlightthickness=2,
                               highlightbackground=self.t['accent_1'])
        entry_frame.pack(fill=tk.X, padx=30)

        self.entry = tk.Entry(entry_frame, bg=self.t['glass_accent'], fg=self.t['fg_color'],
                              insertbackground=self.t['accent_1'], font=('Segoe UI', 11),
                              show=show, relief=tk.FLAT, bd=0)
        self.entry.pack(fill=tk.X, padx=8, pady=8)
        if default:
            self.entry.insert(0, default)

        btn_frame = tk.Frame(self, bg=self.t['glass_bg'])
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="OK", bg=self.t['accent_1'], fg=self.t['send_btn_fg'],
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  command=self._ok, padx=30, pady=8, cursor='hand2').pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", bg=self.t['accent_2'], fg='#fff',
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  command=self.destroy, padx=20, pady=8, cursor='hand2').pack(side=tk.LEFT, padx=10)

        self.entry.bind('<Return>', lambda e: self._ok())
        self.entry.bind('<Escape>', lambda e: self.destroy())
        self.entry.focus_set()

    def _ok(self):
        self.result = self.entry.get()
        self.destroy()


class KeybindDialog(tk.Toplevel):
    def __init__(self, parent, current_key, theme=None):
        super().__init__(parent)
        self.result = current_key; self.listening = False
        self.captured_key = None; self.t = theme or _fallback_theme()
        self.configure(bg=self.t['glass_bg'],
                       highlightthickness=2,
                       highlightbackground=self.t['accent_1'])
        self.resizable(False, False)
        self.overrideredirect(True)
        self.geometry("450x560")
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 225
        y = (self.winfo_screenheight() // 2) - 280
        self.geometry(f'450x560+{x}+{y}')
        self.transient(parent); self.grab_set()
        apply_window_icon(self)

        build_themed_titlebar(self, self.t, "Set Push-to-Talk Key")

        tk.Label(self, text="Choose Push-to-Talk Key", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 14, 'bold')).pack(pady=18)
        tk.Label(self, text=f"Current: {self.format_key_display(current_key)}",
                 bg=self.t['glass_bg'], fg=self.t['fg_color'], font=('Segoe UI', 10)).pack(pady=4)

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
        self.listen_btn = tk.Button(custom_frame, text="Click to Capture",
                                    bg=self.t['accent_3'], fg='#fff',
                                    font=('Segoe UI', 11, 'bold'), relief=tk.FLAT,
                                    command=self.start_listening, padx=20, pady=12, cursor='hand2',
                                    activebackground=self.t['accent_2'])
        self.listen_btn.pack()
        self.capture_label = tk.Label(custom_frame, text="Press any key or mouse button...",
                                      bg=self.t['glass_bg'], fg=self.t['accent_4'],
                                      font=('Segoe UI', 9, 'italic'))
        self.capture_label.pack(pady=5)
        tk.Button(self, text="Return", bg=self.t['accent_2'], fg='#fff',
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
        self.configure(bg=self.t['glass_bg'],
                       highlightthickness=2,
                       highlightbackground=self.t['accent_1'])
        self.resizable(False, False)
        self.overrideredirect(True)
        self.geometry("380x470")
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 190
        y = (self.winfo_screenheight() // 2) - 235
        self.geometry(f'380x470+{x}+{y}')
        self.transient(parent); self.grab_set()
        apply_window_icon(self)

        build_themed_titlebar(self, self.t, "Choose Username Color")
        tk.Label(self, text="Choose Your Name Color", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 14, 'bold')).pack(pady=18)
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
        self.configure(bg=self.t['glass_bg'],
                       highlightthickness=2,
                       highlightbackground=self.t['accent_1'])
        self.resizable(False, False)
        self.overrideredirect(True)
        self.geometry("500x680")
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 250
        y = (self.winfo_screenheight() // 2) - 340
        self.geometry(f'500x680+{x}+{y}')
        self.transient(parent); self.grab_set()
        apply_window_icon(self)

        build_themed_titlebar(self, self.t, "Audio Devices & Volume")
        tk.Label(self, text="🎧 AUDIO SETTINGS", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 16, 'bold')).pack(pady=16)
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
        style = ttk.Style()
        style.theme_use('clam')
        bg = self.t['glass_accent']
        fg = self.t['fg_color']
        sel_bg = self.t['accent_1']
        sel_fg = self.t['send_btn_fg']
        style.configure("Haven.TCombobox",
                        fieldbackground=bg,
                        background=bg,
                        foreground=fg,
                        arrowcolor=self.t['accent_1'],
                        selectbackground=sel_bg,
                        selectforeground=sel_fg,
                        borderwidth=0,
                        relief=tk.FLAT,
                        insertcolor=fg)
        style.map("Haven.TCombobox",
                  fieldbackground=[('readonly', bg), ('disabled', bg)],
                  foreground=[('readonly', fg), ('disabled', fg)],
                  background=[('readonly', bg), ('active', bg)])
        combobox.configure(style="Haven.TCombobox")
        # Also style the dropdown listbox via option_add
        combobox.tk.eval(f'''
            option add *TCombobox*Listbox.background {bg}
            option add *TCombobox*Listbox.foreground {fg}
            option add *TCombobox*Listbox.selectBackground {sel_bg}
            option add *TCombobox*Listbox.selectForeground {sel_fg}
        ''')

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
            test_dialog.configure(bg=self.t['glass_bg']); test_dialog.geometry("300x220")
            test_dialog.overrideredirect(True)
            apply_window_icon(test_dialog)
            build_themed_titlebar(test_dialog, self.t, "Microphone Test",
                                  on_close=lambda: close_test())
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

        # Resolve device index from the display string ("Device N: Name" or "Default (...)")
        for device_key, index_key in (('input_device', 'input_device_index'),
                                       ('output_device', 'output_device_index')):
            device_str = self.result[device_key]
            if device_str and not device_str.startswith("Default"):
                try:
                    self.result[index_key] = int(device_str.split("Device ")[1].split(":")[0])
                except (IndexError, ValueError):
                    self.result[index_key] = None
            else:
                self.result[index_key] = None
        self.destroy()


# ═══════════════════════════════════════════════════════════════════════════════
# About dialog — themed, feather-free
# ═══════════════════════════════════════════════════════════════════════════════

class AboutDialog(tk.Toplevel):
    def __init__(self, parent, theme, theme_name):
        super().__init__(parent)
        self.t = theme
        self.configure(bg=self.t['glass_bg'],
                       highlightthickness=2,
                       highlightbackground=self.t['accent_1'])
        self.resizable(False, False)
        self.overrideredirect(True)
        self.geometry("480x500")
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 240
        y = (self.winfo_screenheight() // 2) - 250
        self.geometry(f'480x500+{x}+{y}')
        self.transient(parent); self.grab_set()
        apply_window_icon(self)

        build_themed_titlebar(self, self.t, "About Haven")

        tk.Label(self, text="HAVEN", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 20, 'bold')).pack(pady=(20, 4))
        tk.Label(self, text="v3", bg=self.t['glass_bg'], fg=self.t['accent_4'],
                 font=('Segoe UI', 11)).pack()
        tk.Label(self, text=f"Current theme: {theme.get('name', theme_name)}",
                 bg=self.t['glass_bg'], fg=self.t['fg_color'],
                 font=('Segoe UI', 10, 'italic')).pack(pady=(4, 16))

        tk.Frame(self, bg=self.t['titlebar_sep'], height=1).pack(fill=tk.X, padx=30)

        body = tk.Frame(self, bg=self.t['glass_accent'])
        body.pack(fill=tk.BOTH, expand=True, padx=24, pady=16)

        tk.Label(body, text="A hopefully secure voice & text chat client\nwith vibes and dreams.",
                 bg=self.t['glass_accent'], fg=self.t['fg_color'],
                 font=('Segoe UI', 10), justify=tk.CENTER).pack(pady=(16, 12))

        tk.Frame(body, bg=self.t['titlebar_sep'], height=1).pack(fill=tk.X, padx=20)

        tk.Label(body,
                 text=("✨ By downloading, installing, or using this software you affirm to uphold "
                       "truth, justice, equity, and the democratic ideals of the American way. You "
                       "commit to defend and respect the sovereignty, self-determination, and human "
                       "rights of all peoples — Ukraine, Palestine, Taiwan, Hong Kong, Tibet, Sudan, "
                       "and every nation or community striving toward freedom and dignity. You affirm "
                       "the right of every person to live authentically, free from discrimination "
                       "regardless of race, creed, sexual orientation, or gender identity. You stand "
                       "against oppression, misinformation, and authoritarianism in all forms. ✨"),
                 bg=self.t['glass_accent'], fg=self.t['accent_4'],
                 font=('Segoe UI', 8), justify=tk.LEFT, wraplength=408, padx=16, pady=12
                 ).pack(fill=tk.X)

        tk.Button(self, text="Close", bg=self.t['accent_1'], fg=self.t['send_btn_fg'],
                  font=('Segoe UI', 11, 'bold'), relief=tk.FLAT,
                  command=self.destroy, padx=40, pady=10, cursor='hand2').pack(pady=16)


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
        self.open_mic_active = False
        self.session_crypto  = None   # SessionCrypto — set after PQ handshake
        self.saved_wire_hash = None   # SHA256(password) for reconnect — never plaintext

        # UI widget refs (set in build_ui, cleared in rebuild_ui)
        self.canvas_bg       = None
        self.chat_text       = None
        self.msg_entry       = None
        self.voice_btn       = None
        self.open_mic_btn    = None
        self.emoji_btn       = None
        self.status_label    = None
        self.user_list_frame = None
        self.speaker_labels  = {}
        self._emoji_picker   = None

        # Structured message log for clean redraw on theme switch
        self._msg_log: list = []
        # PIL image references (prevent garbage collection)
        self._images: list  = []

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

        # ── Password recovery from config ────────────────────────────
        # We store two separate values:
        #   password_hash      — Argon2id/PBKDF2 (verify only, never sent anywhere)
        #   password_wire_hash — SHA256(password) (used for auto-reconnect challenge-response)
        # Plaintext is NEVER written to disk. Legacy 'password_plain' keys are purged here.
        saved_wire_hash = config.get('password_wire_hash', '')

        # Migrate legacy plaintext if present — compute wire hash from it, then delete it
        legacy_plain = config.get('password_plain', '')
        if legacy_plain and not saved_wire_hash:
            saved_wire_hash = compute_password_hash(legacy_plain)
            config['password_wire_hash'] = saved_wire_hash
            config.pop('password_plain', None)
            config.pop('password', None)
            # Upgrade storage hash too while we're here
            if not config.get('password_hash', '').startswith(('argon2:', 'pbkdf2:')):
                config['password_hash'] = hash_password_for_storage(legacy_plain)
            self.save_config()
            print("  ✓ Migrated legacy plaintext password — plaintext removed from config.")
        elif legacy_plain:
            # Wire hash already exists, just purge the plaintext
            config.pop('password_plain', None)
            config.pop('password', None)
            self.save_config()

        connected = False
        if server_ip and saved_username and saved_wire_hash:
            result = self._attempt_connect(server_ip, saved_username, password='', wire_hash=saved_wire_hash)
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
        self.root.title("Haven")
        self.root.geometry("900x850")
        self.root.minsize(800, 500)
        self.root.overrideredirect(True)
        self.root.lift()
        self.root.focus_force()
        self.root.attributes('-topmost', True)
        self.root.after(100, lambda: self.root.attributes('-topmost', False))
        self.root.configure(bg=self.theme['bg_color'])
        apply_window_icon(self.root)

        self.build_ui()

        self.p            = pyaudio.PyAudio()
        self.stream_in    = None
        self.stream_out   = None
        self.voice_active = False
        self.active_speakers = set()

        self._start_tray()

        threading.Thread(target=self.receive_tcp, daemon=True).start()
        threading.Thread(target=self.receive_udp, daemon=True).start()

        self.setup_global_hotkey()
        self.root.protocol("WM_DELETE_WINDOW", self.minimize_to_tray)
        self.root.mainloop()

    # ── System Tray ──────────────────────────────────────────────

    def _start_tray(self):
        if not TRAY_AVAILABLE:
            return
        img = load_tray_image()
        if img is None:
            return
        menu = pystray.Menu(
            pystray.MenuItem('Haven', self._tray_restore, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Restore', self._tray_restore),
            pystray.MenuItem('Quit',    self._tray_quit),
        )
        self.tray_icon = pystray.Icon('haven_chat', img, 'Haven', menu)
        tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
        tray_thread.start()

    def _tray_restore(self, icon=None, item=None):
        self.root.after(0, self._show_window)

    def _tray_quit(self, icon=None, item=None):
        self.root.after(0, self.on_close)

    def _show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.root.attributes('-topmost', True)
        self.root.after(100, lambda: self.root.attributes('-topmost', False))

    def minimize_to_tray(self):
        self.root.withdraw()

    # ── Theme ────────────────────────────────────────────────────

    def apply_theme(self, theme_name):
        self.theme_name = theme_name
        self.theme      = load_theme(theme_name)
        self.save_config()
        self.rebuild_ui()

    def rebuild_ui(self):
        """Tear down and rebuild all UI widgets, replaying the message log."""
        for widget in self.root.winfo_children():
            try: widget.destroy()
            except: pass

        self.canvas_bg = self.chat_text = self.msg_entry = self.voice_btn = None
        self.open_mic_btn = self.emoji_btn = self.status_label = self.user_list_frame = None
        self.speaker_labels = {}
        self._images = []

        self.root.configure(bg=self.theme['bg_color'])
        self.build_ui()

        # Replay structured message log directly to _render_* to avoid re-logging
        for entry in self._msg_log:
            tp = entry['type']
            if tp == 'system':
                self._render_sys(entry['text'], entry['timestamp'])
            elif tp == 'chat':
                self._render_chat(entry['user'], entry['text'],
                                  entry.get('align', 'left'), entry['timestamp'], entry.get('color'))
            elif tp == 'image':
                self._render_image(entry['url'], entry['user'],
                                   entry['timestamp'], entry.get('color'))
            elif tp == 'link':
                self._render_link(entry['url'], entry['user'],
                                  entry['timestamp'], entry.get('color'))

        if self.chat_text:
            self.chat_text.see(tk.END)

        self.update_userlist_with_colors(
            [{'username': u, 'color': c} for u, c in self.user_colors.items()])
        self.display_system_message(f"✓ Theme changed to {self.theme.get('name', self.theme_name)}")

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
                    # Argon2/PBKDF2 hash — strong storage, never leaves disk
                    config['password_hash']      = hash_password_for_storage(data['password'])
                    # Wire hash — SHA256(password), all we need for auto-reconnect.
                    # Not reversible to plaintext; not usable as a password anywhere else.
                    config['password_wire_hash'] = compute_password_hash(data['password'])
                else:
                    # Clear all password data (including any legacy plaintext)
                    for k in ('password_hash', 'password_wire_hash', 'password_plain', 'password'):
                        config.pop(k, None)
                self.server_ip       = data['server_ip']
                self.username        = data['username']
                # Keep wire hash in memory only — plaintext is never stored anywhere
                self.saved_wire_hash = compute_password_hash(data['password']) if data['remember'] else None
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

    def _attempt_connect(self, server_ip, username, password, wire_hash=None):
        """Connect and authenticate.
        `password`  — plaintext, used when the user just typed it in the login box.
        `wire_hash` — pre-computed SHA256(password) from saved config; if supplied,
                      plaintext is not needed and is never held in memory.
        """
        if not HAVEN_CRYPTO:
            return "Encryption module (haven_crypto.py) not found in bin/. Cannot connect."
        try:
            tls_ctx  = create_tls_context()
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(15)
            raw_sock.connect((server_ip, SERVER_TCP_PORT))
            tcp_sock = tls_ctx.wrap_socket(raw_sock, server_hostname=server_ip)

            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(('0.0.0.0', 0))
            udp_port = udp_sock.getsockname()[1]

            # Use pre-computed wire hash if available, otherwise derive from plaintext.
            # Either way plaintext never touches disk.
            password_hash = wire_hash if wire_hash else compute_password_hash(password)

            # ── Receive server hello (PQ handshake or legacy challenge) ──────
            buffer = ''
            server_msg = None
            while server_msg is None:
                chunk = tcp_sock.recv(8192).decode('utf-8', errors='replace')
                if not chunk:
                    raise ConnectionError("Server closed before hello")
                buffer += chunk
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    if not line: continue
                    try: msg = json.loads(line)
                    except json.JSONDecodeError: continue
                    if msg.get('type') in ('server_hello', 'challenge'):
                        server_msg = msg; break
                    elif msg.get('type') == 'error':
                        raise ConnectionError(msg.get('message', 'Server error'))

            nonce = server_msg['nonce']
            auth_response = compute_auth_response(nonce, password_hash)

            # ── PQ Hybrid KEM: encapsulate session key ────────────────────────
            # We require a proper server_hello with Kyber+X25519 keys.
            # If the server sends a legacy 'challenge' we refuse — no downgrade.
            if server_msg.get('type') != 'server_hello':
                raise ConnectionError(
                    "Server did not offer PQ encryption (got legacy challenge). "
                    "Update the server to the current Haven version."
                )
            try:
                srv_nonce, kyber_pk, srv_x25519_pub = unpack_server_hello(server_msg)
                kyber_ct, kyber_ss   = kyber_encapsulate(kyber_pk)
                client_x25519_priv, client_x25519_pub = generate_x25519_keypair()
                ecdh_ss              = x25519_exchange(client_x25519_priv, srv_x25519_pub)
                session_key          = derive_session_key(kyber_ss, ecdh_ss, nonce)
                session              = SessionCrypto(session_key)
                login_msg            = pack_client_hello(
                    auth_response, kyber_ct, client_x25519_pub,
                    username, udp_port, self.name_color)
            except ConnectionError:
                raise  # propagate the downgrade error as-is
            except Exception as e:
                raise ConnectionError(f"PQ handshake failed: {e}")

            tcp_sock.send((json.dumps(login_msg) + '\n').encode())

            # ── Wait for auth_ok ─────────────────────────────────────────────
            tcp_sock.settimeout(15)
            while True:
                chunk = tcp_sock.recv(8192).decode('utf-8', errors='replace')
                if not chunk:
                    raise ConnectionError("Server closed during auth")
                buffer += chunk
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    if not line: continue
                    try: msg = json.loads(line)
                    except json.JSONDecodeError: continue

                    if msg['type'] == 'auth_ok':
                        # Hard check: we must have a live session or we abort.
                        if session is None:
                            tcp_sock.close(); udp_sock.close()
                            return "Server accepted auth but did not complete PQ key exchange. Connection refused."
                        tcp_sock.settimeout(None)
                        self.tcp_sock    = tcp_sock
                        self.udp_sock    = udp_sock
                        self.udp_port    = udp_port
                        self.server_ip   = server_ip
                        self.username    = username
                        # Store wire hash only — plaintext is discarded from memory here
                        self.saved_wire_hash = wire_hash if wire_hash else compute_password_hash(password)
                        self.running     = True
                        self.authenticated = True
                        self._tcp_buffer = buffer
                        self.session_crypto = session
                        if 'user_color' in msg:
                            self.server_assigned_color = msg['user_color']
                            self.name_color = msg['user_color']
                        crypto_info = msg.get('crypto', {})
                        print(f"  ✓ E2E encryption active: {crypto_info.get('kem','?')} / {crypto_info.get('chat_enc','?')}")
                        return 'ok'
                    elif msg['type'] == 'auth_failed':
                        tcp_sock.close(); udp_sock.close(); return 'auth_failed'
                    elif msg['type'] == 'error':
                        tcp_sock.close(); udp_sock.close()
                        return msg.get('message', 'Server error')

        except ssl.SSLError as e:      return f'TLS error: {e}'
        except socket.timeout:         return 'Connection timed out'
        except ConnectionRefusedError: return 'Connection refused (is the server running?)'
        except Exception as e:         return str(e)

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
        # Never write plaintext. Store wire hash (SHA256) for reconnect only.
        config.pop('password_plain', None)   # purge any legacy plaintext key
        config.pop('password', None)
        if getattr(self, 'saved_wire_hash', None):
            config['password_wire_hash'] = self.saved_wire_hash
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)

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

    def lighten_color(self, color, amount=30):
        """Lighten a hex color by adding a fixed amount to each channel (clamped at 255)."""
        try:
            color = color.lstrip('#')
            if len(color) == 3: color = ''.join([c * 2 for c in color])
            r, g, b = int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)
            return f'#{min(r+amount,255):02x}{min(g+amount,255):02x}{min(b+amount,255):02x}'
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

        tk.Label(title_bar, text=" ", bg=t['titlebar_bg'],
                 fg=t['accent_1'], font=('Segoe UI', 14, 'bold')).pack(side=tk.LEFT, padx=(10, 0), pady=5)

        tk.Label(title_bar, text="HAVEN",
                 bg=t['titlebar_bg'], fg=t['titlebar_fg'],
                 font=('Segoe UI', 11, 'bold')).pack(side=tk.LEFT, padx=5, pady=5)

        self.settings_btn = tk.Button(title_bar, text="⚙ Settings",
                                          bg=t['titlebar_bg'], fg=t['titlebar_fg'],
                                          font=('Segoe UI', 9),
                                          activebackground=t['accent_3'],
                                          activeforeground=t['fg_color'],
                                          relief=tk.FLAT, bd=0, padx=8, pady=2,
                                          cursor='hand2',
                                          command=self._show_settings_menu)
        self.settings_btn.pack(side=tk.LEFT, padx=15, pady=5)
        self._settings_popup = None

        controls_frame = tk.Frame(title_bar, bg=t['titlebar_bg'])
        controls_frame.pack(side=tk.RIGHT, padx=5)

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

        for w in (title_bar,):
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

        scrollbar = make_scrollbar(chat_container, t, command=self.chat_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_text.config(yscrollcommand=scrollbar.set)

        # ── Message entry row ─────────────────────────────────────────────
        entry_container = tk.Frame(left_frame, bg=t['glass_accent'], height=50)
        entry_container.pack(fill=tk.X)
        entry_container.pack_propagate(False)
        entry_inner = tk.Frame(entry_container, bg=t['glass_accent'])
        entry_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.msg_entry = tk.Entry(entry_inner, bg=t['entry_bg'], fg=t['entry_fg'],
                                  insertbackground=t['accent_1'],
                                  font=('Segoe UI', 11), relief=tk.FLAT, bd=0)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.msg_entry.bind('<Return>', self.send_chat)

        # Emoji picker button
        self.emoji_btn = tk.Button(entry_inner, text="🔽",
                                   bg=t['glass_accent'], fg=t['fg_color'],
                                   font=('Segoe UI', 13), relief=tk.FLAT, bd=0,
                                   cursor='hand2', padx=6,
                                   activebackground=t['glass_bg'],
                                   command=self.open_emoji_picker)
        self.emoji_btn.pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(entry_inner, text="SEND ➤", bg=t['send_btn_bg'], fg=t['send_btn_fg'],
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT, bd=0,
                  cursor='hand2', activebackground=t['accent_4'],
                  command=self.send_chat, padx=20, pady=8).pack(side=tk.RIGHT)

        # ── Voice row — Open Mic (left, compact) + PTT (right, expanded) ──
        voice_container = tk.Frame(left_frame, bg=t['glass_accent'], height=60)
        voice_container.pack(fill=tk.X, pady=(10, 0))
        voice_container.pack_propagate(False)
        voice_inner = tk.Frame(voice_container, bg=t['glass_accent'])
        voice_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.update_voice_button_text()

        # Open Mic toggle — compact, sits to the left of PTT
        om_bg  = t['voice_active_bg'] if self.open_mic_active else t['voice_idle_bg']
        om_txt = "🔴 MIC ON" if self.open_mic_active else "🎙 OPEN MIC"
        self.open_mic_btn = tk.Button(voice_inner, text=om_txt,
                                      bg=om_bg, fg=t['voice_idle_fg'],
                                      font=('Segoe UI', 9, 'bold'), relief=tk.FLAT,
                                      cursor='hand2', activebackground=t['voice_active_bg'],
                                      bd=0, padx=10, pady=10,
                                      command=self.toggle_open_mic)
        self.open_mic_btn.pack(side=tk.LEFT, padx=(0, 8))

        # PTT button — takes all remaining space
        v_bg  = t['voice_active_bg'] if getattr(self, 'voice_active', False) else t['voice_idle_bg']
        v_fg  = t['voice_active_fg'] if getattr(self, 'voice_active', False) else t['voice_idle_fg']
        v_txt = "🔴 TRANSMITTING..." if getattr(self, 'voice_active', False) else self.voice_btn_text
        self.voice_btn = tk.Button(voice_inner, text=v_txt,
                                   bg=v_bg, fg=v_fg,
                                   font=('Segoe UI', 11, 'bold'), relief=tk.FLAT,
                                   cursor='hand2', activebackground=t['voice_active_bg'],
                                   bd=0, padx=20, pady=10)
        self.voice_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.voice_btn.bind('<ButtonPress>',   self.start_voice)
        self.voice_btn.bind('<ButtonRelease>', self.stop_voice)

        # ── User list panel ────────────────────────────────────────────────
        right_frame = tk.Frame(content, bg=t['userlist_bg'], width=200)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 10), pady=10)
        right_frame.pack_propagate(False)

        tk.Label(right_frame, text="ONLINE", bg=t['userlist_bg'],
                 fg=t['accent_4'], font=('Segoe UI', 12, 'bold')).pack(pady=(10, 15))

        user_list_container = tk.Frame(right_frame, bg=t['userlist_bg'])
        user_list_container.pack(fill=tk.BOTH, expand=True, padx=10)

        canvas = tk.Canvas(user_list_container, bg=t['userlist_bg'], highlightthickness=0)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar_users = make_scrollbar(user_list_container, t, orient=tk.VERTICAL,
                                          command=canvas.yview)
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
        dlg = AboutDialog(self.root, self.theme, self.theme_name)
        self.root.wait_window(dlg)

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

    def _is_ptt_key(self, key):
        """Return True if this pynput key object matches the configured PTT key."""
        if self.ptt_key in self.key_map:
            ptt = self.key_map[self.ptt_key]
            right = self.key_map.get(self.ptt_key[:-1] + 'R') if self.ptt_key.endswith('_L') else None
            return key == ptt or (right is not None and key == right)
        else:
            try:
                key_str = key.char if (hasattr(key, 'char') and key.char) else str(key)
                return key_str == self.ptt_key
            except Exception:
                return False

    def on_global_key_press(self, key):
        if self.open_mic_active: return
        # Always allow the PTT key through. For any other key, skip if a text
        # field has focus so normal typing isn't intercepted.
        if not self._is_ptt_key(key):
            try:
                focused = self.root.focus_get()
                if isinstance(focused, (tk.Entry, tk.Text)):
                    return
            except Exception:
                pass
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
        if self.open_mic_active: return
        if not self._is_ptt_key(key):
            try:
                focused = self.root.focus_get()
                if isinstance(focused, (tk.Entry, tk.Text)):
                    return
            except Exception:
                pass
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
        if self.open_mic_active: return
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
            if hasattr(self, 'saved_wire_hash'): self.saved_wire_hash = None
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
            # Skip echo of our own messages — already displayed locally in send_chat
            if msg['user'] == self.username:
                return
            if msg.get('encrypted') and self.session_crypto:
                plaintext = self.session_crypto.decrypt_chat(msg.get('ct', ''))
                if plaintext is None:
                    self.display_system_message("⚠ Could not decrypt a message — dropped")
                    return
            elif self.session_crypto:
                # Session is active but message arrived unencrypted — refuse it.
                # This prevents downgrade injection attacks.
                self.display_system_message("⚠ Dropped unencrypted message (encryption required)")
                return
            else:
                plaintext = msg.get('text', '')
            self.display_message(msg['user'], plaintext)
        elif msg['type'] == 'chat_history':
            # Clear in-memory log before loading authoritative server history
            self._msg_log.clear()
            if self.chat_text:
                self.chat_text.config(state=tk.NORMAL)
                self.chat_text.delete('1.0', tk.END)
                self.chat_text.config(state=tk.DISABLED)
            for chat_msg in msg['history']:
                user = chat_msg['user']
                text = chat_msg.get('text', '')
                # History is stored as plaintext server-side; handle encrypted entries if present
                if chat_msg.get('encrypted') and self.session_crypto and HAVEN_CRYPTO:
                    dec = self.session_crypto.decrypt_chat(chat_msg.get('ct', ''))
                    if dec: text = dec
                timestamp = chat_msg.get('timestamp'); stored_color = chat_msg.get('color')
                if user == 'System':
                    self.display_message(user, text, timestamp=timestamp,
                                         color=t['system_msg_color'])
                else:
                    if user not in self.user_colors and stored_color:
                        self.user_colors[user] = stored_color
                    display_color = stored_color or self.user_colors.get(user, t['accent_2'])
                    align = 'right' if user == self.username else 'left'
                    self.display_message(user, text, align=align,
                                         timestamp=timestamp, color=display_color)
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
                data, addr = self.udp_sock.recvfrom(8192)
                # Decrypt voice packet
                if self.session_crypto and HAVEN_CRYPTO:
                    data = self.session_crypto.decrypt_voice(data)
                    if data is None:
                        continue  # Drop tampered/invalid packet silently
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
                if self.session_crypto and HAVEN_CRYPTO:
                    ct = self.session_crypto.encrypt_chat(text)
                    msg = {'type': 'chat', 'encrypted': True, 'ct': ct}
                else:
                    msg = {'type': 'chat', 'text': text}
                self.tcp_sock.send((json.dumps(msg) + '\n').encode())
                self.msg_entry.delete(0, tk.END)
                self.display_message(self.username, text, align='right')
            except: messagebox.showerror("Error", "Failed to send message")

    def open_emoji_picker(self):
        if self._emoji_picker and self._emoji_picker.winfo_exists():
            self._emoji_picker.destroy(); self._emoji_picker = None; return
        self._emoji_picker = EmojiPicker(self.root, self.theme,
                                          self._insert_emoji, self.emoji_btn)

    def _insert_emoji(self, em):
        if self.msg_entry:
            self.msg_entry.insert(tk.INSERT, em); self.msg_entry.focus_set()

    def toggle_open_mic(self):
        t = self.theme
        if self.open_mic_active:
            self.open_mic_active = False
            if self.open_mic_btn:
                self.open_mic_btn.config(text="🎙 OPEN MIC", bg=t['voice_idle_bg'])
            self.voice_active = False
            if self.voice_btn:
                self.voice_btn.config(bg=t['voice_idle_bg'], fg=t['voice_idle_fg'],
                                      text=self.voice_btn_text)
            try: self.tcp_sock.send((json.dumps({'type': 'voice_stop'}) + '\n').encode())
            except: pass
        else:
            self.open_mic_active = True
            if self.open_mic_btn:
                self.open_mic_btn.config(text="🔴 MIC ON", bg=t['voice_active_bg'])
            self.start_voice()

    # ── Low-level chat render helpers ────────────────────────────

    def _render_chat(self, user, text, align='left', timestamp=None, color=None):
        """
        Core text render. Uses unique per-user tag names so colors survive theme
        redraws — tags are re-configured on every call with the current theme values.
        User messages use Segoe UI (matching the input box).
        System messages use the theme's chat_font (Consolas by default).
        """
        t = self.theme
        if not self.chat_text: return
        if timestamp is None: timestamp = datetime.now().strftime('%H:%M')

        # "Segoe UI" matches the entry widget font — familiar, readable
        MSG_FONT      = ('Segoe UI', t['chat_font_size'])
        MSG_FONT_BOLD = ('Segoe UI', t['chat_font_size'], 'bold')
        TS_FONT       = (t['chat_font'], max(t['chat_font_size'] - 2, 7))  # Consolas for timestamps

        self.chat_text.config(state=tk.NORMAL)

        if align == 'right':
            # Use a per-message unique tag so theme redraws don't collapse all sent msgs
            msg_id   = hashlib.md5(f'{user}{text}{timestamp}'.encode()).hexdigest()[:8]
            tag_rt   = f'rt_{msg_id}'
            tag_rm   = f'rm_{msg_id}'
            self.chat_text.insert(tk.END, f'{text}  ', tag_rt)
            self.chat_text.insert(tk.END, f'[{timestamp} - {user}]\n', tag_rm)
            self.chat_text.tag_config(tag_rt, justify='right',
                                      foreground=self.name_color, font=MSG_FONT)
            self.chat_text.tag_config(tag_rm, justify='right',
                                      foreground=t['accent_4'],
                                      font=TS_FONT)
        else:
            self.chat_text.insert(tk.END, f'[{timestamp}] ', 'ts')
            self.chat_text.tag_config('ts', foreground=t['accent_4'], font=TS_FONT)

            if user == 'System':
                self.chat_text.insert(tk.END, f'System: ', 'sys_name')
                self.chat_text.tag_config('sys_name', foreground=t['system_msg_color'],
                                          font=(t['chat_font'], t['chat_font_size'], 'bold'))
                self.chat_text.insert(tk.END, f'{text}\n', 'sys_body')
                self.chat_text.tag_config('sys_body', foreground=t['system_msg_color'],
                                          font=(t['chat_font'], t['chat_font_size'], 'italic'))
            else:
                user_color = color or self.user_colors.get(user, t['accent_2'])
                tag_name   = f'user_{hashlib.md5(user.encode()).hexdigest()[:8]}'
                body_tag   = f'body_{tag_name}'  # per-user body tag avoids cross-user clobber
                self.chat_text.insert(tk.END, f'{user}: ', tag_name)
                self.chat_text.tag_config(tag_name, foreground=user_color, font=MSG_FONT_BOLD)
                self.chat_text.insert(tk.END, f'{text}\n', body_tag)
                self.chat_text.tag_config(body_tag, foreground=t['chat_fg'], font=MSG_FONT)

        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.see(tk.END)

    def _render_sys(self, text, timestamp=None):
        """Render a system/status line."""
        t = self.theme
        if not self.chat_text: return
        if timestamp is None: timestamp = datetime.now().strftime('%H:%M')
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.insert(tk.END, f'[{timestamp}] ', 'sys_ts')
        self.chat_text.insert(tk.END, f'{text}\n', 'sys_line')
        self.chat_text.tag_config('sys_ts',   foreground=t['accent_4'],
                                  font=('Consolas', max(t['chat_font_size'] - 2, 7)))
        self.chat_text.tag_config('sys_line', foreground=t['system_msg_color'],
                                  font=(t['chat_font'], t['chat_font_size'], 'italic'))
        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.see(tk.END)

    def _insert_rich_header(self, user, timestamp, color):
        """Insert [timestamp] User: header into chat_text. Returns user color."""
        t        = self.theme
        uc       = color or self.user_colors.get(user, t['accent_2'])
        tag_name = f'user_{hashlib.md5(user.encode()).hexdigest()[:8]}'
        TS_FONT  = (t['chat_font'], max(t['chat_font_size'] - 2, 7))
        MSG_BOLD = ('Segoe UI', t['chat_font_size'], 'bold')
        self.chat_text.insert(tk.END, f'[{timestamp}] ', 'ts')
        self.chat_text.tag_config('ts', foreground=t['accent_4'], font=TS_FONT)
        self.chat_text.insert(tk.END, f'{user}:\n', tag_name)
        self.chat_text.tag_config(tag_name, foreground=uc, font=MSG_BOLD)
        return uc

    def _place_mark(self, mark_name):
        """Place a named mark at END for later async insertion."""
        self.chat_text.insert(tk.END, '\u200b')
        idx = self.chat_text.index(tk.END + '-1c')
        self.chat_text.mark_set(mark_name, idx)
        self.chat_text.mark_gravity(mark_name, tk.LEFT)

    def _render_image(self, url, user, timestamp, color):
        """Render image: header + clickable URL immediately; fill image at mark when loaded."""
        if not self.chat_text: return
        t = self.theme
        self.chat_text.config(state=tk.NORMAL)
        self._insert_rich_header(user, timestamp, color)

        mark     = f'img_{hashlib.md5((url+timestamp+user).encode()).hexdigest()[:12]}'
        link_tag = mark + '_link'
        self.chat_text.insert(tk.END, f'  \U0001f517 {url}\n', link_tag)
        self.chat_text.tag_config(link_tag, foreground=t['accent_1'],
                                  font=(t['chat_font'], t['chat_font_size'], 'underline'),
                                  lmargin1=16, lmargin2=16)
        self.chat_text.tag_bind(link_tag, '<Button-1>', lambda e, u=url: webbrowser.open(u))
        self.chat_text.tag_bind(link_tag, '<Enter>', lambda e: self.chat_text.config(cursor='hand2'))
        self.chat_text.tag_bind(link_tag, '<Leave>', lambda e: self.chat_text.config(cursor=''))

        self._place_mark(mark)
        self.chat_text.insert(tk.END, '\n')
        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.see(tk.END)

        # Store URL so _embed_image_at_mark can make the image clickable
        self._image_urls = getattr(self, '_image_urls', {})
        self._image_urls[mark] = url

        if PIL_AVAILABLE:
            def _fetch(u=url, m=mark):
                data = fetch_image_bytes(u)
                self.root.after(0, lambda: self._embed_image_at_mark(data, m))
            threading.Thread(target=_fetch, daemon=True).start()

    def _embed_image_at_mark(self, data, mark):
        """Replace placeholder mark with the actual image, inside a hoverable/clickable card."""
        if not self.chat_text or not data: return
        t = self.theme
        try:
            img = Image.open(io.BytesIO(data))
            img.thumbnail((380, 280), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            self._images.append(photo)
        except Exception:
            return

        # Recover the URL stored alongside the mark so clicking opens it
        url = self._image_urls.get(mark, '')

        border_col  = t.get('titlebar_sep', t['accent_1'])
        border_glow = t.get('accent_1', border_col)

        try:
            self.chat_text.config(state=tk.NORMAL)

            # Wrap image in a bordered, hoverable card frame
            card = tk.Frame(self.chat_text, bg=border_col,
                            highlightthickness=0, bd=1, relief=tk.SOLID,
                            cursor='hand2')
            img_lbl = tk.Label(card, image=photo, bg=border_col, cursor='hand2',
                               padx=0, pady=0)
            img_lbl.pack(padx=1, pady=1)

            def _open(e, u=url):
                if u: webbrowser.open(u)

            def _on_enter(e):
                try: card.config(bg=border_glow); img_lbl.config(bg=border_glow)
                except: pass

            def _on_leave(e):
                try: card.config(bg=border_col); img_lbl.config(bg=border_col)
                except: pass

            for w in (card, img_lbl):
                w.bind('<Button-1>', _open)
                w.bind('<Enter>',    _on_enter)
                w.bind('<Leave>',    _on_leave)

            self.chat_text.window_create(mark, window=card, padx=8, pady=4)
            self.chat_text.config(state=tk.DISABLED)
            self.chat_text.see(tk.END)
        except tk.TclError:
            pass

    def _render_link(self, url, user, timestamp, color):
        """Render link: header + clickable URL immediately; fill OG card at mark when fetched."""
        if not self.chat_text: return
        t = self.theme
        self.chat_text.config(state=tk.NORMAL)
        self._insert_rich_header(user, timestamp, color)

        mark     = f'lnk_{hashlib.md5((url+timestamp+user).encode()).hexdigest()[:12]}'
        link_tag = mark + '_url'
        self.chat_text.insert(tk.END, f'  \U0001f517 {url}\n', link_tag)
        self.chat_text.tag_config(link_tag, foreground=t['accent_1'],
                                  font=(t['chat_font'], t['chat_font_size'], 'underline'),
                                  lmargin1=16, lmargin2=16)
        self.chat_text.tag_bind(link_tag, '<Button-1>', lambda e, u=url: webbrowser.open(u))
        self.chat_text.tag_bind(link_tag, '<Enter>', lambda e: self.chat_text.config(cursor='hand2'))
        self.chat_text.tag_bind(link_tag, '<Leave>', lambda e: self.chat_text.config(cursor=''))

        self._place_mark(mark)
        self.chat_text.insert(tk.END, '\n')
        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.see(tk.END)

        def _fetch(u=url, m=mark):
            prev = fetch_link_preview(u)
            self.root.after(0, lambda: self._embed_link_preview_at_mark(prev, m))
        threading.Thread(target=_fetch, daemon=True).start()

    def _embed_link_preview_at_mark(self, preview, mark):
        """Insert OG title/description/thumbnail at the placeholder mark as a styled card."""
        if not self.chat_text: return
        t     = self.theme
        title = preview.get('title', '')
        desc  = preview.get('description', '')
        img_url = preview.get('image_url', '')

        if not title and not desc and not img_url:
            return  # Nothing to show

        # Build card colors from theme
        card_bg      = self.lighten_color(t['glass_accent'], 18)
        border_col   = t.get('titlebar_sep', t['accent_1'])
        border_glow  = t.get('accent_1', border_col)   # brighter on hover
        target_url   = preview.get('url', '')

        try:
            self.chat_text.config(state=tk.NORMAL)

            # Outer frame acts as the colored border
            card = tk.Frame(self.chat_text, bg=border_col,
                            highlightthickness=0, bd=1, relief=tk.SOLID,
                            cursor='hand2')
            inner = tk.Frame(card, bg=card_bg, padx=10, pady=8, cursor='hand2')
            inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

            _children = []
            if title:
                title_lbl = tk.Label(inner, text=title, bg=card_bg, fg=t['fg_color'],
                         font=(t['chat_font'], t['chat_font_size'] + 2, 'bold'),
                         anchor='w', wraplength=340, justify='left', cursor='hand2')
                title_lbl.pack(anchor='w')
                _children.append(title_lbl)
            if desc:
                desc_lbl = tk.Label(inner, text=desc, bg=card_bg, fg=t['accent_4'],
                         font=(t['chat_font'], max(t['chat_font_size'] - 1, 8)),
                         anchor='w', wraplength=340, justify='left', cursor='hand2')
                desc_lbl.pack(anchor='w', pady=(2, 0))
                _children.append(desc_lbl)

            # Click anywhere on card → open URL
            def _open_url(e, u=target_url): webbrowser.open(u)

            # Hover glow: swap border/inner bg on enter/leave
            bright_inner = self.lighten_color(card_bg, 12)
            def _on_enter(e):
                try:
                    card.config(bg=border_glow)
                    inner.config(bg=bright_inner)
                    for child in inner.winfo_children():
                        try: child.config(bg=bright_inner)
                        except: pass
                except: pass

            def _on_leave(e):
                try:
                    card.config(bg=border_col)
                    inner.config(bg=card_bg)
                    for child in inner.winfo_children():
                        try: child.config(bg=card_bg)
                        except: pass
                except: pass

            for widget in [card, inner] + _children:
                widget.bind('<Button-1>', _open_url)
                widget.bind('<Enter>',    _on_enter)
                widget.bind('<Leave>',    _on_leave)

            # Store card reference so we can embed thumbnail later
            self._link_cards = getattr(self, '_link_cards', {})
            self._link_cards[mark] = (card, inner, border_col, card_bg,
                                      _open_url, _on_enter, _on_leave)

            self.chat_text.window_create(mark, window=card, padx=16, pady=4)
            self.chat_text.insert(mark, '\n')
            self.chat_text.config(state=tk.DISABLED)
            self.chat_text.see(tk.END)
        except tk.TclError:
            return

        if img_url and PIL_AVAILABLE:
            def _ft(iu=img_url, m=mark):
                d = fetch_image_bytes(iu, max_bytes=500_000)
                if d:
                    self.root.after(0, lambda: self._embed_thumb_at_mark(d, m))
            threading.Thread(target=_ft, daemon=True).start()

    def _embed_thumb_at_mark(self, data, mark):
        if not self.chat_text: return
        try:
            img = Image.open(io.BytesIO(data))
            img.thumbnail((200, 120), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            self._images.append(photo)
        except Exception:
            return
        # Place thumbnail inside the card frame if it exists, else fall back to text widget
        cards = getattr(self, '_link_cards', {})
        if mark in cards:
            card_data = cards[mark]
            _, inner = card_data[0], card_data[1]
            _open_url  = card_data[4] if len(card_data) > 4 else None
            _on_enter  = card_data[5] if len(card_data) > 5 else None
            _on_leave  = card_data[6] if len(card_data) > 6 else None
            try:
                card_bg = inner.cget('bg')
                lbl = tk.Label(inner, image=photo, bg=card_bg, cursor='hand2')
                lbl.image = photo  # keep ref
                lbl.pack(anchor='w', pady=(4, 0))
                if _open_url:  lbl.bind('<Button-1>', _open_url)
                if _on_enter:  lbl.bind('<Enter>',    _on_enter)
                if _on_leave:  lbl.bind('<Leave>',    _on_leave)
            except tk.TclError:
                pass
        else:
            try:
                self.chat_text.config(state=tk.NORMAL)
                self.chat_text.image_create(mark, image=photo, padx=16, pady=2)
                self.chat_text.insert(mark, '\n')
                self.chat_text.config(state=tk.DISABLED)
                self.chat_text.see(tk.END)
            except tk.TclError:
                pass

    # ── Public display methods ────────────────────────────────────

    def display_message(self, user, text, align='left', timestamp=None, color=None, from_history=False):
        if timestamp is None: timestamp = datetime.now().strftime('%H:%M')

        # URL/image detection — applies to ALL messages including sender's own
        urls = URL_RE.findall(text)
        if urls:
            url = urls[0]
            if is_image_url(url):
                self._msg_log.append({'type': 'image', 'url': url,
                                      'user': user, 'timestamp': timestamp, 'color': color})
                self._render_image(url, user, timestamp, color)
                return
            else:
                self._msg_log.append({'type': 'link', 'url': url,
                                      'user': user, 'timestamp': timestamp, 'color': color})
                self._render_link(url, user, timestamp, color)
                return

        self._msg_log.append({'type': 'chat', 'user': user, 'text': text,
                               'align': align, 'timestamp': timestamp, 'color': color})
        self._render_chat(user, text, align=align, timestamp=timestamp, color=color)

    def display_system_message(self, text):
        if not self.chat_text: return
        ts = datetime.now().strftime('%H:%M')
        self._msg_log.append({'type': 'system', 'text': text, 'timestamp': ts})
        self._render_sys(text, ts)

    def update_userlist_with_colors(self, users_with_colors):
        if not self.user_list_frame: return
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

    def _show_settings_menu(self):
        """Show a fully themed custom dropdown menu anchored below the Settings button."""
        # Toggle: if already open, close it
        if self._settings_popup and self._settings_popup.winfo_exists():
            self._settings_popup.destroy()
            self._settings_popup = None
            return

        t   = self.theme
        btn = self.settings_btn

        # Menu items: (label, command) — None = separator
        items = [
            ("Change Username",        self.change_username),
            ("Change Name Color",      self.change_name_color),
            ("Change PTT Key",         self.change_ptt_key),
            ("Audio Devices & Volume", self.configure_audio_devices),
            ("Change Theme",           self.change_theme),
            None,
            ("Clear Saved Password",   self.clear_saved_password),
            None,
            ("About",                  self.show_about),
        ]

        popup = tk.Toplevel(self.root)
        self._settings_popup = popup
        popup.overrideredirect(True)
        popup.configure(bg=t['titlebar_sep'])   # border color via bg of outer window

        # Position below the button
        popup.update_idletasks()
        bx = btn.winfo_rootx()
        by = btn.winfo_rooty() + btn.winfo_height()
        popup.geometry(f'+{bx}+{by}')
        popup.lift()

        # Inner frame = the actual menu background
        inner = tk.Frame(popup, bg=t['glass_accent'], padx=1, pady=1)
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        def _close(cmd=None):
            popup.destroy()
            self._settings_popup = None
            if cmd:
                self.root.after(10, cmd)

        for item in items:
            if item is None:
                # Separator
                tk.Frame(inner, bg=t['titlebar_sep'], height=1).pack(fill=tk.X, padx=4, pady=2)
            else:
                label_text, cmd = item
                row = tk.Label(inner, text=label_text,
                               bg=t['glass_accent'], fg=t['fg_color'],
                               font=('Segoe UI', 9), anchor='w',
                               padx=16, pady=6, cursor='hand2')
                row.pack(fill=tk.X)

                def _enter(e, r=row): r.config(bg=t['accent_1'], fg=t['send_btn_fg'])
                def _leave(e, r=row): r.config(bg=t['glass_accent'], fg=t['fg_color'])
                def _click(e, c=cmd): _close(c)

                row.bind('<Enter>',    _enter)
                row.bind('<Leave>',    _leave)
                row.bind('<Button-1>', _click)

        # Close on focus loss
        popup.bind('<FocusOut>', lambda e: self.root.after(100, _check_focus))
        def _check_focus():
            try:
                if self._settings_popup and self._settings_popup.winfo_exists():
                    if popup.focus_get() is None:
                        _close()
            except: pass

        # Close + reposition: poll the main window position every 50ms.
        # If it has moved since the popup opened, dismiss immediately —
        # this makes the popup feel glued to the titlebar just like a real OS menu.
        _anchor_x = self.root.winfo_x()
        _anchor_y = self.root.winfo_y()

        def _track_position():
            try:
                if not (self._settings_popup and self._settings_popup.winfo_exists()):
                    return  # popup already gone, stop polling
                cx = self.root.winfo_x()
                cy = self.root.winfo_y()
                if cx != _anchor_x or cy != _anchor_y:
                    _close()  # window moved — dismiss
                    return
                self.root.after(50, _track_position)
            except: pass

        self.root.after(50, _track_position)
        popup.focus_set()

        # ── Settings actions ─────────────────────────────────────────

    def change_theme(self):
        dialog = ThemeDialog(self.root, self.theme, self.theme_name)
        self.root.wait_window(dialog)
        if dialog.result and dialog.result != self.theme_name:
            self.apply_theme(dialog.result)

    def change_username(self):
        dialog = ModernInputDialog(self.root, "Change Username", "Enter new username:", theme=self.theme)
        self.root.wait_window(dialog)
        new_name = dialog.result
        if new_name and new_name.strip() and new_name.strip() != self.username:
            try:
                self.tcp_sock.send((json.dumps({'type': 'change_username',
                                                'new_username': new_name.strip(),
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
            if self.voice_btn: self.voice_btn.config(text=self.voice_btn_text)
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
        self.saved_wire_hash = None; self.save_config()
        messagebox.showinfo("Password Cleared", "Saved password has been cleared.")

    # ── Voice ────────────────────────────────────────────────────

    def start_voice(self, event=None):
        if self.voice_active or not self.authenticated: return
        self.voice_active = True
        t = self.theme
        if self.voice_btn:
            self.voice_btn.config(bg=t['voice_active_bg'], fg=t['voice_active_fg'],
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
                if self.voice_btn:
                    self.voice_btn.config(bg=t['voice_idle_bg'], fg=t['voice_idle_fg'],
                                          text=self.voice_btn_text)
                return
        threading.Thread(target=self.send_audio, daemon=True).start()

    def stop_voice(self, event=None):
        if not self.voice_active: return
        if self.open_mic_active: return
        self.voice_active = False
        t = self.theme
        if self.voice_btn:
            self.voice_btn.config(bg=t['voice_idle_bg'], fg=t['voice_idle_fg'],
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
                # Encrypt voice packet before sending
                if self.session_crypto and HAVEN_CRYPTO:
                    data = self.session_crypto.encrypt_voice(data)
                self.udp_sock.sendto(data, (self.server_ip, SERVER_UDP_PORT))
            except Exception as e: print(f"Error sending audio: {e}"); break

    # ── Cleanup ──────────────────────────────────────────────────

    def on_close(self):
        if self._closing: return
        self._closing = True
        self.running  = False

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
