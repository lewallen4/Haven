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
import datetime
import hashlib
import colorsys
import math
import random
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
#       --add-data "bin/sounds;bin/sounds" \
#       --paths "bin" \
#       --hidden-import haven_crypto \
#       --name Haven haven_client.py
#
# Runtime layout (frozen exe on Windows):
#   %LOCALAPPDATA%/Haven\
#     haven_config.json      ← auto-created on first run
#     auth\
#       192.168.1.10_5000.tofu   ← TOFU fingerprints, one per server
#       myserver.com_5000.tofu
#     themes\               ← NOT here — themes are read from _MEIPASS (bundle)
#
# Notes:
#   • --add-data "themes;themes"   bundles themes/ into the exe (read via _MEIPASS)
#   • --paths "bin"                collects haven_crypto as a real module
#   • --hidden-import haven_crypto explicitly includes it
#   • DO NOT use --add-data for haven_crypto.py — causes crypto mismatch in exe
#   • User data (config, auth/) lives in %LOCALAPPDATA%/Haven — never in the exe dir
#   • TOFU: first connect to a server prompts to trust its cert fingerprint
#     and saves it to auth/<host>_<port>.tofu — no manual cert bundling needed
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
# Ensure haven_crypto.py is findable both in dev (bin/) and frozen (_MEIPASS)
if getattr(sys, 'frozen', False):
    # PyInstaller: _MEIPASS already in sys.path; haven_crypto.py bundled there
    _meipass = getattr(sys, '_MEIPASS', '')
    if _meipass and _meipass not in sys.path:
        sys.path.insert(0, _meipass)
else:
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
    _frozen = getattr(sys, 'frozen', False)

    if _frozen and not CRYPTO_AVAILABLE:
        import tkinter.messagebox as _mb
        _mb.showerror("Encryption Error",
            "The cryptography library failed to load in the packaged exe.\n\n"
            "Messages will fail to decrypt on the server.\n\n"
            "Please report this build issue.")
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
# ── Version ──────────────────────────────────────────────────────────────────
HAVEN_VERSION   = '3.8'          # must match tag on GitHub release
GITHUB_USER     = 'lewallen4'
GITHUB_REPO     = 'Haven'
# The updater expects a release tagged v3.2 etc. with:
#   Haven.exe         — the binary
#   SHA256SUMS.txt    — one line: <sha256hex>  Haven.exe

SERVER_TCP_PORT = 5000
SERVER_UDP_PORT = 5001
MAX_TCP_BUFFER = 1048576  # 1MB — large enough for full chat history payload

# ═══════════════════════════════════════════════════════════════════════════════
# Path helpers — centralised so frozen and dev stay consistent
# ═══════════════════════════════════════════════════════════════════════════════

def _user_data_dir():
    """
    Where Haven stores its user data.
    Frozen (exe) → %LOCALAPPDATA%/Haven\
    Dev (.py)    → same directory as haven_client.py
    """
    if getattr(sys, 'frozen', False):
        base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~')
        d = os.path.join(base, 'Haven')
        os.makedirs(d, exist_ok=True)
        return d
    return os.path.dirname(os.path.abspath(__file__))

USER_DATA_DIR = _user_data_dir()
CONFIG_FILE   = os.path.join(USER_DATA_DIR, 'haven_config.json')
AUTH_DIR      = os.path.join(USER_DATA_DIR, 'auth')

def resource_path(relative_path):
    """
    Path to a BUNDLED read-only resource (themes, icon).
    Frozen → inside _MEIPASS (the PyInstaller temp extract dir).
    Dev    → relative to haven_client.py.
    """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)

def user_data_path(relative_path):
    """Path to a user-writable file inside USER_DATA_DIR."""
    return os.path.join(USER_DATA_DIR, relative_path)

def get_exe_path():
    if getattr(sys, 'frozen', False):
        return [sys.executable]
    return [sys.executable, sys.argv[0]]

# Bundled read-only assets
THEMES_DIR = resource_path('themes')
ICON_FILE  = os.path.join(THEMES_DIR, 'haven.ico')
SOUNDS_DIR = resource_path('bin/sounds')

# ── Sound engine ──────────────────────────────────────────────────────────────
# Uses PyAudio (already a project dependency) with a permanently-open output
# stream. PCM frames are decoded from WAV at startup and written directly to
# the device buffer — bypassing WinMM/winsound entirely.
#
# Why PyAudio instead of winsound:
#   winsound goes through WinMM → audio session negotiation on every call,
#   adding 20-80ms of overhead regardless of SND_FILENAME vs SND_MEMORY.
#   PyAudio holds an open PortAudio stream; write() is a direct memcpy into
#   the device ring buffer — latency is one buffer period (~10ms at 1024 frames).
#
# Overlapping sounds each get their own thread writing to the same stream;
# PortAudio mixes them at the driver level.

_sound_pcm: dict     = {}   # name -> (rate, channels, sampwidth, raw_pcm_bytes)
_sfx_stream          = None  # shared PyAudio output stream
_sfx_pa              = None  # dedicated PyAudio instance for sfx
_sfx_lock            = threading.Lock()
_sfx_ready           = False

def _load_sound_buffers():
    """
    Decode all WAVs in SOUNDS_DIR to raw PCM at startup.
    Stored as (rate, channels, sampwidth, pcm_bytes) tuples.
    """
    global _sound_pcm
    try:
        if not os.path.isdir(SOUNDS_DIR):
            return
        import wave as _wave
        for fname in os.listdir(SOUNDS_DIR):
            if not fname.endswith('.wav') or fname.startswith('_'):
                continue
            path = os.path.join(SOUNDS_DIR, fname)
            with _wave.open(path, 'rb') as w:
                rate   = w.getframerate()
                ch     = w.getnchannels()
                sw     = w.getsampwidth()
                pcm    = w.readframes(w.getnframes())
            _sound_pcm[fname[:-4]] = (rate, ch, sw, pcm)
    except Exception as e:
        print(f'[AUDIO] PCM load error: {e}')

def _open_sfx_stream():
    """Open a persistent low-latency PyAudio output stream for sound effects."""
    global _sfx_stream, _sfx_pa, _sfx_ready
    try:
        import pyaudio as _pa
        _sfx_pa = _pa.PyAudio()
        # Use first available sound — all our files are 44100 mono 16-bit
        rate, ch, sw = 44100, 1, 2
        if _sound_pcm:
            rate, ch, sw, _ = next(iter(_sound_pcm.values()))
        _sfx_stream = _sfx_pa.open(
            format=_sfx_pa.get_format_from_width(sw),
            channels=ch,
            rate=rate,
            output=True,
            frames_per_buffer=512,   # ~11ms at 44100 — low latency
        )
        _sfx_ready = True
    except Exception as e:
        print(f'[AUDIO] PyAudio SFX stream failed: {e}')
        _sfx_ready = False

_sfx_volume_ref = [100]  # mutable ref updated by play_sound with the app's sfx_volume

def _play_pcm(pcm: bytes):
    """Write raw PCM to the shared output stream. Called on a per-sound thread."""
    global _sfx_stream, _sfx_ready
    # Apply SFX master volume
    vol = _sfx_volume_ref[0] / 100.0
    if vol != 1.0:
        try:
            import numpy as np
            arr = np.frombuffer(pcm, dtype=np.int16)
            pcm = (arr * min(vol, 2.0)).clip(-32768, 32767).astype(np.int16).tobytes()
        except ImportError:
            pass
    if not _sfx_ready or _sfx_stream is None:
        return
    try:
        with _sfx_lock:
            # write() is non-blocking at the Python level when the buffer has space;
            # for short SFX this returns almost immediately.
            _sfx_stream.write(pcm)
    except Exception:
        # Stream may have closed (device change etc.) — reopen once
        try:
            _open_sfx_stream()
            if _sfx_ready:
                _sfx_stream.write(pcm)
        except Exception:
            pass

def _play_pcm_threaded(name: str):
    """Thread target: look up PCM and write to stream."""
    entry = _sound_pcm.get(name)
    if entry:
        _play_pcm(entry[3])

_sfx_init_done = False

def _ensure_sfx_ready():
    global _sfx_init_done
    if not _sfx_init_done:
        _sfx_init_done = True
        threading.Thread(target=_open_sfx_stream, daemon=True,
                         name='HavenSFXInit').start()

def play_sound(name: str, enabled: bool = True, sfx_vol: int = None):
    """Fire-and-forget PCM playback via PyAudio. Near-zero latency, overlapping."""
    if not enabled:
        return
    if name not in _sound_pcm:
        return
    if sfx_vol is not None:
        _sfx_volume_ref[0] = sfx_vol
    _ensure_sfx_ready()
    threading.Thread(target=_play_pcm_threaded, args=(name,), daemon=True,
                     name=f'HavenSFX_{name}').start()

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

# ═══════════════════════════════════════════════════════════════════════════════
# TOFU — Trust On First Use cert pinning
# auth/<host>_<port>.tofu stores the SHA-256 fingerprint of the server cert.
# First connection: user is prompted to trust. Subsequent connections: silent.
# Fingerprint mismatch: hard block.
# ═══════════════════════════════════════════════════════════════════════════════

def _tofu_path(host, port):
    """Return path to the .tofu fingerprint file for a given server."""
    os.makedirs(AUTH_DIR, exist_ok=True)
    safe = re.sub(r'[^a-zA-Z0-9._-]', '_', host)
    return os.path.join(AUTH_DIR, f'{safe}_{port}.tofu')

def _cert_fingerprint(der_bytes):
    """SHA-256 fingerprint of a DER-encoded certificate, hex-formatted."""
    digest = hashlib.sha256(der_bytes).hexdigest()
    return ':'.join(digest[i:i+2] for i in range(0, len(digest), 2))

class TofuDialog(tk.Toplevel):
    """Themed TOFU trust prompt — matches all other Haven dialogs."""
    def __init__(self, parent, host, port, fp, theme=None):
        super().__init__(parent)
        self.result  = None   # True=trust, False=decline
        t = theme or _fallback_theme()
        self.configure(bg=t['titlebar_sep'] if 'titlebar_sep' in t else t['glass_bg'])
        self.overrideredirect(True)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        apply_window_icon(self)

        # ── Outer border frame (1px accent line) ──────────────────────────────
        inner = tk.Frame(self, bg=t['glass_bg'])
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        build_themed_titlebar(inner, t, "New Server — Trust Certificate?")

        body = tk.Frame(inner, bg=t['glass_bg'])
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)

        tk.Label(body, text=f"🔐  {host}:{port}",
                 bg=t['glass_bg'], fg=t['accent_1'],
                 font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(0, 12))

        tk.Label(body,
                 text="Haven has not connected to this server before.\nVerify this fingerprint with the server operator\nbefore trusting.",
                 bg=t['glass_bg'], fg=t['fg_color'],
                 font=('Segoe UI', 9), justify='left').pack(anchor='w')

        tk.Frame(body, bg=t['accent_1'], height=1).pack(fill='x', pady=12)

        tk.Label(body, text="SHA-256 fingerprint:",
                 bg=t['glass_bg'], fg=t['fg_color'],
                 font=('Segoe UI', 8, 'bold')).pack(anchor='w')

        # Fingerprint in a monospace copyable label broken into 2 lines
        half = len(fp) // 2
        fp_display = fp[:half] + '\n' + fp[half:]
        tk.Label(body, text=fp_display,
                 bg=t['glass_accent'], fg=t['accent_1'],
                 font=('Consolas', 8), justify='left',
                 padx=8, pady=6).pack(fill='x', pady=(4, 14))

        btn_row = tk.Frame(body, bg=t['glass_bg'])
        btn_row.pack(fill='x')

        tk.Button(btn_row, text="✓  Trust & Connect",
                  bg=t['accent_1'], fg=t['send_btn_fg'],
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  padx=16, pady=8, cursor='hand2',
                  command=self._trust).pack(side='left', padx=(0, 8))

        tk.Button(btn_row, text="✕  Decline",
                  bg=t['accent_2'], fg='#ffffff',
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  padx=16, pady=8, cursor='hand2',
                  command=self._decline).pack(side='left')

        self.update_idletasks()
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        if parent and parent.winfo_exists():
            px = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
            py = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        else:
            px = (self.winfo_screenwidth()  - w) // 2
            py = (self.winfo_screenheight() - h) // 2
        self.geometry(f'{w}x{h}+{px}+{py}')
        self.lift()
        self.attributes('-topmost', True)
        self.after(100, lambda: self.attributes('-topmost', False))
        self.focus_force()

    def _trust(self):   self.result = True;  self.destroy()
    def _decline(self): self.result = False; self.destroy()


class TofuMismatchDialog(tk.Toplevel):
    """Themed cert mismatch dialog — lets the user trust the new cert or cancel."""
    def __init__(self, parent, host, port, saved_fp, current_fp, tofu_file, theme=None):
        super().__init__(parent)
        self.result = False   # True = user chose to trust the new cert
        t = theme or _fallback_theme()
        self.configure(bg=t['titlebar_sep'] if 'titlebar_sep' in t else t['glass_bg'])
        self.overrideredirect(True)
        self.resizable(False, False)
        self.transient(parent)
        # (non-modal)
        apply_window_icon(self)

        inner = tk.Frame(self, bg=t['glass_bg'])
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        build_themed_titlebar(inner, t, "⚠  Certificate Changed")

        body = tk.Frame(inner, bg=t['glass_bg'])
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)

        tk.Label(body, text=f"⚠  {host}:{port}",
                 bg=t['glass_bg'], fg='#ff4444',
                 font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(0, 8))

        tk.Label(body,
                 text="The server's certificate has changed since you last connected.\n"
                      "This is normal if the server was rebuilt or the cert was renewed.\n"
                      "If unexpected, verify with the server operator before trusting.",
                 bg=t['glass_bg'], fg=t['fg_color'],
                 font=('Segoe UI', 9), justify='left').pack(anchor='w')

        tk.Frame(body, bg='#ff4444', height=1).pack(fill='x', pady=10)

        for label, fp in (("Old fingerprint:", saved_fp),
                           ("New fingerprint:", current_fp)):
            tk.Label(body, text=label, bg=t['glass_bg'], fg=t['fg_color'],
                     font=('Segoe UI', 8, 'bold')).pack(anchor='w')
            half = len(fp) // 2
            tk.Label(body, text=fp[:half] + '\n' + fp[half:],
                     bg=t['glass_accent'], fg=t['accent_1'],
                     font=('Consolas', 8), justify='left',
                     padx=8, pady=4).pack(fill='x', pady=(2, 8))

        btn_row = tk.Frame(body, bg=t['glass_bg'])
        btn_row.pack(pady=(6, 0))

        def _trust():
            self.result = True
            self.destroy()

        tk.Button(btn_row, text="✓ Trust New Certificate",
                  bg=t['accent_1'], fg=t['send_btn_fg'],
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  padx=16, pady=8, cursor='hand2',
                  command=_trust).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(btn_row, text="Cancel",
                  bg=t['accent_2'], fg='#ffffff',
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  padx=16, pady=8, cursor='hand2',
                  command=self.destroy).pack(side=tk.LEFT)

        self.update_idletasks()
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        if parent and parent.winfo_exists():
            px = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
            py = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        else:
            px = (self.winfo_screenwidth()  - w) // 2
            py = (self.winfo_screenheight() - h) // 2
        self.geometry(f'{w}x{h}+{px}+{py}')
        self.lift()
        self.attributes('-topmost', True)
        self.after(100, lambda: self.attributes('-topmost', False))
        self.focus_force()
        self.wait_window()


def _tofu_check(host, port, der_bytes, parent_window=None, theme=None):
    """
    Check TOFU trust for a server cert.
    Returns True if trusted, False if rejected.
    On first connect: shows themed trust dialog.
    On repeat connect: verifies silently.
    On mismatch: shows themed warning, returns False.
    """
    fp        = _cert_fingerprint(der_bytes)
    tofu_file = _tofu_path(host, port)

    if os.path.exists(tofu_file):
        saved = open(tofu_file).read().strip()
        if saved == fp:
            return True   # known and trusted — silent
        # Fingerprint changed — ask the user whether to trust the new cert
        print(f"[TOFU] Cert changed for {host}:{port} — prompting user")
        if parent_window:
            dlg = TofuMismatchDialog(parent_window, host, port,
                                     saved, fp, tofu_file, theme=theme)
            if dlg.result:
                # User chose to trust — overwrite the saved fingerprint
                with open(tofu_file, 'w') as fh:
                    fh.write(fp)
                print(f"[TOFU] New fingerprint accepted and saved for {host}:{port}")
                return True
        print(f"[TOFU] New cert rejected by user for {host}:{port}")
        return False

    # First time seeing this server — save silently and connect
    os.makedirs(AUTH_DIR, exist_ok=True)
    with open(tofu_file, 'w') as f:
        f.write(fp)
    print(f"[TOFU] New server {host}:{port} — fingerprint saved automatically")
    return True

def create_tls_context():
    """Create a TLS context that accepts any cert — TOFU check is done post-handshake."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE   # we do our own pinning via TOFU
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
    window.overrideredirect(True) must already be set (on the Toplevel).
    *window* may be the Toplevel itself or a child Frame used as a border container —
    in either case dragging is applied to the nearest Toplevel ancestor.
    Returns the titlebar Frame.
    """
    t = theme
    close_cmd = on_close if on_close else window.destroy

    # Resolve the actual Toplevel so drag calls .geometry() on the right widget
    def _toplevel(w):
        while w is not None:
            if isinstance(w, (tk.Tk, tk.Toplevel)):
                return w
            w = w.master
        return window  # fallback
    top = _toplevel(window)

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

    # Drag support — always moves the Toplevel, never a Frame
    top._dx = top._dy = None
    def _s(e): top._dx = e.x; top._dy = e.y
    def _e(e): top._dx = None; top._dy = None
    def _m(e):
        if top._dx is not None:
            top.geometry(f"+{top.winfo_x()+e.x-top._dx}+{top.winfo_y()+e.y-top._dy}")
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
        self.withdraw()
        self.geometry("420x610")
        self.update_idletasks()
        self.update()
        x = (self.winfo_screenwidth()  // 2) - 210
        y = (self.winfo_screenheight() // 2) - 305
        self.geometry(f'420x610+{x}+{y}')
        self.deiconify()

        # Apply haven.ico even to overrideredirect windows (may not show on all platforms)
        apply_window_icon(self)

        self.grab_set()
        self.lift()
        self.attributes('-topmost', True)
        self.after(100, lambda: self.attributes('-topmost', False))
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
        self.connect_btn.pack(pady=(20, 6), padx=30, fill=tk.X)

        tk.Button(self, text="⬇  Check for Updates",
                  bg=self.t['login_form_bg'], fg=self.t['login_sub_fg'],
                  font=('Segoe UI', 9), relief=tk.FLAT,
                  command=lambda: check_for_updates(self, self.t, silent=False),
                  padx=20, pady=7, cursor='hand2',
                  activebackground=self.t['glass_accent'],
                  activeforeground=self.t['login_title_fg']).pack(padx=30, fill=tk.X)

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
        # (non-modal)
        apply_window_icon(self)

        build_themed_titlebar(self, theme, " ")

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
    Themed text-input dialog. Same structure as ColorPickerDialog/ThemeDialog —
    transient + grab_set, plain destroy(). No embedded widget hide/show needed.
    """
    def __init__(self, parent, title, prompt, theme=None, show='', default='', app=None):
        super().__init__(parent)
        self.result = None
        self.t = theme or _fallback_theme()

        self.configure(bg=self.t['titlebar_sep'])
        self.resizable(False, False)
        self.overrideredirect(True)
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 200
        y = (self.winfo_screenheight() // 2) - 110
        self.geometry(f'400x220+{x}+{y}')
        self.transient(parent)
        # (non-modal)
        self.lift()
        self.attributes('-topmost', True)
        self.after(100, lambda: self.attributes('-topmost', False))
        apply_window_icon(self)

        _inner = tk.Frame(self, bg=self.t['glass_bg'])
        _inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        build_themed_titlebar(_inner, self.t, " ", on_close=self._cancel)

        tk.Label(_inner, text=prompt, bg=self.t['glass_bg'], fg=self.t['fg_color'],
                 font=('Segoe UI', 11)).pack(padx=30, pady=(20, 10))

        entry_frame = tk.Frame(_inner, bg=self.t['glass_accent'], highlightthickness=1,
                               highlightbackground=self.t['titlebar_sep'])
        entry_frame.pack(fill=tk.X, padx=30)

        self.entry = tk.Entry(entry_frame, bg=self.t['glass_accent'], fg=self.t['fg_color'],
                              insertbackground=self.t['accent_1'], font=('Segoe UI', 11),
                              show=show, relief=tk.FLAT, bd=0)
        self.entry.pack(fill=tk.X, padx=8, pady=8)
        if default:
            self.entry.insert(0, default)

        btn_frame = tk.Frame(_inner, bg=self.t['glass_bg'])
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="OK", bg=self.t['accent_1'], fg=self.t['send_btn_fg'],
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  command=self._ok, padx=30, pady=8, cursor='hand2').pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", bg=self.t['accent_2'], fg='#fff',
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  command=self._cancel, padx=20, pady=8, cursor='hand2').pack(side=tk.LEFT, padx=10)

        self.entry.bind('<Return>', lambda e: self._ok())
        self.entry.bind('<Escape>', lambda e: self._cancel())
        self.entry.focus_set()

    def _cancel(self):
        self.destroy()

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
        self.transient(parent); # (non-modal)
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
        self.transient(parent); # (non-modal)
        apply_window_icon(self)

        build_themed_titlebar(self, self.t, " ")
        tk.Label(self, text="Choose Your Name Color", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 14, 'bold')).pack(pady=18)
        colors = [
            ['#ff006e', '#ff4d6d', '#ff6b9d', '#ff8fab'],
            ['#00ff88', '#06ffa5', '#4ecca3', '#78e08f'],
            ['#8338ec', '#a855f7', '#c084fc', '#e0aaff'],
            ['#ffd60a', '#ffb703', '#fb8500', '#ff9500'],
            ['#0066ff', '#00aaff', '#33ccff', '#66eeff'],
            ['#ffffff', '#ffe8d6', '#b8c8e8', '#e8e0ff'],
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
        self.resizable(False, True)
        self.overrideredirect(True)
        # Fit within screen height with some headroom
        screen_h = self.winfo_screenheight()
        dlg_h = min(720, screen_h - 80)
        dlg_w = 520
        self.update_idletasks()
        x = (self.winfo_screenwidth()  // 2) - dlg_w // 2
        y = (screen_h // 2) - dlg_h // 2
        self.geometry(f'{dlg_w}x{dlg_h}+{x}+{y}')
        self.transient(parent); # (non-modal)
        apply_window_icon(self)

        build_themed_titlebar(self, self.t, "Audio Devices & Volume")
        tk.Label(self, text="AUDIO SETTINGS", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 16, 'bold')).pack(pady=(12, 4))

        self.input_devices = []; self.output_devices = []
        self.get_audio_devices()

        # ── Scrollable content area ───────────────────────────────────────────
        scroll_outer = tk.Frame(self, bg=self.t['glass_bg'])
        scroll_outer.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        canvas = tk.Canvas(scroll_outer, bg=self.t['glass_bg'], highlightthickness=0)
        scrollbar = make_scrollbar(scroll_outer, self.t, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        content = tk.Frame(canvas, bg=self.t['glass_bg'])
        cw = canvas.create_window((0, 0), window=content, anchor='nw')

        def _on_content_configure(e):
            canvas.configure(scrollregion=canvas.bbox('all'))
        def _on_canvas_configure(e):
            canvas.itemconfig(cw, width=e.width)
        def _on_mousewheel(e):
            canvas.yview_scroll(int(-1 * (e.delta / 120)), 'units')

        content.bind('<Configure>', _on_content_configure)
        canvas.bind('<Configure>', _on_canvas_configure)
        canvas.bind('<MouseWheel>', _on_mousewheel)
        content.bind('<MouseWheel>', _on_mousewheel)

        def section(label_text):
            f = tk.Frame(content, bg=self.t['glass_accent'])
            f.pack(fill=tk.X, padx=16, pady=8)
            tk.Label(f, text=label_text, bg=self.t['glass_accent'], fg=self.t['accent_1'],
                     font=('Segoe UI', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=(10, 4))
            f.bind('<MouseWheel>', _on_mousewheel)
            return f

        def vol_row(parent, label_text, var, callback):
            row = tk.Frame(parent, bg=self.t['glass_accent'])
            row.pack(fill=tk.X, padx=10, pady=(6, 2))
            row.bind('<MouseWheel>', _on_mousewheel)
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
                                                        callback())).pack(fill=tk.X, padx=10, pady=(0, 10))

        UNCHANGED = '— Leave Unchanged —'

        in_frame = section("INPUT DEVICE (Microphone)")
        self.input_devices.insert(0, UNCHANGED)
        self.input_var = tk.StringVar(value=UNCHANGED)
        in_combo = ttk.Combobox(in_frame, textvariable=self.input_var,
                                values=self.input_devices, state='readonly', width=50)
        in_combo.pack(padx=10, pady=5); self.style_combobox(in_combo)
        in_combo.current(0)
        in_combo.bind('<<ComboboxSelected>>',
                      lambda e: self.result.update({'input_device': self.input_var.get()}))
        self.input_volume = tk.DoubleVar(value=self.result.get('input_volume', 100))
        vol_row(in_frame, "Input Volume", self.input_volume,
                lambda: self.result.update({'input_volume': self.input_volume.get()}))
        tk.Button(in_frame, text="🎤 Test Microphone", bg=self.t['glass_bg'], fg=self.t['fg_color'],
                  font=('Segoe UI', 9), relief=tk.FLAT, command=self.test_input_device,
                  padx=15, pady=5, cursor='hand2').pack(pady=(0, 10))

        out_frame = section("OUTPUT DEVICE (Speakers/Headphones)")
        self.output_devices.insert(0, UNCHANGED)
        self.output_var = tk.StringVar(value=UNCHANGED)
        out_combo = ttk.Combobox(out_frame, textvariable=self.output_var,
                                 values=self.output_devices, state='readonly', width=50)
        out_combo.pack(padx=10, pady=5); self.style_combobox(out_combo)
        out_combo.current(0)
        out_combo.bind('<<ComboboxSelected>>',
                       lambda e: self.result.update({'output_device': self.output_var.get()}))
        self.output_volume = tk.DoubleVar(value=self.result.get('output_volume', 100))
        vol_row(out_frame, "Output Volume", self.output_volume,
                lambda: self.result.update({'output_volume': self.output_volume.get()}))
        tk.Button(out_frame, text="🔊 Test Speakers", bg=self.t['glass_bg'], fg=self.t['fg_color'],
                  font=('Segoe UI', 9), relief=tk.FLAT, command=self.test_output_device,
                  padx=15, pady=5, cursor='hand2').pack(pady=(0, 10))

        # PTT release delay
        ptt_frame = section("PUSH-TO-TALK RELEASE DELAY")
        tk.Label(ptt_frame, text="Adds a brief pause before PTT stops transmitting.",
                 bg=self.t['glass_accent'], fg=self.t['fg_color'],
                 font=('Segoe UI', 8)).pack(anchor=tk.W, padx=10, pady=(0, 6))
        ptt_delay_options = [('Off (0s)', 0.0), ('0.5s', 0.5), ('1s', 1.0), ('1.5s', 1.5), ('2s', 2.0)]
        ptt_delay_labels  = [x[0] for x in ptt_delay_options]
        ptt_delay_values  = [x[1] for x in ptt_delay_options]
        current_delay = self.result.get('ptt_release_delay', 0.0)
        try:
            sel_idx = ptt_delay_values.index(current_delay)
        except ValueError:
            sel_idx = 0
        self.ptt_delay_var = tk.StringVar(value=ptt_delay_labels[sel_idx])
        ptt_combo = ttk.Combobox(ptt_frame, textvariable=self.ptt_delay_var,
                                 values=ptt_delay_labels, state='readonly', width=20)
        ptt_combo.pack(padx=10, pady=(0, 12))
        self.style_combobox(ptt_combo)
        self._ptt_delay_map = dict(zip(ptt_delay_labels, ptt_delay_values))

        # ── Fixed bottom button row (outside scroll area) ─────────────────────
        btn_frame = tk.Frame(self, bg=self.t['glass_bg'])
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=12)
        tk.Button(btn_frame, text="SAVE SETTINGS", bg=self.t['accent_1'], fg=self.t['send_btn_fg'],
                  font=('Segoe UI', 11, 'bold'), relief=tk.FLAT, command=self.save_settings,
                  padx=30, pady=10, cursor='hand2').pack(side=tk.LEFT, padx=(20, 10))
        tk.Button(btn_frame, text="CANCEL", bg=self.t['accent_2'], fg='#fff',
                  font=('Segoe UI', 11, 'bold'), relief=tk.FLAT, command=self.destroy,
                  padx=30, pady=10, cursor='hand2').pack(side=tk.LEFT)

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

    def _find_device_str(self, device_list, saved_index):
        """Find the display string in device_list that matches a saved device index.
        Falls back to the first entry (Default) if no match found."""
        if saved_index is not None:
            target = f"Device {saved_index}:"
            for entry in device_list:
                if entry.startswith(target):
                    return entry
        return device_list[0] if device_list else "Default"

    def get_audio_devices(self):
        # Default entries
        try:
            self.input_devices.append(f"Default ({self.p.get_default_input_device_info()['name']})")
        except: self.input_devices.append("Default")
        try:
            self.output_devices.append(f"Default ({self.p.get_default_output_device_info()['name']})")
        except: self.output_devices.append("Default")

        for i in range(self.p.get_device_count()):
            try:
                d = self.p.get_device_info_by_index(i)
                name = d['name'].strip()
                # Input-only list: devices that have input channels
                if d['maxInputChannels'] > 0:
                    self.input_devices.append(f"Device {i}: {name}")
                # Output-only list: devices that have output channels
                if d['maxOutputChannels'] > 0:
                    self.output_devices.append(f"Device {i}: {name}")
            except: continue

    def test_input_device(self):
        try:
            # Input device
            device_name  = self.input_var.get(); in_idx = None
            if not device_name.startswith("Default"):
                try: in_idx = int(device_name.split("Device ")[1].split(":")[0])
                except: pass

            # Output device (for loopback)
            out_name = self.output_var.get(); out_idx = None
            if not out_name.startswith("Default"):
                try: out_idx = int(out_name.split("Device ")[1].split(":")[0])
                except: pass

            stream_in = None; stream_out = None; used_rate = None
            for rate in SUPPORTED_RATES:
                try:
                    stream_in = self.p.open(format=FORMAT, channels=CHANNELS, rate=rate,
                                            input=True, input_device_index=in_idx,
                                            frames_per_buffer=CHUNK)
                    used_rate = rate; break
                except: continue
            if stream_in is None: raise Exception("Could not open input device at any sample rate")

            # Open matching output for loopback
            for rate in [used_rate] + [r for r in SUPPORTED_RATES if r != used_rate]:
                try:
                    stream_out = self.p.open(format=FORMAT, channels=CHANNELS, rate=rate,
                                             output=True, output_device_index=out_idx,
                                             frames_per_buffer=CHUNK)
                    break
                except: continue

            loopback_enabled = [stream_out is not None]

            test_dialog = tk.Toplevel(self)
            test_dialog.configure(bg=self.t['glass_bg'])
            test_dialog.overrideredirect(True)
            apply_window_icon(test_dialog)
            build_themed_titlebar(test_dialog, self.t, "Microphone Test",
                                  on_close=lambda: close_test())
            x = (self.winfo_screenwidth() // 2) - 150
            y = (self.winfo_screenheight() // 2) - 130
            test_dialog.geometry(f'300x260+{x}+{y}')

            tk.Label(test_dialog, text="🎤 Testing Microphone", bg=self.t['glass_bg'],
                     fg=self.t['accent_1'], font=('Segoe UI', 12, 'bold')).pack(pady=(18, 4))
            tk.Label(test_dialog, text=f"Sample Rate: {used_rate} Hz",
                     bg=self.t['glass_bg'], fg=self.t['fg_color'],
                     font=('Segoe UI', 9)).pack()

            # VU meter
            vu_label = tk.Label(test_dialog, text="●●●●●●●●●●",
                                bg=self.t['glass_bg'], fg=self.t['glass_accent'],
                                font=('Segoe UI', 14))
            vu_label.pack(pady=10)

            # Loopback toggle
            loop_var = tk.BooleanVar(value=loopback_enabled[0])
            loop_row = tk.Frame(test_dialog, bg=self.t['glass_bg'])
            loop_row.pack()
            tk.Label(loop_row, text="Hear yourself:", bg=self.t['glass_bg'],
                     fg=self.t['fg_color'], font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=(0,6))
            loop_status = tk.Label(loop_row,
                                   text=("ON" if loopback_enabled[0] else "No output device"),
                                   bg=self.t['glass_bg'],
                                   fg=(self.t['accent_1'] if loopback_enabled[0] else self.t['accent_4']),
                                   font=('Segoe UI', 9, 'bold'))
            loop_status.pack(side=tk.LEFT)
            if loopback_enabled[0]:
                def toggle_loopback():
                    loopback_enabled[0] = not loopback_enabled[0]
                    loop_status.config(
                        text="ON" if loopback_enabled[0] else "OFF",
                        fg=self.t['accent_1'] if loopback_enabled[0] else self.t['accent_4']
                    )
                tk.Checkbutton(loop_row, variable=loop_var,
                               bg=self.t['glass_bg'], activebackground=self.t['glass_bg'],
                               selectcolor=self.t['glass_accent'], relief=tk.FLAT,
                               command=toggle_loopback).pack(side=tk.LEFT, padx=4)

            running = [True]

            def _loopback_thread():
                while running[0]:
                    try:
                        data = stream_in.read(CHUNK, exception_on_overflow=False)
                        # VU update via after
                        try:
                            vals = [abs(int.from_bytes(data[i:i+2], 'little', signed=True))
                                    for i in range(0, min(len(data), 64), 2)]
                            peak = max(vals) if vals else 0
                            test_dialog.after(0, lambda p=peak: _update_vu(p))
                        except: pass
                        # Loopback
                        if loopback_enabled[0] and stream_out:
                            try:
                                vol = self.output_volume.get() / 100
                                if vol != 1.0:
                                    try:
                                        import numpy as np
                                        arr = np.frombuffer(data, dtype=np.int16)
                                        data = (arr * vol).astype(np.int16).tobytes()
                                    except ImportError: pass
                                stream_out.write(data)
                            except: pass
                    except: break

            def _update_vu(peak):
                if not test_dialog.winfo_exists(): return
                level = min(10, peak // 3000)
                lit   = self.t['accent_1']
                dim   = self.t['glass_accent']
                vu_label.config(text='●' * level + '○' * (10 - level),
                                fg=lit if level > 6 else (self.t['accent_4'] if level > 3 else dim))

            threading.Thread(target=_loopback_thread, daemon=True).start()

            def close_test():
                running[0] = False
                try: stream_in.stop_stream();  stream_in.close()
                except: pass
                if stream_out:
                    try: stream_out.stop_stream(); stream_out.close()
                    except: pass
                test_dialog.destroy()

            tk.Button(test_dialog, text="STOP TEST", bg=self.t['accent_2'], fg='#fff',
                      font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                      command=close_test, padx=20, pady=5).pack(pady=14)
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
        UNCHANGED = '— Leave Unchanged —'
        self.result['input_volume']  = self.input_volume.get()
        self.result['output_volume'] = self.output_volume.get()
        chosen_label = self.ptt_delay_var.get()
        self.result['ptt_release_delay'] = self._ptt_delay_map.get(chosen_label, 0.0)

        # Only commit device selections that the user explicitly changed
        for device_key, index_key, var in (
            ('input_device',  'input_device_index',  self.input_var),
            ('output_device', 'output_device_index', self.output_var),
        ):
            chosen = var.get()
            if chosen == UNCHANGED:
                pass   # keep whatever was already in self.result from current_settings
            elif chosen.startswith("Default"):
                self.result[device_key]  = chosen
                self.result[index_key]   = None
            else:
                try:
                    idx = int(chosen.split("Device ")[1].split(":")[0].strip())
                    self.result[device_key] = chosen
                    self.result[index_key]  = idx
                except (IndexError, ValueError):
                    self.result[device_key] = chosen
                    self.result[index_key]  = None
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
        self.transient(parent); # (non-modal)
        apply_window_icon(self)

        build_themed_titlebar(self, self.t, "About Haven")

        tk.Label(self, text="HAVEN", bg=self.t['glass_bg'], fg=self.t['accent_1'],
                 font=('Segoe UI', 20, 'bold')).pack(pady=(20, 4))
        tk.Label(self, text=f"v{HAVEN_VERSION}", bg=self.t['glass_bg'], fg=self.t['accent_4'],
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
# =============================================================================
# Auto-updater
# =============================================================================

def _github_api(path):
    import urllib.request
    url = f'https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}{path}'
    req = urllib.request.Request(url, headers={
        'Accept':     'application/vnd.github+json',
        'User-Agent': f'Haven/{HAVEN_VERSION}',
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def _download_file(url, dest_path, progress_cb=None):
    import urllib.request
    req = urllib.request.Request(url, headers={'User-Agent': f'Haven/{HAVEN_VERSION}'})
    with urllib.request.urlopen(req, timeout=60) as r:
        total = int(r.headers.get('Content-Length', 0))
        done  = 0
        with open(dest_path, 'wb') as f:
            while True:
                chunk = r.read(65536)
                if not chunk: break
                f.write(chunk)
                done += len(chunk)
                if progress_cb: progress_cb(done, total)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _themed_dialog(parent, theme, title, icon, message, buttons, width=420):
    """
    Generic themed modal dialog — same visual style as ColorPickerDialog.

    buttons: list of (label, accent_key, return_value)
             e.g. [("✓ Yes", 'accent_1', True), ("✕ No", 'accent_2', False)]

    Returns the return_value of whichever button was clicked,
    or None if the window is closed without clicking.
    """
    t = theme
    result_holder = [None]

    dlg = tk.Toplevel(parent)
    dlg.configure(bg=t['accent_1'],           # 1px accent border via outer bg
                  highlightthickness=0)
    dlg.overrideredirect(True)
    dlg.resizable(False, False)
    dlg.transient(parent)
    dlg.grab_set()
    apply_window_icon(dlg)

    inner = tk.Frame(dlg, bg=t['glass_bg'])
    inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

    build_themed_titlebar(inner, t, title, on_close=lambda: dlg.destroy())

    body = tk.Frame(inner, bg=t['glass_bg'])
    body.pack(fill=tk.BOTH, expand=True, padx=24, pady=(18, 20))

    # Icon + heading row
    if icon:
        tk.Label(body, text=icon, bg=t['glass_bg'], fg=t['accent_1'],
                 font=('Segoe UI', 20)).pack(anchor='w', pady=(0, 6))

    # Message text — wrap at width - margins
    tk.Label(body, text=message, bg=t['glass_bg'], fg=t['fg_color'],
             font=('Segoe UI', 10), justify='left',
             wraplength=width - 60, anchor='w').pack(anchor='w', pady=(0, 18))

    tk.Frame(body, bg=t['titlebar_sep'], height=1).pack(fill='x', pady=(0, 14))

    btn_row = tk.Frame(body, bg=t['glass_bg'])
    btn_row.pack(anchor='e')

    def _click(val):
        result_holder[0] = val
        try: dlg.destroy()
        except: pass

    for label, accent_key, val in buttons:
        bg = t.get(accent_key, t['accent_1'])
        fg = t.get('send_btn_fg', '#ffffff')
        tk.Button(btn_row, text=label, bg=bg, fg=fg,
                  font=('Segoe UI', 10, 'bold'), relief=tk.FLAT,
                  padx=18, pady=8, cursor='hand2',
                  command=lambda v=val: _click(v)).pack(side='left', padx=(0, 8))

    # Size and centre — withdraw first so the window doesn't flash at 0,0
    dlg.withdraw()
    dlg.update_idletasks()
    dlg.update()
    w  = max(dlg.winfo_reqwidth(), width)
    h  = dlg.winfo_reqheight()
    px = (dlg.winfo_screenwidth()  - w) // 2
    py = (dlg.winfo_screenheight() - h) // 2
    dlg.geometry(f'{w}x{h}+{px}+{py}')
    dlg.deiconify()
    dlg.lift()
    dlg.attributes('-topmost', True)
    dlg.after(100, lambda: dlg.attributes('-topmost', False))
    dlg.focus_force()

    parent.wait_window(dlg)
    return result_holder[0]


def _themed_info(parent, theme, title, icon, message, width=420):
    """Convenience wrapper for a single-button info dialog."""
    _themed_dialog(parent, theme, title, icon, message,
                   [("✓  OK", 'accent_1', True)], width=width)


def _themed_error(parent, theme, title, message, width=420):
    """Convenience wrapper for a single-button error dialog."""
    _themed_dialog(parent, theme, title, '✕', message,
                   [("OK", 'accent_2', True)], width=width)


def _themed_yesno(parent, theme, title, icon, message, yes_label="✓  Yes",
                  no_label="✕  No", width=420):
    """Convenience wrapper for a yes/no confirmation dialog."""
    return _themed_dialog(parent, theme, title, icon, message,
                          [(yes_label, 'accent_1', True),
                           (no_label,  'accent_2', False)], width=width)


def check_for_updates(parent, theme, silent=False):
    t = theme

    # Show a "Checking..." window immediately so the UI doesn't freeze
    checking_win = [None]
    if not silent:
        cw = tk.Toplevel(parent)
        cw.configure(bg=t['accent_1'], highlightthickness=0)
        cw.overrideredirect(True)
        cw.resizable(False, False)
        cw.transient(parent)
        apply_window_icon(cw)
        _ci = tk.Frame(cw, bg=t['glass_bg'])
        _ci.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        build_themed_titlebar(_ci, t, "Checking for Updates...")
        _cb = tk.Frame(_ci, bg=t['glass_bg'])
        _cb.pack(fill=tk.BOTH, expand=True, padx=24, pady=20)
        tk.Label(_cb, text='✦', bg=t['glass_bg'], fg=t['accent_1'],
                 font=('Segoe UI', 20)).pack(anchor='w', pady=(0, 6))
        tk.Label(_cb, text=f"Contacting GitHub...\nChecking for updates to v{HAVEN_VERSION}.",
                 bg=t['glass_bg'], fg=t['fg_color'],
                 font=('Segoe UI', 10), justify='left').pack(anchor='w')
        cw.withdraw()
        cw.update_idletasks()
        cw.update()
        _cw, _ch = 380, cw.winfo_reqheight()
        cw.geometry(f'{_cw}x{_ch}+'
                    f'{(cw.winfo_screenwidth()  - _cw) // 2}+'
                    f'{(cw.winfo_screenheight() - _ch) // 2}')
        cw.deiconify()
        cw.lift()
        cw.attributes('-topmost', True)
        cw.after(100, lambda: cw.attributes('-topmost', False))
        cw.update()
        checking_win[0] = cw

    def _close_checking():
        try:
            if checking_win[0]: checking_win[0].destroy()
        except: pass
        checking_win[0] = None

    def _do_check():
        data = _github_api('/releases/latest')
        parent.after(0, lambda: _on_result(data))

    def _on_result(data):
        _close_checking()
        if not data:
            if not silent:
                _themed_error(parent, t, "Update Check Failed",
                              "Could not reach GitHub.\nCheck your internet connection.")
            return
        tag = data.get('tag_name', '').lstrip('v')
        if not tag:
            if not silent:
                _themed_error(parent, t, "Update Check Failed",
                              "Could not read version from GitHub release.")
            return
        def _ver(s):
            try:    return tuple(int(x) for x in s.split('.'))
            except: return (0,)
        if _ver(tag) <= _ver(HAVEN_VERSION):
            if not silent:
                _themed_info(parent, t, "Haven — Up to Date", '✦',
                             f"You are running the latest version.\n\nv{HAVEN_VERSION}  ·  no update available")
            return
        assets   = {a['name']: a['browser_download_url'] for a in data.get('assets', [])}
        exe_url  = assets.get('Haven.exe')
        sums_url = assets.get('SHA256SUMS.txt')
        if not exe_url:
            if not silent:
                _themed_error(parent, t, "Update Check Failed",
                              f"v{tag} is available but no Haven.exe asset was found.")
            return
        notes = (data.get('body') or '').strip()[:400]
        update_msg = f"Haven v{tag} is available.\nYou are on v{HAVEN_VERSION}."
        if notes:
            update_msg += f"\n\n{notes}"
        update_msg += "\n\nDownload and install now?"
        if not _themed_yesno(parent, t, "Haven — Update Available", '⬡',
                             update_msg,
                             yes_label="⬇  Download & Install",
                             no_label="✕  Not Now",
                             width=460):
            return
        # proceed to download — build progress window and kick off download thread
        prog_win = tk.Toplevel(parent)
        prog_win.configure(bg=t['accent_1'], highlightthickness=0)
        prog_win.overrideredirect(True)
        prog_win.resizable(False, False)
        prog_win.transient(parent)
        prog_win.grab_set()
        apply_window_icon(prog_win)

        prog_inner = tk.Frame(prog_win, bg=t['glass_bg'])
        prog_inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        build_themed_titlebar(prog_inner, t, f"Downloading Haven v{tag}...")

        prog_body = tk.Frame(prog_inner, bg=t['glass_bg'])
        prog_body.pack(fill=tk.BOTH, expand=True, padx=24, pady=20)

        tk.Label(prog_body, text="\u2b07  Downloading Haven.exe",
                 bg=t['glass_bg'], fg=t['accent_1'],
                 font=('Segoe UI', 11, 'bold')).pack(anchor='w', pady=(0, 10))

        bar_bg = tk.Frame(prog_body, bg=t['glass_accent'], height=10)
        bar_bg.pack(fill='x', pady=(0, 6))
        bar_bg.pack_propagate(False)

        bar_fill = tk.Frame(bar_bg, bg=t['accent_1'], height=10, width=0)
        bar_fill.place(x=0, y=0, relheight=1, width=0)

        prog_pct = tk.Label(prog_body, text="0%",
                            bg=t['glass_bg'], fg=t['accent_4'],
                            font=('Segoe UI', 9))
        prog_pct.pack(anchor='e')

        prog_win.withdraw()
        prog_win.update_idletasks()
        prog_win.update()
        pw = 400
        ph = prog_win.winfo_reqheight()
        prog_win.geometry(
            f'{pw}x{ph}+'
            f'{(prog_win.winfo_screenwidth()  - pw) // 2}+'
            f'{(prog_win.winfo_screenheight() - ph) // 2}')
        prog_win.deiconify()
        prog_win.lift()
        prog_win.attributes('-topmost', True)
        prog_win.after(100, lambda: prog_win.attributes('-topmost', False))
        prog_win.update()

        import tempfile, sys, subprocess as _sp
        tmp_exe  = os.path.join(tempfile.gettempdir(), f'Haven_v{tag}.exe')
        tmp_sums = os.path.join(tempfile.gettempdir(), f'Haven_v{tag}_SHA256SUMS.txt')
        error_holder = [None]

        def _cleanup(paths):
            for p in paths:
                try:
                    if os.path.exists(p): os.remove(p)
                except: pass

        def _progress(done, total):
            if total and prog_win.winfo_exists():
                pct = done / total
                try:
                    bar_bg.update_idletasks()
                    bar_w = bar_bg.winfo_width()
                    fill_w = max(0, int(bar_w * pct))
                    parent.after(0, lambda fw=fill_w, p=pct: (
                        bar_fill.place_configure(width=fw),
                        prog_pct.config(text=f"{int(p * 100)}%"),
                    ))
                except Exception:
                    pass

        def _do_download():
            try:
                _download_file(exe_url, tmp_exe, _progress)
                if sums_url:
                    _download_file(sums_url, tmp_sums)
            except Exception as e:
                error_holder[0] = str(e)
            finally:
                parent.after(0, _download_done)

        def _download_done():
            try: prog_win.destroy()
            except: pass

            if error_holder[0]:
                _themed_error(parent, t, "Haven \u2014 Download Failed",
                              f"The download could not be completed.\n\n{error_holder[0]}")
                _cleanup([tmp_exe, tmp_sums])
                return

            actual_hash = _sha256_file(tmp_exe)

            if sums_url and os.path.exists(tmp_sums):
                expected_hash = None
                try:
                    for line in open(tmp_sums).read().splitlines():
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].strip('* ') == 'Haven.exe':
                            expected_hash = parts[0].lower(); break
                except: pass

                if expected_hash and actual_hash.lower() != expected_hash:
                    _themed_error(parent, t, "Haven \u2014 Security Error",
                                  f"Checksum mismatch \u2014 the file has been deleted.\n\n"
                                  f"Expected:\n{expected_hash}\n\nGot:\n{actual_hash}")
                    _cleanup([tmp_exe, tmp_sums])
                    return
                elif not expected_hash:
                    if not _themed_yesno(parent, t, "Haven \u2014 Checksum Warning", '\u26a0',
                                         f"Could not parse SHA256SUMS.txt.\n\n"
                                         f"SHA-256:  {actual_hash}\n\nInstall anyway?",
                                         yes_label="\u26a0  Install Anyway",
                                         no_label="\u2715  Cancel"):
                        _cleanup([tmp_exe, tmp_sums])
                        return
            else:
                if not _themed_yesno(parent, t, "Haven \u2014 No Checksum", '\u26a0',
                                     f"No SHA256SUMS.txt was found in this release.\n\n"
                                     f"SHA-256:  {actual_hash}\n\nInstall anyway?",
                                     yes_label="\u26a0  Install Anyway",
                                     no_label="\u2715  Cancel"):
                    _cleanup([tmp_exe, tmp_sums])
                    return

            current_exe = sys.executable if getattr(sys, 'frozen', False) else None
            if not current_exe or not current_exe.lower().endswith('.exe'):
                _themed_info(parent, t, "Haven \u2014 Downloaded", '\u2726',
                             f"Update saved to:\n{tmp_exe}\n\nReplace Haven.exe manually to complete.")
                _cleanup([tmp_sums])
                return

            old_exe = current_exe.replace('.exe', '.old.exe')
            try:
                if os.path.exists(old_exe):
                    os.remove(old_exe)
                os.rename(current_exe, old_exe)
            except Exception as e:
                _themed_error(parent, t, "Haven \u2014 Install Failed",
                              f"Could not rename Haven.exe:\n\n{e}")
                _cleanup([tmp_sums])
                return

            try:
                import shutil
                shutil.move(tmp_exe, current_exe)
            except Exception as e:
                try: os.rename(old_exe, current_exe)
                except: pass
                _themed_error(parent, t, "Haven \u2014 Install Failed",
                              f"Could not place new Haven.exe:\n\n{e}")
                _cleanup([tmp_sums])
                return

            _cleanup([tmp_sums])
            _themed_info(parent, t, "Haven \u2014 Update Complete", '\u2726',
                         f"Haven v{tag} installed successfully.\n\nPlease restart Haven to use the new version.")
            try:
                parent.destroy()
            except Exception:
                pass
            import sys as _sys
            _sys.exit(0)

        import threading
        threading.Thread(target=_do_download, daemon=True).start()

    # Kick off the GitHub API check on a background thread — never blocks the UI
    import threading
    threading.Thread(target=_do_check, daemon=True).start()

# Main client
# ═══════════════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════════════
# SOUND SETTINGS DIALOG
# ══════════════════════════════════════════════════════════════════════════════

class SoundSettingsDialog(tk.Toplevel):
    """
    Sound settings panel — enabled toggle, SFX master volume, per-user voice volume.
    """

    def __init__(self, parent, theme, sounds_enabled, sfx_volume, user_volumes,
                 known_users, on_save):
        super().__init__(parent)
        self.t       = theme
        self.on_save = on_save
        self.overrideredirect(True)
        self.configure(bg=theme['accent_4'])
        apply_window_icon(self)

        t = self.t
        build_themed_titlebar(self, t, "Sound Settings", on_close=self.destroy)

        outer = tk.Frame(self, bg=t['glass_bg'], highlightthickness=0)
        outer.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 2))

        self._enabled_var = tk.BooleanVar(value=sounds_enabled)
        self._sfx_var     = tk.IntVar(value=int(sfx_volume))

        tk.Label(outer, text="SOUND SETTINGS", bg=t['glass_bg'], fg=t['accent_4'],
                 font=('Segoe UI', 8, 'bold')).pack(anchor='w', padx=16, pady=(14, 4))
        tk.Frame(outer, bg=t['titlebar_sep'], height=1).pack(fill=tk.X, padx=16, pady=(0, 8))

        # Enabled toggle
        en_row = tk.Frame(outer, bg=t['glass_bg'])
        en_row.pack(fill=tk.X, padx=16, pady=4)
        tk.Label(en_row, text="Sounds Enabled", bg=t['glass_bg'], fg=t['fg_color'],
                 font=('Segoe UI', 9), width=18, anchor='w').pack(side=tk.LEFT)
        tk.Checkbutton(en_row, variable=self._enabled_var,
                       bg=t['glass_bg'], fg=t['fg_color'],
                       activebackground=t['glass_bg'], selectcolor=t['glass_accent'],
                       relief=tk.FLAT).pack(side=tk.LEFT)

        # SFX master volume
        sfx_row = tk.Frame(outer, bg=t['glass_bg'])
        sfx_row.pack(fill=tk.X, padx=16, pady=4)
        tk.Label(sfx_row, text="SFX Volume", bg=t['glass_bg'], fg=t['fg_color'],
                 font=('Segoe UI', 9), width=18, anchor='w').pack(side=tk.LEFT)
        sfx_val = tk.Label(sfx_row, text=f"{int(sfx_volume)}%", bg=t['glass_bg'],
                           fg=t['accent_1'], font=('Segoe UI', 9), width=5)
        sfx_val.pack(side=tk.RIGHT)
        tk.Scale(sfx_row, from_=0, to=200, orient=tk.HORIZONTAL, variable=self._sfx_var,
                 bg=t['glass_bg'], fg=t['fg_color'], troughcolor=t['glass_accent'],
                 highlightthickness=0, showvalue=False, length=140,
                 command=lambda v: sfx_val.config(text=f"{int(float(v))}%")).pack(side=tk.LEFT, padx=(8, 4))

        # Per-user voice volumes
        self._user_vars = {}
        if known_users:
            tk.Frame(outer, bg=t['titlebar_sep'], height=1).pack(fill=tk.X, padx=16, pady=(10, 6))
            tk.Label(outer, text="PER-USER VOICE VOLUME", bg=t['glass_bg'], fg=t['accent_4'],
                     font=('Segoe UI', 8, 'bold')).pack(anchor='w', padx=16)

            sc = tk.Frame(outer, bg=t['glass_bg'])
            sc.pack(fill=tk.BOTH, expand=True, padx=16, pady=(6, 4))

            h = min(200, len(known_users) * 38)
            canvas = tk.Canvas(sc, bg=t['glass_bg'], highlightthickness=0, height=h)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

            if len(known_users) > 5:
                sb = make_scrollbar(sc, t, orient=tk.VERTICAL, command=canvas.yview)
                sb.pack(side=tk.RIGHT, fill=tk.Y)
                canvas.configure(yscrollcommand=sb.set)

            uf = tk.Frame(canvas, bg=t['glass_bg'])
            canvas.create_window((0, 0), window=uf, anchor='nw')
            uf.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

            for uname in known_users:
                vol = user_volumes.get(uname, 100)
                var = tk.IntVar(value=int(vol))
                self._user_vars[uname] = var
                row = tk.Frame(uf, bg=t['glass_bg'])
                row.pack(fill=tk.X, pady=2)
                tk.Label(row, text=uname, bg=t['glass_bg'], fg=t['fg_color'],
                         font=('Segoe UI', 9), width=14, anchor='w').pack(side=tk.LEFT)
                vl = tk.Label(row, text=f"{int(vol)}%", bg=t['glass_bg'],
                              fg=t['accent_1'], font=('Segoe UI', 9), width=5)
                vl.pack(side=tk.RIGHT)
                tk.Scale(row, from_=0, to=200, orient=tk.HORIZONTAL, variable=var,
                         bg=t['glass_bg'], fg=t['fg_color'], troughcolor=t['glass_accent'],
                         highlightthickness=0, showvalue=False, length=120,
                         command=lambda v, lbl=vl: lbl.config(text=f"{int(float(v))}%")).pack(side=tk.LEFT, padx=(8,4))
        else:
            tk.Label(outer, text="(No users seen this session yet)",
                     bg=t['glass_bg'], fg=t['accent_4'],
                     font=('Segoe UI', 8, 'italic')).pack(padx=16, pady=8, anchor='w')

        # Buttons
        tk.Frame(outer, bg=t['titlebar_sep'], height=1).pack(fill=tk.X, padx=16, pady=(10, 6))
        btn_row = tk.Frame(outer, bg=t['glass_bg'])
        btn_row.pack(fill=tk.X, padx=16, pady=(0, 14))
        tk.Button(btn_row, text="SAVE", bg=t['accent_1'], fg=t['send_btn_fg'],
                  font=('Segoe UI', 9, 'bold'), relief=tk.FLAT, padx=16, pady=4,
                  command=self._save).pack(side=tk.RIGHT, padx=(6, 0))
        tk.Button(btn_row, text="Cancel", bg=t['glass_accent'], fg=t['fg_color'],
                  font=('Segoe UI', 9), relief=tk.FLAT, padx=16, pady=4,
                  command=self.destroy).pack(side=tk.RIGHT)

        self.withdraw()          # hide while measuring
        self.update_idletasks()
        self.update_idletasks()  # second pass — overrideredirect windows need it
        w  = max(self.winfo_reqwidth(),  self.winfo_width())
        h2 = max(self.winfo_reqheight(), self.winfo_height())
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x  = sw // 2 - w // 2
        y  = sh // 2 - h2 // 2
        self.geometry(f"{w}x{h2}+{x}+{y}")
        self.deiconify()
        self.lift()
        self.attributes('-topmost', True)
        self.after(100, lambda: self.attributes('-topmost', False))
        # (non-modal)

    def _save(self):
        self.on_save(
            self._enabled_var.get(),
            int(self._sfx_var.get()),
            {u: int(v.get()) for u, v in self._user_vars.items()}
        )
        self.destroy()



# ══════════════════════════════════════════════════════════════════════════════
# LORE BOOK DIALOG
# A tabbed paged book showing the world's living mythology.
# ══════════════════════════════════════════════════════════════════════════════

class LoreBookDialog(tk.Toplevel):
    """
    The Lore Book — tabs as page tabs, themed, centered on screen.
    Pages: The Record | Souls | Bonds | Legends | The Deep Record
    """

    PAGES = ["The Record", "Souls", "Bonds", "Legends", "The Deep Record"]

    def __init__(self, parent, theme, summary, own_identity):
        super().__init__(parent)
        self.t           = theme
        self.summary     = summary
        self.own_identity = own_identity
        self._current    = 0

        self.overrideredirect(True)
        self.configure(bg=theme['accent_4'])
        apply_window_icon(self)

        t = self.t
        build_themed_titlebar(self, t, "✦  The Lore Book", on_close=self.destroy)

        outer = tk.Frame(self, bg=t['glass_bg'], highlightthickness=0)
        outer.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 2))

        # ── Tab row ───────────────────────────────────────────────────────────
        tab_row = tk.Frame(outer, bg=t['glass_accent'])
        tab_row.pack(fill=tk.X, padx=0, pady=0)

        self._tab_btns = []
        for i, name in enumerate(self.PAGES):
            btn = tk.Label(tab_row, text=name,
                           bg=t['glass_accent'], fg=t['accent_4'],
                           font=('Segoe UI', 8), padx=10, pady=5, cursor='hand2')
            btn.pack(side=tk.LEFT)
            btn.bind('<Button-1>', lambda e, idx=i: self._switch_page(idx))
            btn.bind('<Enter>', lambda e, b=btn: b.config(fg=t['fg_color']) if b != self._tab_btns[self._current] else None)
            btn.bind('<Leave>', lambda e, b=btn, idx2=i: b.config(fg=(t['send_btn_fg'] if idx2 == self._current else t['accent_4'])))
            self._tab_btns.append(btn)

        tk.Frame(outer, bg=t['accent_4'], height=1).pack(fill=tk.X)

        # ── Page area ─────────────────────────────────────────────────────────
        self._page_frame = tk.Frame(outer, bg=t['glass_bg'], width=420, height=480)
        self._page_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        self._page_frame.pack_propagate(False)

        # Close is handled by the titlebar X button

        self._switch_page(0)

        self.withdraw()
        self.update_idletasks()
        self.update_idletasks()
        w  = max(self.winfo_reqwidth(), 440)
        h2 = max(self.winfo_reqheight(), 560)
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h2}+{sw//2 - w//2}+{sh//2 - h2//2}")
        self.deiconify()
        self.lift()
        self.attributes('-topmost', True)
        self.after(100, lambda: self.attributes('-topmost', False))
        # (non-modal)

    def _switch_page(self, idx):
        t = self.t
        self._current = idx
        # Update tab styling
        for i, btn in enumerate(self._tab_btns):
            if i == idx:
                btn.config(bg=t['glass_bg'], fg=t['send_btn_fg'],
                           font=('Segoe UI', 8, 'bold'))
            else:
                btn.config(bg=t['glass_accent'], fg=t['accent_4'],
                           font=('Segoe UI', 8))

        for w in self._page_frame.winfo_children():
            w.destroy()

        # Scrollable content area
        canvas = tk.Canvas(self._page_frame, bg=t['glass_bg'],
                           highlightthickness=0, bd=0)
        sb = make_scrollbar(self._page_frame, t, orient=tk.VERTICAL, command=canvas.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        canvas.configure(yscrollcommand=sb.set)

        content = tk.Frame(canvas, bg=t['glass_bg'])
        cwin = canvas.create_window((0, 0), window=content, anchor='nw')
        content.bind('<Configure>', lambda e: canvas.configure(
            scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>', lambda e: canvas.itemconfig(cwin, width=e.width))

        # Mousewheel — scoped to canvas only, guarded against destroyed widget
        def _mw(event):
            if canvas.winfo_exists():
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind('<MouseWheel>', _mw)
        content.bind('<MouseWheel>', _mw)

        # Build page
        builders = [
            self._page_record,
            self._page_souls,
            self._page_bonds,
            self._page_legends,
            self._page_deep_record,
        ]
        builders[idx](content)

    def _lbl(self, parent, text, color=None, bold=False, italic=False,
             pady=4, padx=16, wrap=380, size=8):
        t = self.t
        style = 'bold italic' if bold and italic else 'bold' if bold else 'italic' if italic else 'normal'
        tk.Label(parent, text=text, bg=t['glass_bg'],
                 fg=color or t['fg_color'],
                 font=('Segoe UI', size, style), wraplength=wrap,
                 padx=padx, pady=pady, justify='left', anchor='w').pack(fill=tk.X)

    def _sep(self, parent):
        tk.Frame(parent, bg=self.t['accent_4'], height=1).pack(
            fill=tk.X, padx=16, pady=6)

    def _head(self, parent, text):
        self._lbl(parent, text, color=self.t.get('accent_1','#00ff88'),
                  bold=True, size=9, pady=10)

    def _page_record(self, p):
        t = self.t; s = self.summary
        self._head(p, "✦  THE RECORD")
        self._lbl(p, s.get('world_age',''), italic=True)
        self._lbl(p, s.get('season',''), color=t.get('accent_1'))
        self._sep(p)

        soul_counts = s.get('soul_counts', {})
        mortals  = soul_counts.get('mortal', 0)
        seraphs  = soul_counts.get('seraph', 0)
        daemons  = soul_counts.get('daemon', 0)
        self._lbl(p, f"{s.get('total_souls',0)} souls have passed through this world.", bold=True)
        if seraphs: self._lbl(p, f"Of these, {seraphs} are of Seraphic nature.", italic=True)
        if daemons: self._lbl(p, f"{daemons} are of Daemonic nature.", italic=True)
        if mortals: self._lbl(p, f"{mortals} are mortal.")
        self._sep(p)

        self._lbl(p, f"{s.get('total_bonds',0)} bonds have been recorded between souls.", italic=True)
        self._lbl(p, f"{s.get('total_events',0)} events are in the record.")
        choir = s.get('choir_count', 0)
        if choir:
            self._lbl(p, f"The Choir has convened {choir} time{'s' if choir > 1 else ''}.", italic=True,
                     color=t.get('accent_1'))
        self._sep(p)
        self._head(p, "RECENT RECORD")
        for line in s.get('recent_lore', []):
            self._lbl(p, line, italic=True, color=t['accent_4'], pady=2)

        own = self.own_identity
        if own:
            self._sep(p)
            self._head(p, "YOUR RECORD")
            soul = own.get('soul_type', 'mortal')
            soul_label = {'seraph': '✦ Seraph', 'daemon': '⬡ Daemon', 'mortal': '· Mortal'}.get(soul, soul)
            self._lbl(p, soul_label, color=t.get('accent_1'), bold=True, pady=2)
            self._lbl(p, own.get('title',''), bold=True, pady=2)
            self._lbl(p, own.get('origin',''), pady=2)
            if own.get('faction'): self._lbl(p, own['faction'], italic=True, pady=2)
            if own.get('trait'): self._lbl(p, f'"{own["trait"]}"', italic=True,
                                            color=t['fg_color'], pady=4)

    def _page_souls(self, p):
        t = self.t; s = self.summary
        self._head(p, "✦  THE SOULS")
        all_users = s.get('all_users', [])
        if not all_users:
            self._lbl(p, "No souls recorded yet.", italic=True, color=t['accent_4'])
            return
        self._lbl(p, f"{len(all_users)} souls in the record.", italic=True, pady=2)
        self._sep(p)
        soul_icons = {'seraph': '✦', 'daemon': '⬡', 'mortal': '·'}
        for u in all_users:
            soul  = u.get('soul_type', 'mortal')
            icon  = soul_icons.get(soul, '·')
            uname = u.get('username', '')
            self._lbl(p, f"{icon}  {uname}", bold=True, pady=8,
                     color={'seraph': t.get('accent_1','#00ff88'),
                             'daemon': t.get('accent_2','#cc4444'),
                             'mortal': t['fg_color']}.get(soul, t['fg_color']))
            if u.get('title'): self._lbl(p, u['title'], pady=1, color=t['accent_4'])
            if u.get('origin'): self._lbl(p, u['origin'], pady=1, color=t['accent_4'])
            if u.get('faction'): self._lbl(p, u['faction'], italic=True, pady=1, color=t['accent_4'])
            if u.get('trait'): self._lbl(p, f'"{u["trait"]}"', italic=True, pady=4)
            tk.Frame(p, bg=t['glass_accent'], height=1).pack(fill=tk.X, padx=16, pady=1)

    def _page_bonds(self, p):
        t = self.t; s = self.summary
        self._head(p, "✦  BONDS & ALLIANCES")
        all_bonds = s.get('all_bonds', [])
        if not all_bonds:
            self._lbl(p, "No bonds have formed yet.", italic=True, color=t['accent_4'])
            self._lbl(p, "Bonds form when souls meet more than once in the same region.",
                     italic=True, color=t['accent_4'], pady=2)
            return
        self._lbl(p, f"{len(all_bonds)} bonds in the record.", italic=True, pady=2)
        self._sep(p)
        for bond in all_bonds:
            a = bond.get('a',''); b = bond.get('b','')
            count  = bond.get('count', 0)
            region = bond.get('region','')
            depth  = "Deep bond" if count >= 5 else "Known to each other"
            self._lbl(p, f"{a}  ·  {b}", bold=True, pady=8, color=t.get('accent_1'))
            self._lbl(p, f"{depth}  ·  {count} meeting{'s' if count > 1 else ''}", pady=1,
                     color=t['accent_4'])
            if region: self._lbl(p, f"Last in {region}", italic=True, pady=1, color=t['accent_4'])
            tk.Frame(p, bg=t['glass_accent'], height=1).pack(fill=tk.X, padx=16, pady=1)

    def _page_legends(self, p):
        t = self.t; s = self.summary
        self._head(p, "✦  LEGENDS & HAUNTINGS")

        legends = s.get('all_legends', [])
        if legends:
            self._lbl(p, "— regional legends —", italic=True, color=t['accent_4'], pady=2)
            for leg in legends:
                self._lbl(p, leg, italic=True, pady=4)
                tk.Frame(p, bg=t['glass_accent'], height=1).pack(fill=tk.X, padx=16, pady=2)

        ghosts = s.get('all_ghosts', [])
        if ghosts:
            self._sep(p)
            self._lbl(p, "— from the ghost records —", italic=True,
                     color=t.get('accent_2','#cc4444'), pady=2)
            for tale in ghosts:
                self._lbl(p, tale, italic=True, color=t.get('accent_2','#cc4444'), pady=4)
                tk.Frame(p, bg=t['glass_accent'], height=1).pack(fill=tk.X, padx=16, pady=2)

        if not legends and not ghosts:
            self._lbl(p, "The world is young. No legends have formed yet.", italic=True,
                     color=t['accent_4'])
            self._lbl(p, "Legends emerge when regions accumulate enough history.",
                     italic=True, color=t['accent_4'], pady=2)
            self._lbl(p, "Ghost tales appear when souls have been absent for more than 7 days.",
                     italic=True, color=t['accent_4'], pady=2)

    def _page_deep_record(self, p):
        t = self.t; s = self.summary
        self._head(p, "✦  THE DEEP RECORD")
        self._lbl(p, "A complete account of what the world has witnessed.", italic=True,
                 color=t['accent_4'], pady=2)
        self._sep(p)

        events = s.get('full_events', [])
        if not events:
            self._lbl(p, "The record is empty.", italic=True, color=t['accent_4'])
            return

        type_colors = {
            'first_arrival': t.get('accent_1','#00ff88'),
            'arrival':       t['fg_color'],
            'return':        t.get('accent_1','#00ff88'),
            'departure':     t['accent_4'],
            'silence':       t['accent_4'],
            'gathering':     t.get('accent_1','#00ff88'),
            'choir':         t.get('accent_1','#00ff88'),
        }
        for e in reversed(events):
            etype = e.get('type','')
            ts    = e.get('timestamp', 0)
            color = type_colors.get(etype, t['fg_color'])
            if ts:
                dt = datetime.datetime.fromtimestamp(ts).strftime('%b %d, %H:%M')
                self._lbl(p, dt, color=t['accent_4'], size=7, pady=6)
            self._lbl(p, e.get('text',''), color=color, italic=True, pady=1)
            for extra in e.get('extra', []):
                self._lbl(p, extra, color=t['accent_4'], italic=True, pady=1)


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
        self._last_send_time = 0.0       # throttle key-repeat sends
        self._online_users      = []        # last userlist_full payload — used for theme rebuild
        self._world_identities  = {}        # username → world identity dict (expansion worlds)
        self._sigil_canvases    = {}        # username → sigil tk.Canvas for glow effect
        self._world_summary     = None      # latest world summary from server
        self._expansion_enabled = False     # whether server has expansion worlds on
        self.saved_wire_hash = None   # SHA256(password) for reconnect — never plaintext
        self.authenticated   = False  # set True after auth_ok
        self._child_windows  = []      # open non-modal dialogs — lifted on restore

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

        _load_sound_buffers()  # decode WAVs to raw PCM for zero-latency PyAudio playback

        config = self.load_config()
        self.ptt_key    = config.get('ptt_key', 'Control_L')
        self.name_color = config.get('name_color', self.generate_random_color())
        self.theme_name = config.get('theme', 'default')
        self.theme      = load_theme(self.theme_name)
        self.sounds_enabled     = config.get('sounds_enabled', True)
        self.sfx_volume         = config.get('sfx_volume', 100)
        self.user_volumes       = config.get('user_volumes', {})
        self.ptt_release_delay  = config.get('ptt_release_delay', 0.0)
        self._saved_win_w       = config.get('window_w', 900)
        self._saved_win_h       = config.get('window_h', 850)

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
        sw  = self.root.winfo_screenwidth()
        sh  = self.root.winfo_screenheight()
        ww  = getattr(self, '_saved_win_w', 900)
        wh  = getattr(self, '_saved_win_h', 850)
        self.root.geometry(f"{ww}x{wh}+{sw//2-ww//2}+{sh//2-wh//2}")
        self.root.minsize(800, 500)
        self.root.resizable(True, True)
        _IS_LINUX = sys.platform.startswith('linux')
        if _IS_LINUX:
            # On Linux/X11, overrideredirect(True) prevents the WM from routing
            # keyboard events — the window renders but can't receive typing.
            # Use splash/override window type instead: borderless but focusable.
            try:
                self.root.wm_attributes('-type', 'splash')
            except Exception:
                pass  # Wayland or older X11 — fall back gracefully
        else:
            self.root.overrideredirect(True)
        self.root.lift()
        self.root.focus_force()
        self.root.attributes('-topmost', True)
        self.root.after(100, lambda: self.root.attributes('-topmost', False))
        if _IS_LINUX:
            # Re-request focus after event loop settles on Linux
            self.root.after(200, lambda: self.root.focus_force())
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
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        self._tray_has_notification = False

        self.setup_global_hotkey()
        self.root.protocol("WM_DELETE_WINDOW", self.minimize_to_tray)
        self.root.bind("<Map>", lambda e: self.root.after(100, self._lift_children))
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
        self.root.after(150, self._lift_children)

    def minimize_to_tray(self):
        # Only hide the window — do NOT touch self.running or the TCP connection.
        # The server keeps the user in the userlist; they remain fully online.
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

        self.root.configure(bg=self.theme['accent_4'])
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

        # Rebuild from the last known online list, not the full color history
        self.update_userlist_with_colors(self._online_users)


    # ── Login helpers ────────────────────────────────────────────

    def _run_login_loop(self, config, prefill=None, error_msg=None):
        current_prefill = prefill or {}
        current_error   = error_msg
        while True:
            # root stays withdrawn — LoginScreen is a Toplevel that centers itself
            dialog = LoginScreen(self.root, self.theme,
                                 prefill=current_prefill, error_msg=current_error)
            self.root.wait_window(dialog)
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

            # ── TOFU cert check ───────────────────────────────────────────────
            der = tcp_sock.getpeercert(binary_form=True)
            if not der:
                tcp_sock.close()
                raise ConnectionError("Server did not present a TLS certificate")
            if not _tofu_check(server_ip, SERVER_TCP_PORT, der,
                               parent_window=getattr(self, 'root', None),
                               theme=getattr(self, 'theme', None)):
                tcp_sock.close()
                raise ConnectionError("Server certificate not trusted — connection refused")

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
                        pass  # crypto active — no console noise
                        # Silent startup update check (non-blocking)
                        import threading as _ut
                        _ut.Thread(target=lambda: self.root.after(5000, lambda: check_for_updates(self.root, self.theme, silent=True)), daemon=True).start()
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
        # Capture current window size if the main window is visible
        try:
            if self.root.winfo_viewable():
                w = self.root.winfo_width()
                h = self.root.winfo_height()
                if w > 200 and h > 200:   # sanity check — ignore collapsed/hidden state
                    self._saved_win_w = w
                    self._saved_win_h = h
        except Exception:
            pass
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
            'sounds_enabled':      getattr(self, 'sounds_enabled', True),
            'sfx_volume':          getattr(self, 'sfx_volume', 100),
            'user_volumes':        getattr(self, 'user_volumes', {}),
            'ptt_release_delay':   getattr(self, 'ptt_release_delay', 0.0),
            'window_w':            getattr(self, '_saved_win_w', 900),
            'window_h':            getattr(self, '_saved_win_h', 850),
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

        # Maximize / restore button
        self._maximized = False
        self._pre_max_geometry = None

        def _toggle_maximize():
            if not self._maximized:
                self._pre_max_geometry = self.root.geometry()
                sw = self.root.winfo_screenwidth()
                sh = self.root.winfo_screenheight()
                self.root.geometry(f"{sw}x{sh}+0+0")
                self._maximized = True
                max_btn.config(text="⬜")
            else:
                if self._pre_max_geometry:
                    self.root.geometry(self._pre_max_geometry)
                self._maximized = False
                max_btn.config(text="⬜")

        max_btn = tk.Button(controls_frame, text="⬜", bg=t['titlebar_bg'], fg=t['titlebar_fg'],
                            font=('Segoe UI', 11), bd=0,
                            activebackground=t['accent_3'], activeforeground=t['fg_color'],
                            command=_toggle_maximize, cursor='hand2',
                            padx=6, pady=0)
        max_btn.pack(side=tk.LEFT, padx=2)

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
            w.bind('<Double-Button-1>', lambda e: _toggle_maximize())

        tk.Frame(self.root, bg=t['titlebar_sep'], height=1).pack(fill=tk.X, side=tk.TOP)

        # Save window size whenever it's resized
        def _on_resize(event):
            if event.widget is self.root and not self._maximized:
                self._saved_win_w = event.width
                self._saved_win_h = event.height
        self.root.bind('<Configure>', _on_resize)

        # On Linux: re-focus the entry widget whenever the window gets focus
        # (compensates for WM occasionally stealing focus back)
        if sys.platform.startswith('linux'):
            def _linux_focus_fix(e):
                if self.msg_entry and self.msg_entry.winfo_exists():
                    self.root.after(50, self.msg_entry.focus_set)
            self.root.bind('<FocusIn>', _linux_focus_fix)

        # ── Edge/corner resize handles for overrideredirect window ────────────
        GRIP = 6  # px — invisible hit area on each edge

        def _make_grip(cursor, resize_fn):
            """Create an invisible resize strip with the given cursor."""
            f = tk.Frame(self.root, bg=t['accent_4'], cursor=cursor)
            f.lift()
            f._rx = f._ry = f._rw = f._rh = None
            def _rs(e):
                f._rx = e.x_root; f._ry = e.y_root
                f._rw = self.root.winfo_width()
                f._rh = self.root.winfo_height()
                f._ox = self.root.winfo_x()
                f._oy = self.root.winfo_y()
            def _rm(e):
                if f._rx is None: return
                dx = e.x_root - f._rx
                dy = e.y_root - f._ry
                resize_fn(f, dx, dy)
            f.bind('<Button-1>', _rs)
            f.bind('<B1-Motion>', _rm)
            f.bind('<ButtonRelease-1>', lambda e: setattr(f, '_rx', None))
            return f

        def _resize_right(f, dx, dy):
            nw = max(800, f._rw + dx)
            self.root.geometry(f"{nw}x{f._rh}+{f._ox}+{f._oy}")
        def _resize_bottom(f, dx, dy):
            nh = max(500, f._rh + dy)
            self.root.geometry(f"{f._rw}x{nh}+{f._ox}+{f._oy}")
        def _resize_left(f, dx, dy):
            nw = max(800, f._rw - dx)
            nx = f._ox + (f._rw - nw)
            self.root.geometry(f"{nw}x{f._rh}+{nx}+{f._oy}")
        def _resize_top(f, dx, dy):
            pass  # top resize disabled — titlebar is the drag handle
        def _resize_se(f, dx, dy):
            nw = max(800, f._rw + dx); nh = max(500, f._rh + dy)
            self.root.geometry(f"{nw}x{nh}+{f._ox}+{f._oy}")
        def _resize_sw(f, dx, dy):
            nw = max(800, f._rw - dx); nh = max(500, f._rh + dy)
            nx = f._ox + (f._rw - nw)
            self.root.geometry(f"{nw}x{nh}+{nx}+{f._oy}")


        # Place grips — corners first (they sit on top of edges)
        TB = 36  # titlebar height — grips start below it
        r  = _make_grip('right_side',  _resize_right);  r.place(relx=1, rely=0, x=-GRIP, y=TB, width=GRIP, relheight=1, height=-(TB+GRIP))
        b  = _make_grip('bottom_side', _resize_bottom); b.place(relx=0, rely=1, x=GRIP, y=-GRIP, relwidth=1, width=-GRIP*2, height=GRIP)
        l  = _make_grip('left_side',   _resize_left);   l.place(x=0, y=TB, width=GRIP, relheight=1, height=-(TB+GRIP))
        # top resize grip intentionally omitted — titlebar serves as the top edge
        se = _make_grip('bottom_right_corner', _resize_se); se.place(relx=1, rely=1, x=-GRIP, y=-GRIP, width=GRIP, height=GRIP)
        sw = _make_grip('bottom_left_corner',  _resize_sw); sw.place(x=0, rely=1, y=-GRIP, width=GRIP, height=GRIP)

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
                                 state=tk.DISABLED, font=('Segoe UI', t['chat_font_size']),
                                 relief=tk.FLAT, padx=15, pady=15, spacing3=5)
        self.chat_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        # Disable Tkinter's built-in edge-proximity auto-scroll on mouse motion
        self.chat_text.bind('<Motion>', lambda e: 'break')

        scrollbar = make_scrollbar(chat_container, t, command=self.chat_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_text.config(yscrollcommand=scrollbar.set)

        # Sparkle lore-book button — tiny, bottom-right corner of the whole window
        # Sparkle lore-book button — tiny Canvas so we can clip the right edge
        # by making the canvas 2px narrower than the emoji (right side clips naturally)
        self._sparkle_btn = tk.Canvas(self.root, width=14, height=16,
                                      bg=t['glass_bg'], highlightthickness=0,
                                      cursor='hand2')
        self._sparkle_btn.create_text(0, 8, text="✨", anchor='w',
                                      font=('Segoe UI', 8),
                                      fill=t['accent_4'], tags='icon')
        self._sparkle_btn.place(relx=1.0, rely=1.0, x=-2, y=-4, anchor='se')
        self._sparkle_btn.place(relx=1.0, rely=1.0, x=-4, y=-4, anchor='se')
        self._sparkle_btn.bind('<Button-1>', lambda e: self._open_lore_book())
        self._sparkle_btn.bind('<Enter>',  lambda e: self._sparkle_btn.itemconfig('icon', fill=t['accent_1']))
        self._sparkle_btn.bind('<Leave>',  lambda e: self._sparkle_btn.itemconfig('icon', fill=t['accent_4']))
        self.root.after(100, lambda: tk.Misc.lift(self._sparkle_btn))

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
        om_fg  = t['voice_active_fg'] if self.open_mic_active else t['voice_idle_fg']
        om_txt = "🔴 MIC ON" if self.open_mic_active else "🎙 OPEN MIC"
        self.open_mic_btn = tk.Button(voice_inner, text=om_txt,
                                      bg=om_bg, fg=om_fg,
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

        # World lore panel — collapsed by default, sits below the userlist
        self._build_world_panel(right_frame)
        canvas.configure(yscrollcommand=scrollbar_users.set)
        self.user_list_frame.bind('<Configure>',
                                  lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind('<Configure>',
                    lambda e: canvas.itemconfig(canvas_window, width=e.width))

    def _build_world_panel(self, parent):
        """Collapsible world lore panel — sits at the bottom of the right sidebar."""
        t = self.theme
        self._world_panel_frame = tk.Frame(parent, bg=t['userlist_bg'])
        self._world_panel_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=(0, 10))
        self._world_panel_visible = False

        header = tk.Frame(self._world_panel_frame, bg=t['glass_accent'],
                          highlightthickness=1, highlightbackground=t['accent_4'])
        header.pack(fill=tk.X)

        # Left: toggle label
        self._world_toggle_label = tk.Label(
            header, text="✦  THE WORLD  ▸",
            bg=t['glass_accent'], fg=t['accent_4'],
            font=('Segoe UI', 7, 'bold'), anchor='w', padx=8, pady=4, cursor='hand2')
        self._world_toggle_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._world_toggle_label.bind('<Button-1>', lambda e: self._toggle_world_panel())
        header.bind('<Button-1>', lambda e: self._toggle_world_panel())

        # Scrollable wrapper for world lore
        self._world_lore_scroll_canvas = tk.Canvas(
            self._world_panel_frame, bg=t['glass_accent'],
            highlightthickness=0, height=220)
        self._world_lore_scrollbar = make_scrollbar(
            self._world_panel_frame, t, orient=tk.VERTICAL,
            command=self._world_lore_scroll_canvas.yview)
        self._world_lore_frame = tk.Frame(
            self._world_lore_scroll_canvas, bg=t['glass_accent'])
        self._world_lore_canvas_window = self._world_lore_scroll_canvas.create_window(
            (0, 0), window=self._world_lore_frame, anchor='nw')
        self._world_lore_scroll_canvas.configure(
            yscrollcommand=self._world_lore_scrollbar.set)
        self._world_lore_frame.bind('<Configure>', lambda e: (
            self._world_lore_scroll_canvas.configure(
                scrollregion=self._world_lore_scroll_canvas.bbox('all')),
            self._world_lore_scroll_canvas.itemconfig(
                self._world_lore_canvas_window,
                width=self._world_lore_scroll_canvas.winfo_width())))
        self._world_lore_scroll_canvas.bind('<Configure>', lambda e:
            self._world_lore_scroll_canvas.itemconfig(
                self._world_lore_canvas_window, width=e.width))
        def _world_scroll(event):
            if self._world_lore_scroll_canvas.winfo_exists():
                self._world_lore_scroll_canvas.yview_scroll(
                    int(-1*(event.delta/120)), 'units')
        self._world_lore_scroll_canvas.bind('<MouseWheel>', _world_scroll)
        self._world_lore_frame.bind('<MouseWheel>', _world_scroll)

    def _toggle_world_panel(self):
        if self._world_panel_visible:
            self._world_lore_scroll_canvas.pack_forget()
            self._world_lore_scrollbar.pack_forget()
            self._world_toggle_label.config(text="✦  THE WORLD  ▸")
            self._world_panel_visible = False
        else:
            self._world_lore_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            self._world_lore_scroll_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            self._world_toggle_label.config(text="✦  THE WORLD  ▾")
            self._world_panel_visible = True
            self._refresh_world_panel()

    def _open_lore_book(self):
        if not self._world_summary:
            return
        dialog = LoreBookDialog(self.root, self.theme, self._world_summary,
                                self._world_identities.get(self.username, {}))
        self._track_dialog(dialog)

    def _refresh_world_panel(self):
        """Populate the world lore panel with current summary."""
        if not hasattr(self, '_world_lore_frame') or not self._world_panel_visible:
            return
        t = self.theme
        for w in self._world_lore_frame.winfo_children():
            w.destroy()

        summary = self._world_summary
        if not summary:
            tk.Label(self._world_lore_frame,
                     text="Expansion Worlds not enabled on this server.",
                     bg=t['glass_accent'], fg=t['accent_4'],
                     font=('Segoe UI', 8), wraplength=160, padx=8, pady=6,
                     justify='left').pack(fill=tk.X)
            return

        def lbl(text, color=None, bold=False, italic=False, pady=2, wrap=160):
            font = ('Segoe UI', 7, ('bold italic' if bold and italic else 'bold' if bold else 'italic' if italic else 'normal'))
            tk.Label(self._world_lore_frame, text=text,
                     bg=t['glass_accent'], fg=color or t['accent_4'],
                     font=font, wraplength=wrap, padx=8, pady=pady,
                     justify='left', anchor='w').pack(fill=tk.X)

        def sep():
            tk.Frame(self._world_lore_frame, bg=t['accent_4'], height=1).pack(fill=tk.X, padx=8, pady=3)

        souls       = summary.get('total_souls', 0)
        events      = summary.get('total_events', 0)
        bonds       = summary.get('total_bonds', 0)
        choir_count = summary.get('choir_count', 0)
        age         = summary.get('world_age', '')
        season      = summary.get('season', '')
        soul_counts = summary.get('soul_counts', {})

        # ── Season & age ──────────────────────────────────────────────────────
        if season:
            lbl(season, color=t.get('accent_1', '#00ff88'), bold=True, pady=6)
        if age:
            lbl(age, italic=True, pady=1)

        # Soul count line with soul type breakdown
        soul_line = f"{souls} souls  ·  {bonds} bonds  ·  {events} events"
        if soul_counts.get('seraph') or soul_counts.get('daemon'):
            parts = []
            if soul_counts.get('seraph'): parts.append(f"{soul_counts['seraph']} seraph")
            if soul_counts.get('daemon'): parts.append(f"{soul_counts['daemon']} daemon")
            soul_line += f"  ·  {', '.join(parts)}"
        lbl(soul_line, pady=3)

        if choir_count:
            lbl(f"The Choir has convened {choir_count} time{'s' if choir_count > 1 else ''}.", italic=True, pady=1)

        sep()

        # ── Recent lore ───────────────────────────────────────────────────────
        for line in summary.get('recent_lore', []):
            lbl(line, color=t['fg_color'], italic=True, pady=2)

        # ── Ghost tales (if any) ──────────────────────────────────────────────
        ghost_tales = summary.get('ghost_tales', [])
        if ghost_tales:
            sep()
            lbl("— from the ghost records —", italic=True, pady=1)
            for tale in ghost_tales:
                lbl(tale, color=t.get('accent_2', '#cc4444'), italic=True, pady=2)

        # ── Regional legend (if any) ──────────────────────────────────────────
        legend = summary.get('legend')
        if legend:
            sep()
            lbl("— a local legend —", italic=True, pady=1)
            lbl(legend, color=t.get('accent_4', '#888888'), italic=True, pady=2)

        # ── Own identity ──────────────────────────────────────────────────────
        own = self._world_identities.get(self.username)
        if own:
            sep()
            soul = own.get('soul_type', 'mortal')
            soul_label = {'seraph': '✦ Seraph', 'daemon': '⬡ Daemon', 'mortal': '· Mortal'}.get(soul, soul)
            lbl(soul_label, color=t.get('accent_1', '#00ff88'), bold=True, pady=1)
            lbl(own.get('title', ''), color=t.get('accent_1', '#00ff88'), bold=True, pady=1)
            lbl(own.get('origin', ''), pady=1)
            if own.get('faction'):
                lbl(own['faction'], italic=True, pady=1)
            if own.get('trait'):
                lbl(f'"{own["trait"]}"', italic=True, color=t['fg_color'], pady=2)


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

    def _track_dialog(self, win):
        """Register a non-modal dialog so it gets lifted on window restore."""
        self._child_windows.append(win)
        def _on_destroy(e=None):
            try: self._child_windows.remove(win)
            except ValueError: pass
        win.bind('<Destroy>', _on_destroy)

    def _lift_children(self):
        """Bring all tracked child dialogs above the main window."""
        dead = []
        for w in list(self._child_windows):
            try:
                if w.winfo_exists():
                    w.deiconify()
                    w.lift()
                    w.focus_force()
                else:
                    dead.append(w)
            except Exception:
                dead.append(w)
        for w in dead:
            try: self._child_windows.remove(w)
            except ValueError: pass

    def show_about(self):
        dlg = AboutDialog(self.root, self.theme, self.theme_name)
        self._track_dialog(dlg)
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
            # Drain all complete messages first, then check size
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if not line.strip(): continue
                try: msg = json.loads(line)
                except json.JSONDecodeError: continue
                self.root.after(0, lambda m=msg: self.handle_tcp_message(m))
            # Only check overflow after draining — large history arrives in
            # multiple chunks and may briefly exceed the limit mid-message
            if len(buffer) > MAX_TCP_BUFFER:
                print("TCP buffer overflow — disconnecting"); break
            try:
                data = self.tcp_sock.recv(8192).decode('utf-8', errors='replace')
                if not data: break
                buffer += data
            except ssl.SSLError: break
            except OSError: break
            except Exception: break
        if self.running:
            self.root.after(0, self.connection_lost)

    def _heartbeat_loop(self):
        """Send a ping to the server every 5 minutes. Silent — no UI noise."""
        import time
        while self.running:
            time.sleep(300)
            if not self.running:
                break
            try:
                self.tcp_sock.send((json.dumps({'type': 'ping'}) + '\n').encode())
            except Exception:
                break

    def connection_lost(self):
        """Show a themed disconnect dialog then restart the app."""
        if self._closing:
            return
        self._closing = True
        self.running  = False

        for sock in [getattr(self, 'tcp_sock', None), getattr(self, 'udp_sock', None)]:
            try:
                if sock: sock.close()
            except: pass

        t = self.theme

        dlg = tk.Toplevel(self.root)
        dlg.overrideredirect(True)
        dlg.configure(bg=t.get('titlebar_sep', t['accent_1']))
        dlg.resizable(False, False)
        dlg.geometry("420x240")
        dlg.update_idletasks()
        sw = dlg.winfo_screenwidth()
        sh = dlg.winfo_screenheight()
        dlg.geometry(f"420x240+{sw//2-210}+{sh//2-120}")
        dlg.lift()
        dlg.attributes('-topmost', True)
        apply_window_icon(dlg)
        dlg.grab_set()

        inner = tk.Frame(dlg, bg=t['glass_bg'])
        inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        build_themed_titlebar(inner, t, "Haven — Disconnected",
                              on_close=lambda: _restart())

        tk.Label(inner, text="⚠  Haven Disconnected",
                 bg=t['glass_bg'], fg=t['accent_2'],
                 font=('Segoe UI', 13, 'bold')).pack(pady=(18, 6))
        tk.Label(inner,
                 text="Connection to the server was lost.\nClick OK to restart Haven.",
                 bg=t['glass_bg'], fg=t['fg_color'],
                 font=('Segoe UI', 10), justify='center').pack(pady=(0, 16))

        def _restart():
            try: dlg.destroy()
            except: pass
            try: self.root.destroy()
            except: pass
            import subprocess
            subprocess.Popen(get_exe_path())

        tk.Button(inner, text="OK — Restart", bg=t['accent_1'], fg=t['send_btn_fg'],
                  font=('Segoe UI', 11, 'bold'), relief=tk.FLAT,
                  command=_restart, padx=30, pady=10, cursor='hand2').pack()

    def handle_tcp_message(self, msg):
        try:
            self._handle_tcp_message_inner(msg)
        except Exception as e:
            print(f"[WARN] Error handling message: {e}")

    def _handle_tcp_message_inner(self, msg):
        t = self.theme
        if msg['type'] == 'ping':
            try:
                self.tcp_sock.send((json.dumps({'type': 'pong'}) + '\n').encode())
            except: pass
            return
        if msg['type'] == 'pong':
            return
        if msg['type'] == 'auth_ok':
            if 'user_color' in msg:
                self.server_assigned_color = msg['user_color']
                self.name_color = msg['user_color']; self.save_config()
            self.display_system_message("✓ Connected to server", local_only=True)
            play_sound('self_join', self.sounds_enabled, sfx_vol=getattr(self,'sfx_volume',100))
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
                    print("[WARN] Could not decrypt a message — dropped")
                    return
            elif self.session_crypto:
                # Session is active but message arrived unencrypted — refuse it.
                # This prevents downgrade injection attacks.
                print("[WARN] Dropped unencrypted message (encryption required)")
                return
            else:
                plaintext = msg.get('text', '')
            self.display_message(msg['user'], plaintext)
            play_sound('msg_received', self.sounds_enabled, sfx_vol=getattr(self,'sfx_volume',100))
        elif msg['type'] == 'chat_history':
            # Clear in-memory log before loading authoritative server history
            self._msg_log.clear()
            if self.chat_text:
                self.chat_text.config(state=tk.NORMAL)
                self.chat_text.delete('1.0', tk.END)
                self.chat_text.config(state=tk.DISABLED)
            skipped = 0
            for chat_msg in msg['history']:
                user = chat_msg.get('user', '')
                timestamp    = chat_msg.get('timestamp')
                stored_color = chat_msg.get('color')

                if chat_msg.get('encrypted'):
                    # Server now sends all history encrypted with our session key
                    if self.session_crypto and HAVEN_CRYPTO:
                        text = self.session_crypto.decrypt_chat(chat_msg.get('ct', ''))
                        if text is None:
                            # Decryption failed — skip rather than show blank/garbage
                            skipped += 1
                            print(f"[WARN] History decrypt failed for entry from {user} — skipped")
                            continue
                    else:
                        # No session crypto — cannot decrypt, skip entirely
                        skipped += 1
                        continue
                else:
                    # Unencrypted entry: old server or pre-migration plaintext history.
                    # Accept it so upgrades don't wipe visible history on first connect.
                    text = chat_msg.get('text', '')
                    if not text:
                        continue

                if user in ('System', 'World'):
                    self.display_message(user, text, timestamp=timestamp,
                                         color=t['system_msg_color'], from_history=True)
                else:
                    if user not in self.user_colors and stored_color:
                        self.user_colors[user] = stored_color
                    display_color = stored_color or self.user_colors.get(user, t['accent_2'])
                    align = 'right' if user == self.username else 'left'
                    self.display_message(user, text, align=align,
                                         timestamp=timestamp, color=display_color, from_history=True)

            if skipped:
                print(f"[INFO] {skipped} history entries could not be decrypted and were skipped")
        elif msg['type'] == 'userlist_full':
            self.update_userlist_with_colors(msg['users'])
        elif msg['type'] == 'userlist':
            self.update_userlist_with_colors([{'username': u, 'color': t['accent_2']} for u in msg['users']])
        elif msg['type'] == 'user_color_changed':
            self.update_user_color(msg['username'], msg['color'])
        elif msg['type'] == 'voice_start':
            self.set_user_voice_active(msg['user'], True)
            if msg['user'] == self.username:
                play_sound('ptt_start', self.sounds_enabled, sfx_vol=getattr(self,'sfx_volume',100))
        elif msg['type'] == 'voice_stop':
            self.set_user_voice_active(msg['user'], False)
            if msg['user'] == self.username:
                play_sound('ptt_stop', self.sounds_enabled, sfx_vol=getattr(self,'sfx_volume',100))
        elif msg['type'] == 'username_changed':
            self.display_system_message(f"✓ Username changed to {msg['new_username']}", local_only=True)
            old_username = self.username; self.username = msg['new_username']
            if 'user_color' in msg:
                self.name_color = msg['user_color']; self.server_assigned_color = msg['user_color']
            self.save_config()
            # Remove old user card completely (label + sigil canvas)
            if old_username in self.speaker_labels:
                try:
                    # Destroy the whole card frame not just the label
                    self.speaker_labels[old_username].master.master.destroy()
                except Exception:
                    try: self.speaker_labels[old_username].destroy()
                    except: pass
                del self.speaker_labels[old_username]
            if old_username in self._sigil_canvases:
                del self._sigil_canvases[old_username]
            if old_username in self.user_colors:
                self.user_colors[self.username] = self.user_colors.pop(old_username)
            # Add fresh card with new name — sigil redraws from new username seed
            self.add_user_to_list(self.username, self.name_color, has_voice=True)
        elif msg['type'] == 'world_identity':
            self._expansion_enabled = True
            identity = msg.get('identity', {})
            summary  = msg.get('summary', {})
            username = self.username
            if identity:
                self._world_identities[username] = identity
            if summary:
                self._world_summary = summary
            self.root.after(0, lambda: self.update_userlist_with_colors(self._online_users))
            self.root.after(0, self._refresh_world_panel)

        elif msg['type'] == 'world_update':
            # Server pushed a fresh summary (silent event — no chat message)
            summary = msg.get('summary', {})
            if summary:
                self._world_summary = summary
            self.root.after(0, self._refresh_world_panel)

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
                packet, addr = self.udp_sock.recvfrom(8192)

                # Strip sender header: [len(1)] [username(N)] [encrypted audio]
                sender = None
                if len(packet) >= 1:
                    name_len = packet[0]
                    if len(packet) >= 1 + name_len:
                        try:
                            sender = packet[1:1 + name_len].decode('utf-8')
                        except Exception:
                            sender = None
                        data = packet[1 + name_len:]
                    else:
                        data = packet  # old server — no header
                else:
                    data = packet

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

                # Apply volumes: global output × per-user override
                master = self.audio_settings.get('output_volume', 100) / 100
                per_user = self.user_volumes.get(sender, 100) / 100 if sender else 1.0
                volume = master * per_user
                if volume != 1.0:
                    try:
                        import numpy as np
                        audio_data = np.frombuffer(data, dtype=np.int16)
                        data = (audio_data * volume).clip(-32768, 32767).astype(np.int16).tobytes()
                    except ImportError: pass

                self.stream_out.write(data)
            except OSError: break
            except Exception as e: print(f"Error in receive_udp: {e}"); break

    def _chat_insert(self, index, text, *tags):
        """Safe wrapper around chat_text.insert — catches Tcl encoding errors."""
        if not self.chat_text:
            return
        safe = self._safe_text(str(text))
        try:
            self.chat_text.insert(index, safe, *tags)
        except tk.TclError as e:
            print(f"[WARN] Could not insert text into chat: {e}")
            try:
                self.chat_text.insert(index, '[?]', *tags)
            except Exception:
                pass

    @staticmethod
    def _safe_text(text):
        """
        Sanitise text for tkinter's Text widget on Windows.
        Tcl/Tk uses UTF-8 internally but chokes on:
          - Lone surrogates (U+D800–U+DFFF)
          - Null bytes (U+0000)
          - Characters Tcl can't encode to its internal cesu-8 variant
        We normalise by round-tripping through UTF-8 with replacement.
        """
        try:
            # Round-trip through UTF-8 — strips lone surrogates, normalises
            safe = text.encode('utf-8', 'replace').decode('utf-8', 'replace')
            # Remove null bytes which Tcl treats as string terminators
            safe = safe.replace('\x00', '')
            return safe
        except Exception:
            return '[message could not be displayed]' 

    def send_chat(self, event=None):
        # Throttle: ignore key-repeat events (held Return key fires many times/sec)
        import time as _time; now = _time.monotonic()
        if now - self._last_send_time < 0.1:
            return
        self._last_send_time = now
        text = self.msg_entry.get().strip()
        if text and self.authenticated:
            try:
                if self.session_crypto and HAVEN_CRYPTO:
                    ct = self.session_crypto.encrypt_chat(text)
                    msg = {'type': 'chat', 'encrypted': True, 'ct': ct}
                else:
                    msg = {'type': 'chat', 'text': text}
                self.tcp_sock.send((json.dumps(msg) + '\n').encode('utf-8'))
                self.msg_entry.delete(0, tk.END)
                self.display_message(self.username, text, align='right')
                play_sound('msg_sent', self.sounds_enabled, sfx_vol=getattr(self,'sfx_volume',100))
            except UnicodeEncodeError:
                messagebox.showerror("Error", "Message contains unsupported characters")
            except Exception as _e:
                import traceback; traceback.print_exc()
                messagebox.showerror("Error", f"Failed to send message: {_e}")

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
                self.open_mic_btn.config(text="🎙 OPEN MIC", bg=t['voice_idle_bg'], fg=t['voice_idle_fg'])
            self.voice_active = False
            if self.voice_btn:
                self.voice_btn.config(bg=t['voice_idle_bg'], fg=t['voice_idle_fg'],
                                      text=self.voice_btn_text)
            try: self.tcp_sock.send((json.dumps({'type': 'voice_stop'}) + '\n').encode())
            except: pass
        else:
            self.open_mic_active = True
            if self.open_mic_btn:
                self.open_mic_btn.config(text="🔴 MIC ON", bg=t['voice_active_bg'], fg=t['voice_active_fg'])
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
        if timestamp is None: timestamp = datetime.datetime.now().strftime('%H:%M')
        text = self._safe_text(text)   # strip lone surrogates that crash tkinter

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
            self._chat_insert(tk.END, f'{text}  ', tag_rt)
            self._chat_insert(tk.END, f'[{timestamp} - {user}]\n', tag_rm)
            self.chat_text.tag_config(tag_rt, justify='right',
                                      foreground=self.name_color, font=MSG_FONT)
            self.chat_text.tag_config(tag_rm, justify='right',
                                      foreground=t['accent_4'],
                                      font=TS_FONT)
        else:
            self._chat_insert(tk.END, f'[{timestamp}] ', 'ts')
            self.chat_text.tag_config('ts', foreground=t['accent_4'], font=TS_FONT)

            if user == 'World':
                pass  # World lore is panel-only — silently drop from chat
            elif user == 'System':
                self._chat_insert(tk.END, f'System: ', 'sys_name')
                self.chat_text.tag_config('sys_name', foreground=t['system_msg_color'],
                                          font=(t['chat_font'], t['chat_font_size'], 'bold'))
                self._chat_insert(tk.END, f'{text}\n', 'sys_body')
                self.chat_text.tag_config('sys_body', foreground=t['system_msg_color'],
                                          font=(t['chat_font'], t['chat_font_size'], 'italic'))
            else:
                user_color = color or self.user_colors.get(user, t['accent_2'])
                tag_name   = f'user_{hashlib.md5(user.encode()).hexdigest()[:8]}'
                body_tag   = f'body_{tag_name}'  # per-user body tag avoids cross-user clobber
                self._chat_insert(tk.END, f'{user}: ', tag_name)
                self.chat_text.tag_config(tag_name, foreground=user_color, font=MSG_FONT_BOLD)
                self._chat_insert(tk.END, f'{text}\n', body_tag)
                self.chat_text.tag_config(body_tag, foreground=t['chat_fg'], font=MSG_FONT)

        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.see(tk.END)

    def _render_sys(self, text, timestamp=None):
        """Render a system/status line."""
        t = self.theme
        if not self.chat_text: return
        if timestamp is None: timestamp = datetime.datetime.now().strftime('%H:%M')
        self.chat_text.config(state=tk.NORMAL)
        self._chat_insert(tk.END, f'[{timestamp}] ', 'sys_ts')
        self._chat_insert(tk.END, f'{text}\n', 'sys_line')
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
        self._chat_insert(tk.END, f'[{timestamp}] ', 'ts')
        self.chat_text.tag_config('ts', foreground=t['accent_4'], font=TS_FONT)
        self._chat_insert(tk.END, f'{user}:\n', tag_name)
        self.chat_text.tag_config(tag_name, foreground=uc, font=MSG_BOLD)
        return uc

    def _place_mark(self, mark_name):
        """Place a named mark at END for later async insertion."""
        self._chat_insert(tk.END, '\u200b')
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
        self._chat_insert(tk.END, f'  \U0001f517 {url}\n', link_tag)
        self.chat_text.tag_config(link_tag, foreground=t['accent_1'],
                                  font=(t['chat_font'], t['chat_font_size'], 'underline'),
                                  lmargin1=16, lmargin2=16)
        self.chat_text.tag_bind(link_tag, '<Button-1>', lambda e, u=url: webbrowser.open(u))
        self.chat_text.tag_bind(link_tag, '<Enter>', lambda e: self.chat_text.config(cursor='hand2'))
        self.chat_text.tag_bind(link_tag, '<Leave>', lambda e: self.chat_text.config(cursor=''))

        self._place_mark(mark)
        self._chat_insert(tk.END, '\n')
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
        self._chat_insert(tk.END, f'  \U0001f517 {url}\n', link_tag)
        self.chat_text.tag_config(link_tag, foreground=t['accent_1'],
                                  font=(t['chat_font'], t['chat_font_size'], 'underline'),
                                  lmargin1=16, lmargin2=16)
        self.chat_text.tag_bind(link_tag, '<Button-1>', lambda e, u=url: webbrowser.open(u))
        self.chat_text.tag_bind(link_tag, '<Enter>', lambda e: self.chat_text.config(cursor='hand2'))
        self.chat_text.tag_bind(link_tag, '<Leave>', lambda e: self.chat_text.config(cursor=''))

        self._place_mark(mark)
        self._chat_insert(tk.END, '\n')
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
            self._chat_insert(mark, '\n')
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
                self._chat_insert(mark, '\n')
                self.chat_text.config(state=tk.DISABLED)
                self.chat_text.see(tk.END)
            except tk.TclError:
                pass

    # ── Public display methods ────────────────────────────────────

    def display_message(self, user, text, align='left', timestamp=None, color=None, from_history=False):
        if timestamp is None: timestamp = datetime.datetime.now().strftime('%H:%M')

        # System message visibility: hide from non-admins
        if user == 'System':
            is_admin = getattr(self, 'username', '').startswith('admin_')
            if not from_history:
                if ' has joined the chat' in text:
                    joining_user = text.replace(' has joined the chat', '').strip()
                    if joining_user != getattr(self, 'username', ''):
                        play_sound('user_join', self.sounds_enabled, sfx_vol=getattr(self,'sfx_volume',100))
                elif ' has left the chat' in text:
                    play_sound('user_leave', self.sounds_enabled, sfx_vol=getattr(self,'sfx_volume',100))
            if not is_admin:
                return  # hide all system messages from non-admins (sounds already fired above)

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
        if user != getattr(self, 'username', '') and not from_history:
            self._notify_tray_if_hidden(user, text)

    def _notify_tray_if_hidden(self, user, text):
        """Show a tray notification when the window is hidden and a new message arrives."""
        try:
            if self.root.state() == 'withdrawn' and TRAY_AVAILABLE and self.tray_icon:
                snippet = text[:60] + ('…' if len(text) > 60 else '')
                try:
                    self.tray_icon.notify(f'{user}: {snippet}', 'Haven — New Message')
                except Exception:
                    pass
        except Exception:
            pass

    def display_system_message(self, text, local_only=False):
        """Show a system message in chat.
        local_only=True bypasses the admin filter (for client-side status messages
        that are never stored server-side, e.g. sounds toggle, PTT key change).
        """
        if not self.chat_text: return
        is_admin = getattr(self, 'username', '').startswith('admin_')
        if not local_only and not is_admin:
            return  # non-admins don't see server system messages
        ts = datetime.datetime.now().strftime('%H:%M')
        self._msg_log.append({'type': 'system', 'text': text, 'timestamp': ts})
        self._render_sys(text, ts)

    def update_userlist_with_colors(self, users_with_colors):
        if not self.user_list_frame: return
        # Remember exactly who is online so theme rebuilds show the same list
        self._online_users = list(users_with_colors)
        for widget in self.user_list_frame.winfo_children():
            widget.destroy()
        self.speaker_labels.clear()
        self._sigil_canvases.clear()
        for user_data in users_with_colors:
            self.user_colors[user_data['username']] = user_data.get('color', self.theme['accent_2'])
        for user_data in users_with_colors:
            username = user_data['username']
            # has_voice=True if the client registered a UDP port (False for terminal clients)
            has_voice = user_data.get('has_voice', True)  # default True for legacy servers
            self.add_user_to_list(username, self.user_colors[username], has_voice=has_voice)
        if self.username not in self.user_colors:
            self.user_colors[self.username] = self.name_color

    def add_user_to_list(self, username, color, has_voice=True):
        t        = self.theme
        identity = self._world_identities.get(username)

        card = tk.Frame(self.user_list_frame, bg=t['userlist_card_bg'],
                        highlightthickness=1, highlightbackground=t['accent_4'])
        card.pack(fill=tk.X, pady=5)

        if identity and self._expansion_enabled:
            # ── Expansion card: sigil + name + title ──────────────────────
            inner = tk.Frame(card, bg=t['userlist_card_bg'])
            inner.pack(fill=tk.X, padx=8, pady=6)

            # Sigil — rendered from SVG as a PhotoImage via base64 PNG fallback
            # We draw the sigil on a small canvas using tkinter geometry
            sigil_canvas = tk.Canvas(inner, width=44, height=44,
                                     bg=t['userlist_card_bg'], highlightthickness=0)
            sigil_canvas.pack(side=tk.LEFT, padx=(0, 6))
            self._draw_sigil_on_canvas(sigil_canvas, username, color, size=44)
            if not has_voice:
                # Zalgo effect — ghost sigils tiled across the card
                # Shows they exist but aren't voice-present
                self._draw_zalgo_overlay(card, username, color)
            self._sigil_canvases[username] = (sigil_canvas, color)

            right = tk.Frame(inner, bg=t['userlist_card_bg'])
            right.pack(side=tk.LEFT, fill=tk.X, expand=True)

            label = tk.Label(right, text=username,
                             bg=t['userlist_card_bg'], fg=color,
                             font=('Segoe UI', 10), anchor='w')
            label.pack(fill=tk.X)

            title_text = identity.get('title', '')
            if title_text:
                tk.Label(right, text=title_text,
                         bg=t['userlist_card_bg'], fg=t['accent_4'],
                         font=('Segoe UI', 7), anchor='w').pack(fill=tk.X)

            # Tooltip on hover
            self._bind_world_tooltip(card, identity)
            self._bind_world_tooltip(inner, identity)
            self._bind_world_tooltip(label, identity)
        else:
            # ── Standard card ─────────────────────────────────────────────
            # Add a small "no-voice" indicator glyph when the user is terminal-only
            prefix = "◌ " if not has_voice else "● "
            label = tk.Label(card, text=f"{prefix}{username}",
                             bg=t['userlist_card_bg'], fg=color,
                             font=('Segoe UI', 10), anchor='w', padx=10, pady=8)
            label.pack(fill=tk.X)
            if not has_voice:
                self._draw_zalgo_overlay(card, username, color)

        self.speaker_labels[username] = label
        if username in self.active_speakers:
            self.set_user_voice_active(username, True)

    def _draw_sigil_on_canvas(self, canvas, username, color, size=28, rotation_offset=0, offset=None):
        """Draw a deterministic sigil on a tk.Canvas using pure tkinter geometry.
        offset=(x,y) shifts the drawing origin — used for zalgo tiling."""
        ox, oy = offset if offset else (0, 0)
        cx = ox + size / 2
        cy = oy + size / 2
        radius = size * 0.38

        def _rng_local(seed):
            h = int(hashlib.sha256(seed.encode()).hexdigest(), 16)
            return random.Random(h)

        r = _rng_local(f'sigil:{username}')
        shape_type = r.choice(['polygon', 'star', 'orbital', 'rune'])

        sw = max(1, int(size * 0.045 * 10) / 10)  # stroke width

        def pt(angle_deg, dist):
            a = math.radians(angle_deg - 90 + rotation_offset)
            return (cx + dist * math.cos(a), cy + dist * math.sin(a))

        def flat(points):
            return [coord for p in points for coord in p]

        if shape_type == 'polygon':
            sides    = r.randint(3, 7)
            rotation = r.uniform(0, 360 / sides)
            pts = [pt(rotation + i * 360 / sides, radius) for i in range(sides)]
            canvas.create_polygon(flat(pts), outline=color, fill='', width=sw)
            if r.random() > 0.4:
                inner_r    = radius * r.uniform(0.35, 0.6)
                inner_sides = r.choice([sides, 3, 4])
                inner_rot  = r.uniform(0, 360)
                ipts = [pt(inner_rot + i * 360 / inner_sides, inner_r) for i in range(inner_sides)]
                canvas.create_polygon(flat(ipts), outline=color, fill='', width=max(1, sw-1))
            if r.random() > 0.5:
                dot_r = size * 0.05
                canvas.create_oval(cx - dot_r, cy - dot_r, cx + dot_r, cy + dot_r,
                                   fill=color, outline='')

        elif shape_type == 'star':
            points  = r.randint(4, 7)
            outer_r = radius
            inner_r = radius * r.uniform(0.35, 0.55)
            rotation = r.uniform(0, 360 / points)
            star_pts = []
            for i in range(points * 2):
                angle = rotation + i * 180 / points
                dist  = outer_r if i % 2 == 0 else inner_r
                star_pts.append(pt(angle, dist))
            canvas.create_polygon(flat(star_pts), outline=color, fill='', width=sw)
            if r.random() > 0.5:
                dot_r = size * 0.07
                canvas.create_oval(cx - dot_r, cy - dot_r, cx + dot_r, cy + dot_r,
                                   fill=color, outline='')

        elif shape_type == 'orbital':
            num_rings = r.randint(2, 3)
            for i in range(num_rings):
                ring_r = radius * (0.4 + 0.6 * (i + 1) / num_rings) * 0.85
                canvas.create_oval(cx - ring_r, cy - ring_r, cx + ring_r, cy + ring_r,
                                   outline=color, fill='', width=max(1, sw - i))
            num_lines = r.randint(2, 4)
            for _ in range(num_lines):
                angle = r.uniform(0, math.pi)
                x1 = cx + radius * math.cos(angle)
                y1 = cy + radius * math.sin(angle)
                x2 = cx - radius * math.cos(angle)
                y2 = cy - radius * math.sin(angle)
                canvas.create_line(x1, y1, x2, y2, fill=color, width=max(1, sw - 1))

        elif shape_type == 'rune':
            num_points = r.randint(4, 7)
            angles = sorted(r.uniform(0, 360) for _ in range(num_points))
            dists  = [r.uniform(radius * 0.4, radius) for _ in range(num_points)]
            rune_pts = [pt(a, d) for a, d in zip(angles, dists)]
            for i in range(len(rune_pts) - 1):
                x1, y1 = rune_pts[i]
                x2, y2 = rune_pts[i + 1]
                canvas.create_line(x1, y1, x2, y2, fill=color, width=sw, capstyle='round')
            if r.random() > 0.4:
                x1, y1 = rune_pts[-1]
                x2, y2 = rune_pts[0]
                canvas.create_line(x1, y1, x2, y2, fill=color, width=sw, capstyle='round')
            dot_r = size * 0.05
            canvas.create_oval(rune_pts[0][0] - dot_r, rune_pts[0][1] - dot_r,
                               rune_pts[0][0] + dot_r, rune_pts[0][1] + dot_r,
                               fill=color, outline='')

    def _draw_zalgo_overlay(self, card, username, color):
        """
        Tile faded ghost-sigils across the user card to show a terminal/no-voice
        user. The sigil is recognisable but fragmented — 'lost in the sauce'.

        Strategy: place a canvas as the card background FIRST, then lift all
        existing children (text labels, sigil canvas) above it so they remain
        readable. The canvas is drawn at card-level via place() so it fills the
        whole card behind the packed widgets.
        """
        t = self.theme

        # Dim the color way down so it ghosts behind the text
        def _dim(hex_color, alpha=0.22):
            try:
                h = hex_color.lstrip('#')
                r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
                bg_h = t['userlist_card_bg'].lstrip('#')
                br, bg_c, bb = int(bg_h[0:2],16), int(bg_h[2:4],16), int(bg_h[4:6],16)
                nr = int(br + (r - br) * alpha)
                ng = int(bg_c + (g - bg_c) * alpha)
                nb = int(bb + (b - bb) * alpha)
                return f'#{nr:02x}{ng:02x}{nb:02x}'
            except Exception:
                return t.get('accent_4', '#444444')

        ghost_color = _dim(color, 0.22)

        def _do_draw(event=None):
            try:
                w = card.winfo_width()
                h = card.winfo_height()
                if w < 4 or h < 4:
                    card.after(50, _do_draw)
                    return

                # Create the overlay canvas with the card's own bg colour (safe, no blank bg)
                ov = tk.Canvas(card, bg=t['userlist_card_bg'], highlightthickness=0,
                               width=w, height=h)
                # Place it to fill the whole card — it goes under pack-managed widgets
                # by being placed at z-order bottom
                ov.place(x=0, y=0, relwidth=1, relheight=1)
                ov.lower()   # send behind all packed children

                # Tile small ghost sigils across the card
                tile = 18   # size of each ghost sigil
                gap  = 6    # gap between tiles
                step = tile + gap

                rng = random.Random(int(hashlib.sha256(f'zalgo:{username}'.encode()).hexdigest(), 16))

                for row_y in range(-tile, h + tile, step):
                    # Offset every other row for a staggered/chaotic feel
                    x_off = rng.randint(0, step) if (row_y // step) % 2 else 0
                    for col_x in range(-tile + x_off, w + tile, step):
                        # Slight random jitter
                        jx = col_x + rng.randint(-3, 3)
                        jy = row_y + rng.randint(-3, 3)
                        # Random rotation offset per tile
                        rot = rng.uniform(0, 360)
                        self._draw_sigil_on_canvas(
                            ov, username, ghost_color,
                            size=tile,
                            rotation_offset=rot,
                            offset=(jx, jy)
                        )

                # Lift all existing packed children above the overlay canvas
                for child in card.winfo_children():
                    if child is not ov:
                        try:
                            child.lift()
                        except Exception:
                            pass

            except Exception:
                pass

        card.bind('<Map>', _do_draw)
        card.after(80, _do_draw)   # fallback for already-visible cards

    # ── Sigil animation helpers ────────────────────────────────────────────────

    def _hex_to_rgb(self, color):
        h = color.lstrip('#')
        return int(h[0:2],16)/255, int(h[2:4],16)/255, int(h[4:6],16)/255

    def _boost_color(self, color, factor):
        try:
            r_v, g_v, b_v = self._hex_to_rgb(color)
            hh, ss, vv = colorsys.rgb_to_hsv(r_v, g_v, b_v)
            vv2 = min(1.0, vv * factor); ss2 = min(1.0, ss * 1.1)
            r2, g2, b2 = colorsys.hsv_to_rgb(hh, ss2, vv2)
            return f'#{int(r2*255):02x}{int(g2*255):02x}{int(b2*255):02x}'
        except Exception:
            return color

    def _color_with_alpha(self, color, alpha):
        """Blend color toward canvas bg for pseudo-transparency."""
        try:
            r_v, g_v, b_v = self._hex_to_rgb(color)
            bg = self.theme.get('userlist_card_bg', '#0a0a1a')
            br, bg2, bb = self._hex_to_rgb(bg)
            r2 = r_v * alpha + br * (1 - alpha)
            g2 = g_v * alpha + bg2 * (1 - alpha)
            b2 = b_v * alpha + bb * (1 - alpha)
            return f'#{int(r2*255):02x}{int(g2*255):02x}{int(b2*255):02x}'
        except Exception:
            return color

    def _glow_sigil(self, canvas, username, color, _phase=0):
        """
        Full sigil animation while user is speaking:
          - Sigil rotates continuously
          - Outward glowing rings emanate from center
          - 16ms tick (~60fps feel)
        """
        if not canvas.winfo_exists(): return
        if username not in self.active_speakers:
            # User stopped — play sparkle burst then restore static sigil
            self._sparkle_sigil(canvas, username, color, _frames=0)
            return

        size   = 44
        cx, cy = size / 2, size / 2
        phase  = _phase  # unbounded, wraps naturally in trig

        canvas.delete('all')

        # ── Outward glow rings — start inside sigil boundary, expand outward ──
        for ring_offset in [0, 15]:
            ring_phase = (phase + ring_offset) % 30
            # Radius grows from 14 → 21 over 30 frames (stays within 44px canvas)
            r_min, r_max = 14, 21
            ring_r  = r_min + (r_max - r_min) * (ring_phase / 30)
            # Alpha fades from 0.55 → 0 as ring expands
            ring_alpha = 0.55 * (1.0 - ring_phase / 30)
            ring_color = self._color_with_alpha(color, ring_alpha)
            thickness = max(1, int(3 * (1.0 - ring_phase / 30)))
            canvas.create_oval(cx - ring_r, cy - ring_r, cx + ring_r, cy + ring_r,
                               outline=ring_color, width=thickness)

        # ── Rotating sigil ────────────────────────────────────────────────────
        speak_color = self._boost_color(color, 1.3)
        rotation_deg = (phase * 3) % 360  # 3 deg/frame = ~1 full rotation/2 sec
        self._draw_sigil_on_canvas(canvas, username, speak_color, size=size,
                                   rotation_offset=rotation_deg)

        canvas.after(16, lambda: self._glow_sigil(canvas, username, color, _phase + 1))

    def _sparkle_sigil(self, canvas, username, color, _frames=0):
        """
        Post-voice sparkle burst: 8 dots fly outward from center and fade over ~500ms.
        """
        if not canvas.winfo_exists(): return
        if username in self.active_speakers: return  # started speaking again

        TOTAL_FRAMES = 20
        size = 44; cx = size / 2; cy = size / 2

        canvas.delete('all')

        if _frames < TOTAL_FRAMES:
            progress = _frames / TOTAL_FRAMES  # 0 → 1
            # Restore base sigil underneath
            self._draw_sigil_on_canvas(canvas, username, color, size=size)
            # 8 spark dots flying outward
            n_sparks = 8
            for i in range(n_sparks):
                angle = math.radians(i * 360 / n_sparks)
                dist  = 6 + 15 * progress   # 6 → 21 px from center (fits 44px canvas)
                sx    = cx + dist * math.cos(angle)
                sy    = cy + dist * math.sin(angle)
                alpha = 1.0 - progress       # fade out
                spark_color = self._color_with_alpha(color, alpha)
                dot_r = max(1.0, 2.5 * (1.0 - progress))
                canvas.create_oval(sx - dot_r, sy - dot_r, sx + dot_r, sy + dot_r,
                                   fill=spark_color, outline='')
            canvas.after(25, lambda: self._sparkle_sigil(canvas, username, color, _frames + 1))
        else:
            # Sparkle done — restore clean static sigil
            self._draw_sigil_on_canvas(canvas, username, color, size=size)

    def _bind_world_tooltip(self, widget, identity):
        """Bind hover tooltip showing world title + origin + trait."""
        tip_win = [None]

        def show(e):
            if tip_win[0]:
                return
            t = self.theme
            title   = identity.get('title', '')
            origin  = identity.get('origin', '')
            trait   = identity.get('trait', '')
            faction = identity.get('faction', '')
            text    = f"{title}\n{origin}"
            if faction: text += f"\n{faction}"
            text   += f'\n\n"{trait}"'

            win = tk.Toplevel(self.root)
            win.overrideredirect(True)
            win.attributes('-topmost', True)
            win.configure(bg=t['glass_accent'])
            lbl = tk.Label(win, text=text, bg=t['glass_accent'],
                           fg=t['fg_color'], font=('Segoe UI', 8),
                           padx=10, pady=8, justify='left',
                           wraplength=180)
            lbl.pack()
            # Position near cursor
            x = e.x_root + 12
            y = e.y_root + 8
            win.geometry(f'+{x}+{y}')
            tip_win[0] = win

        def hide(e):
            if tip_win[0]:
                tip_win[0].destroy()
                tip_win[0] = None

        widget.bind('<Enter>', show)
        widget.bind('<Leave>', hide)

    def update_user_color(self, username, new_color):
        self.user_colors[username] = new_color
        if username in self.speaker_labels:
            prefix = "🔴" if username in self.active_speakers else "●"
            self.speaker_labels[username].config(fg=new_color, text=f"{prefix} {username}")
        if username == self.username:
            self.name_color = new_color; self.server_assigned_color = new_color
            self.save_config()

    def set_user_voice_active(self, username, active):
        if active: self.active_speakers.add(username)
        else:      self.active_speakers.discard(username)
        user_color = self.user_colors.get(username, self.theme['fg_color'])

        # Glow/unglow sigil canvas if expansion worlds on
        if username in self._sigil_canvases and self._expansion_enabled:
            canvas, base_color = self._sigil_canvases[username]
            if canvas.winfo_exists():
                if active:
                    self._glow_sigil(canvas, username, user_color)
                else:
                    # _glow_sigil checks active_speakers and triggers sparkle itself
                    # but if it wasn't running (e.g. rejoined), trigger sparkle directly
                    self._sparkle_sigil(canvas, username, user_color, _frames=0)

        if username in self.speaker_labels:
            label = self.speaker_labels[username]
            if active:
                if not self._expansion_enabled:
                    label.config(fg=user_color, font=('Segoe UI', 10, 'bold'), text=f"🔴 {username}")
                else:
                    label.config(fg=user_color, font=('Segoe UI', 10, 'bold'))
                self.pulse_speaker(label, username)
            else:
                if not self._expansion_enabled:
                    label.config(fg=user_color, font=('Segoe UI', 10), text=f"● {username}")
                else:
                    label.config(fg=user_color, font=('Segoe UI', 10))

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
            ("Sound Settings",          self.open_sound_settings),
            None,
            ("Clear Saved Password",   self.clear_saved_password),
            ("Change Server",          self.change_server),
            None,
            ("Check for Updates",     lambda: check_for_updates(self.root, self.theme, silent=False)),
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

    def open_sound_settings(self):
        known_users = [u for u in self.user_colors if u != self.username]
        dialog = SoundSettingsDialog(
            self.root, self.theme,
            self.sounds_enabled, self.sfx_volume, self.user_volumes,
            known_users,
            on_save=self._apply_sound_settings
        )
        self.root.wait_window(dialog)

    def _apply_sound_settings(self, enabled, sfx_vol, user_vols):
        self.sounds_enabled = enabled
        self.sfx_volume     = sfx_vol
        self.user_volumes.update(user_vols)
        _sfx_volume_ref[0]  = sfx_vol
        self.save_config()

    def change_username(self):
        dialog = ModernInputDialog(self.root, "Change Username", "Enter new username:", theme=self.theme, app=self)
        self.root.wait_window(dialog)
        new_name = dialog.result
        if new_name and new_name.strip() and new_name.strip() != self.username:
            try:
                self.tcp_sock.send((json.dumps({'type': 'change_username',
                                                'new_username': new_name.strip(),
                                                'user_color': self.name_color}) + '\n').encode())
            except: messagebox.showerror("Error", "Failed to change username")
        self.root.focus_force()
        if self.msg_entry and self.msg_entry.winfo_exists():
            self.msg_entry.focus_set()
    def change_name_color(self):
        dialog = ColorPickerDialog(self.root, self.name_color, theme=self.theme)
        self._track_dialog(dialog)
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
                f"✓ Push-to-talk key changed to {self.format_key_display(dialog.result)}", local_only=True)

    def _get_embedded_chat_widgets(self):
        """Return all tk.Frame widgets embedded in the chat text widget."""
        widgets = []
        try:
            # dump returns all embedded windows as a flat list of (key, value, index) tuples
            dump = self.chat_text.dump('1.0', tk.END, window=True)
            for key, value, idx in dump:
                if key == 'window' and value:
                    try:
                        w = self.chat_text.nametowidget(value)
                        widgets.append(w)
                    except Exception:
                        pass
        except Exception:
            pass
        return widgets

    def _hide_embedded_chat_widgets(self):
        """Lower all embedded chat frames so dialogs paint over them correctly."""
        for w in self._get_embedded_chat_widgets():
            try: w.lower()
            except: pass

    def _show_embedded_chat_widgets(self):
        """Restore embedded chat frames to normal stacking order."""
        for w in self._get_embedded_chat_widgets():
            try: w.lift()
            except: pass

    def configure_audio_devices(self):
        settings_with_ptt = self.audio_settings.copy()
        settings_with_ptt['ptt_release_delay'] = getattr(self, 'ptt_release_delay', 0.0)
        dialog = AudioDeviceDialog(self.root, self.p, settings_with_ptt, theme=self.theme)
        self.root.wait_window(dialog)
        if dialog.result:
            old_settings = self.audio_settings.copy()
            new_ptt_delay = dialog.result.pop('ptt_release_delay', 0.0)
            self.audio_settings = dialog.result
            self.ptt_release_delay = new_ptt_delay
            if (old_settings.get('input_device_index')  != self.audio_settings.get('input_device_index') or
                    old_settings.get('output_device_index') != self.audio_settings.get('output_device_index')):
                self.restart_audio_streams()
            self.save_config()


    def restart_audio_streams(self):
        for stream in [self.stream_in, self.stream_out]:
            if stream:
                try: stream.stop_stream(); stream.close()
                except: pass
        self.stream_in = None; self.stream_out = None

    def clear_saved_password(self):
        self.saved_wire_hash = None; self.save_config()
        messagebox.showinfo("Password Cleared", "Saved password has been cleared.")

    def change_server(self):
        """Clear saved password and server, disconnect, and restart to login screen."""
        if not _themed_yesno(self.root, self.theme,
                             "Change Server", '⚠',
                             "This will clear your saved password and return you to the login screen.\n\nContinue?",
                             yes_label="✓  Continue",
                             no_label="✕  Cancel"):
            return
        # Wipe saved credentials and server
        self.saved_wire_hash = None
        cfg = self.load_config() or {}
        cfg.pop('server_ip', None)
        cfg['password'] = ''
        cfg['remember'] = False
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass
        # Restart the app — login dialog will appear fresh
        import subprocess
        try: self.root.after(100, self.root.destroy)
        except: pass
        self.running = False
        subprocess.Popen(get_exe_path())

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
        delay = getattr(self, 'ptt_release_delay', 0.0)
        if delay > 0:
            self.root.after(int(delay * 1000), self._do_stop_voice)
        else:
            self._do_stop_voice()

    def _do_stop_voice(self):
        if not self.voice_active: return
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
