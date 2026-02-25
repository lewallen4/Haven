import socket
import ssl
import threading
import json
import datetime
import time
import hashlib
import hmac as _hmac
import secrets
import random
import os
import sys
import base64
import getpass
import subprocess
from collections import defaultdict, deque

# ── Crypto module ─────────────────────────────────────────────────────────────
import sys, os as _os
_bin_dir = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', 'bin')
if _bin_dir not in sys.path:
    sys.path.insert(0, _os.path.abspath(_bin_dir))

try:
    from haven_crypto import (
        generate_kyber_keypair, kyber_encapsulate, kyber_decapsulate,
        generate_x25519_keypair, x25519_exchange,
        derive_session_key, derive_voice_key,
        encrypt_message, decrypt_message,
        encrypt_voice, decrypt_voice,
        hash_password, verify_password,
        compute_auth_response, compute_wire_password_hash,
        pack_server_hello, unpack_client_hello,
        SessionCrypto, CRYPTO_AVAILABLE, ARGON2_AVAILABLE
    )
    HAVEN_CRYPTO = True
except ImportError as e:
    HAVEN_CRYPTO = False
    print(f"\n  ✗ FATAL: haven_crypto not found — {e}")
    print(f"  Put haven_crypto.py in bin/ (one level up from server/).")
    print(f"  Haven server will not start without encryption.\n")
    import sys as _sys; _sys.exit(1)

# ---------- Configuration ----------
TCP_HOST = '0.0.0.0'
TCP_PORT = 5000
UDP_HOST = '0.0.0.0'
UDP_PORT = 5001
_SERVER_DIR        = os.path.dirname(os.path.abspath(__file__))
LOG_FILE           = os.path.join(_SERVER_DIR, 'server.log')
CHAT_HISTORY_FILE  = os.path.join(_SERVER_DIR, 'chat_history.json')
SERVER_CONFIG_FILE = os.path.join(_SERVER_DIR, 'server_config.json')
TLS_CERT_FILE      = os.path.join(_SERVER_DIR, 'server.crt')
TLS_KEY_FILE       = os.path.join(_SERVER_DIR, 'server.key')
MAX_HISTORY_MESSAGES = 1000

# Security limits
MAX_CONNECTIONS        = 100
MAX_CONNECTIONS_PER_IP = 3
LOGIN_TIMEOUT          = 20
RECV_TIMEOUT           = 300
MAX_BUFFER_SIZE        = 131072
MAX_MESSAGE_LENGTH     = 4000
MAX_USERNAME_LENGTH    = 32
UDP_RATE_LIMIT         = 80
UDP_RATE_WINDOW        = 1.0

BANNED_IPS = set()
# -----------------------------------

USER_COLOR_PALETTE = [
    '#ff006e', '#ff4d6d', '#ff6b9d', '#ff8fab',
    '#00ff88', '#06ffa5', '#4ecca3', '#78e08f',
    '#8338ec', '#a855f7', '#c084fc', '#e0aaff',
    '#ffd60a', '#ffb703', '#fb8500', '#ff9500',
    '#06d6a0', '#00b4d8', '#0096c7', '#48cae4',
    '#f72585', '#b5179e', '#7209b7', '#560bad'
]

clients      = {}
clients_lock = threading.Lock()

active_connections  = 0
connections_by_ip   = defaultdict(int)
connections_lock    = threading.Lock()

active_speakers      = set()
active_speakers_lock = threading.Lock()   # FIX: was unprotected
chat_history    = deque(maxlen=MAX_HISTORY_MESSAGES)
history_lock    = threading.Lock()

udp_rate_tracker = defaultdict(deque)
udp_rate_lock    = threading.Lock()

_AUTH_FAIL_WINDOW   = 600
_AUTH_FAIL_MAX      = 5
_AUTH_LOCKOUT_TIME  = 1800
_auth_failures      = defaultdict(deque)
_auth_lockouts      = {}
_auth_lock          = threading.Lock()

voice_sessions      = {}
voice_sessions_lock = threading.Lock()

SERVER_PASSWORD_HASH = ''

# ---------- TLS Certificate ----------

def generate_self_signed_cert():
    print("  Generating self-signed TLS certificate...")
    try:
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', TLS_KEY_FILE, '-out', TLS_CERT_FILE,
            '-days', '3650', '-nodes', '-subj', '/CN=haven-chat-server'
        ], check=True, capture_output=True)
        print(f"  ✓ TLS certificate generated (4096-bit RSA)")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"  ✗ Failed to generate cert: {e}")
        return False

def ensure_tls_cert():
    if os.path.exists(TLS_CERT_FILE) and os.path.exists(TLS_KEY_FILE):
        return True
    return generate_self_signed_cert()

def create_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    return ctx

# ---------- Config / Password ----------

def load_or_create_config():
    global SERVER_PASSWORD_HASH

    if os.path.exists(SERVER_CONFIG_FILE):
        try:
            with open(SERVER_CONFIG_FILE, 'r') as f:
                config = json.load(f)
            stored = config.get('password_hash', '')
            wire   = config.get('password_wire_hash', '')
            if stored:
                if not any(stored.startswith(p) for p in ('argon2:', 'pbkdf2:', 'sha256:')):
                    stored = 'sha256:' + stored
                    _upgrade_config_hash(stored)
                SERVER_PASSWORD_HASH = stored
                algo = 'Argon2id' if stored.startswith('argon2:') else ('PBKDF2' if stored.startswith('pbkdf2:') else 'SHA-256 (legacy)')
                if wire:
                    _SERVER_AUTH_CACHE['wire_response'] = wire
                return
        except Exception as e:
            print(f"  ⚠ Could not read config: {e}")

    print("\n" + "="*60)
    print("  FIRST TIME SETUP — Haven Chat Server")
    print("="*60)

    while True:
        password = getpass.getpass("  Enter server password (min 8 chars): ")
        if len(password) < 8:
            print("  ✗ Password must be at least 8 characters.")
            continue
        confirm = getpass.getpass("  Confirm password: ")
        if password != confirm:
            print("  ✗ Passwords do not match.")
            continue
        break

    SERVER_PASSWORD_HASH = hash_password(password)
    _SERVER_AUTH_CACHE['wire_response'] = hashlib.sha256(password.encode()).hexdigest()
    save_config()
    print(f"\n  ✓ Password hashed with {'Argon2id' if ARGON2_AVAILABLE else 'PBKDF2-SHA256'} and saved.\n")

def _upgrade_config_hash(new_hash):
    global SERVER_PASSWORD_HASH
    SERVER_PASSWORD_HASH = new_hash
    save_config()
    print("  ✓ Password hash upgraded to stronger format.")

def save_config():
    try:
        data = {'password_hash': SERVER_PASSWORD_HASH}
        wire = _SERVER_AUTH_CACHE.get('wire_response', '')
        if wire:
            data['password_wire_hash'] = wire
        with open(SERVER_CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"⚠ Could not save config: {e}")

# ---------- Network Info ----------

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except: return '127.0.0.1'

def get_external_ip():
    for url in ['https://api.ipify.org', 'https://checkip.amazonaws.com']:
        try:
            import urllib.request
            with urllib.request.urlopen(url, timeout=4) as r:
                return r.read().decode().strip()
        except: pass
    return 'unavailable'

def print_network_info():
    local_ip = get_local_ip()
    print("  Fetching external IP...")
    external_ip = get_external_ip()
    print("\n" + "="*60)
    print("  SERVER CONNECTIVITY INFO")
    print("="*60)
    print(f"  Local IP   : {local_ip}")
    print(f"  External IP: {external_ip}")
    print(f"  TCP Port   : {TCP_PORT}  (chat, TLS 1.2+ + PQ hybrid)")
    print(f"  UDP Port   : {UDP_PORT}  (voice, encrypted)")
    print()
    print(f"  LAN: {local_ip}:{TCP_PORT}    WAN: {external_ip}:{TCP_PORT}")
    print("="*60 + "\n")

# ---------- Utility ----------

def generate_random_color():
    return random.choice(USER_COLOR_PALETTE)

def sanitize_username(username):
    import re
    return re.sub(r'[^\w\-]', '', username)[:MAX_USERNAME_LENGTH]

def _history_key():
    """Derive the history encryption key from the wire hash in memory."""
    wire = _SERVER_AUTH_CACHE.get('wire_response', '')
    if not wire:
        return None
    return _hmac.new(wire.encode(), b'history-encryption-key-v1', hashlib.sha256).digest()

# ---------- History Encryption (AES-256-GCM direct, no haven_crypto API) ------
# We use the cryptography library directly rather than encrypt_message() to
# avoid any ambiguity about that function's key format or return type.

def _encrypt_history(data_bytes: bytes, key: bytes) -> bytes:
    """
    AES-256-GCM encrypt with a random 12-byte nonce.
    Layout: 0x02 | nonce(12) | ciphertext+tag(len+16)
    Falls back to SHAKE256-CTR+HMAC if cryptography lib unavailable.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        ct = AESGCM(key[:32]).encrypt(nonce, data_bytes, None)
        return b'\x02' + nonce + ct
    except ImportError:
        # SHAKE256-CTR + HMAC-SHA256 stdlib fallback
        nonce = os.urandom(12)
        h = hashlib.shake_256()
        h.update(key + nonce + b'history-ctr')
        ks = h.digest(len(data_bytes))
        ct = bytes(a ^ b for a, b in zip(data_bytes, ks))
        tag_key = _hmac.new(key, b'history-tag-' + nonce, hashlib.sha256).digest()
        tag = _hmac.new(tag_key, ct, hashlib.sha256).digest()
        return b'\x01' + nonce + tag + ct

def _decrypt_history(enc_bytes: bytes, key: bytes):
    """Returns decrypted bytes or None on auth/format failure."""
    if not enc_bytes:
        return None

    version = enc_bytes[0]

    if version == 0x02:
        # AES-256-GCM direct
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            nonce = enc_bytes[1:13]
            ct    = enc_bytes[13:]
            return AESGCM(key[:32]).decrypt(nonce, ct, None)
        except Exception:
            return None

    elif version == 0x01:
        # Legacy SHAKE256-CTR — reads fine, re-saves as 0x02 on next write
        payload = enc_bytes[1:]
        if len(payload) < 44:
            return None
        nonce = payload[:12]
        tag   = payload[12:44]
        ct    = payload[44:]
        tag_key = _hmac.new(key, b'history-tag-' + nonce, hashlib.sha256).digest()
        expected = _hmac.new(tag_key, ct, hashlib.sha256).digest()
        if not _hmac.compare_digest(tag, expected):
            return None
        h = hashlib.shake_256()
        h.update(key + nonce + b'history-ctr')
        ks = h.digest(len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks))

    else:
        # Pre-versioned legacy format — try SHAKE256-CTR without version byte
        payload = enc_bytes
        if len(payload) < 44:
            return None
        nonce = payload[:12]
        tag   = payload[12:44]
        ct    = payload[44:]
        tag_key = _hmac.new(key, b'history-tag-' + nonce, hashlib.sha256).digest()
        expected = _hmac.new(tag_key, ct, hashlib.sha256).digest()
        if not _hmac.compare_digest(tag, expected):
            return None
        h = hashlib.shake_256()
        h.update(key + nonce + b'history-ctr')
        ks = h.digest(len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks))

def load_chat_history():
    key = _history_key()
    try:
        with open(CHAT_HISTORY_FILE, 'r') as f:
            wrapper = json.load(f)

        if isinstance(wrapper, list):
            # Legacy plaintext format — migrate to encrypted on next save
            data = wrapper
            log_action(f'Loaded {len(data)} messages (plaintext — will encrypt on next save)')
        elif wrapper.get('v') == 1:
            if key is None:
                log_action('Cannot decrypt history — wire key not available')
                return
            enc_bytes = base64.b64decode(wrapper['data'])
            pt = _decrypt_history(enc_bytes, key)
            if pt is None:
                log_action('Chat history decryption failed — wrong key or file corrupt')
                return
            data = json.loads(pt.decode('utf-8'))
            log_action(f'Loaded {len(data)} messages (encrypted)')
        else:
            log_action('Unknown history format — skipping')
            return

        with history_lock:
            chat_history.extend(data)
    except FileNotFoundError:
        log_action('No existing chat history, starting fresh')
    except Exception as e:
        log_action(f'Error loading chat history: {e}')

def save_chat_history():
    try:
        with history_lock:
            data = list(chat_history)
        payload = json.dumps(data).encode('utf-8')
        key = _history_key()
        if key:
            enc = _encrypt_history(payload, key)
            wrapper = {'v': 1, 'data': base64.b64encode(enc).decode('ascii')}
        else:
            log_action('Warning: saving chat history unencrypted (no key)')
            wrapper = data
        with open(CHAT_HISTORY_FILE, 'w') as f:
            json.dump(wrapper, f)
    except Exception as e:
        log_action(f'Error saving chat history: {e}')

def add_to_history(user, text):
    ts = datetime.datetime.now().strftime('%H:%M')
    user_color = None
    with clients_lock:
        if user in clients and user != 'System':
            user_color = clients[user].get('color')
    with history_lock:
        chat_history.append({'user': user, 'text': text, 'timestamp': ts, 'color': user_color})
    threading.Thread(target=save_chat_history, daemon=True).start()

def log_action(action):
    ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    safe_action = action.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
    with open(LOG_FILE, 'a', encoding='utf-8', errors='replace') as f:
        f.write(f'[{ts}] {safe_action}\n')
    console_enc = sys.stdout.encoding or 'utf-8'
    console_safe = safe_action.encode(console_enc, errors='replace').decode(console_enc, errors='replace')
    print(f'[LOG] {console_safe}')

def send_json(conn, obj):
    conn.send((json.dumps(obj) + '\n').encode())

def broadcast_tcp(message, exclude=None):
    with clients_lock:
        for username, info in clients.items():
            if not info.get('authenticated'): continue
            if exclude and info['tcp'] == exclude: continue
            try:
                raw = json.dumps(message) + '\n'
                info['tcp'].send(raw.encode())
            except: pass

def broadcast_full_userlist():
    with clients_lock:
        user_list = [
            {'username': u, 'color': i.get('color', generate_random_color())}
            for u, i in clients.items() if i.get('authenticated')
        ]
    broadcast_tcp({'type': 'userlist_full', 'users': user_list})

# ---------- FIX: History sent encrypted per-recipient -------------------------

def send_chat_history(conn, session):
    """
    Send chat history encrypted with the recipient's session key.
    Each message is individually encrypted so the wire format matches live
    broadcast messages — no plaintext history ever leaves the server.

    If session is None (shouldn't happen — server rejects clients without one)
    we do NOT send history at all rather than leaking it in plaintext.
    """
    if session is None:
        log_action('Skipping history send — no session (would be plaintext)')
        return
    try:
        with history_lock:
            history_data = list(chat_history)
        if not history_data:
            return

        encrypted_history = []
        for entry in history_data:
            plaintext = entry.get('text', '')
            try:
                ct = session.encrypt_chat(plaintext)
                encrypted_history.append({
                    'user':      entry.get('user', ''),
                    'timestamp': entry.get('timestamp', ''),
                    'color':     entry.get('color'),
                    'encrypted': True,
                    'ct':        ct,
                })
            except Exception as e:
                # Skip messages that fail to encrypt rather than sending plaintext
                log_action(f'History entry encryption failed, skipping: {e}')
                continue

        if encrypted_history:
            send_json(conn, {'type': 'chat_history', 'history': encrypted_history})
            log_action(f'Sent {len(encrypted_history)} history messages (encrypted)')
    except Exception as e:
        log_action(f'Failed to send chat history: {e}')

# ---------- Encrypted broadcast -----------------------------------------------

def broadcast_encrypted_chat(sender_username, plaintext, exclude_conn=None):
    """Broadcast a chat message encrypted per-recipient with their session key."""
    with clients_lock:
        targets = [
            (u, i) for u, i in clients.items()
            if i.get('authenticated') and i['tcp'] != exclude_conn
        ]

    for uname, info in targets:
        session = info.get('session')
        try:
            if session:
                ct = session.encrypt_chat(plaintext)
                msg = {'type': 'chat', 'user': sender_username, 'encrypted': True, 'ct': ct}
            else:
                log_action(f"Skipping unencrypted relay to {uname} (no session)")
                continue
            info['tcp'].send((json.dumps(msg) + '\n').encode())
        except: pass

# ---------- Auth Handshake ----------------------------------------------------

def do_server_handshake(conn, addr):
    nonce = secrets.token_hex(32)
    if HAVEN_CRYPTO:
        kyber_pk, kyber_sk = generate_kyber_keypair()
        x25519_priv, x25519_pub = generate_x25519_keypair()
        hello = pack_server_hello(nonce, kyber_pk, x25519_pub)
    else:
        hello = {'type': 'challenge', 'nonce': nonce}
        kyber_sk = x25519_priv = None
    send_json(conn, hello)
    return nonce, kyber_sk, x25519_priv

def finalize_session_crypto(kyber_sk, x25519_priv, nonce, client_hello_msg):
    if not HAVEN_CRYPTO or not kyber_sk:
        return None
    try:
        kyber_ct, client_x25519_pub = unpack_client_hello(client_hello_msg)
        kyber_ss    = kyber_decapsulate(kyber_sk, kyber_ct)
        ecdh_ss     = x25519_exchange(x25519_priv, client_x25519_pub)
        session_key = derive_session_key(kyber_ss, ecdh_ss, nonce)
        return SessionCrypto(session_key)
    except Exception as e:
        log_action(f'Crypto handshake error: {e}')
        return None

# ---------- Auth failure tracking ---------------------------------------------

def _record_auth_failure(ip):
    now = time.time()
    with _auth_lock:
        failures = _auth_failures[ip]
        while failures and now - failures[0] > _AUTH_FAIL_WINDOW:
            failures.popleft()
        failures.append(now)
        if len(failures) >= _AUTH_FAIL_MAX:
            _auth_lockouts[ip] = now + _AUTH_LOCKOUT_TIME
            log_action(f'Auth lockout: {ip} after {len(failures)} failures — blocked for {_AUTH_LOCKOUT_TIME//60}min')
            return True
    return False

def _is_auth_locked(ip):
    with _auth_lock:
        expiry = _auth_lockouts.get(ip)
        if expiry and time.time() < expiry:
            return True
        elif expiry:
            del _auth_lockouts[ip]
    return False

# ---------- TCP Client Handler ------------------------------------------------

def handle_tcp_client(conn, addr):
    username = None
    buffer   = ''
    authenticated = False
    ip = addr[0]
    session = None

    if _is_auth_locked(ip):
        log_action(f'Rejected locked-out IP: {ip}')
        try: conn.close()
        except: pass
        return

    with connections_lock:
        global active_connections
        active_connections += 1
        connections_by_ip[ip] += 1

    try:
        if ip in BANNED_IPS:
            send_json(conn, {'type': 'error', 'message': 'You are banned'})
            return

        conn.settimeout(LOGIN_TIMEOUT)

        nonce, kyber_sk, x25519_priv = do_server_handshake(conn, addr)

        while True:
            try:
                data = conn.recv(4096).decode('utf-8', errors='replace')
            except socket.timeout:
                if not authenticated:
                    log_action(f'Login timeout from {ip}')
                    return
                continue

            if not data:
                break

            buffer += data
            if len(buffer) > MAX_BUFFER_SIZE:
                log_action(f'Buffer overflow from {ip}, dropping')
                return

            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if not line.strip(): continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue

                mtype = msg.get('type', '')

                if mtype == 'login':
                    provided = msg.get('auth_response', '')
                    expected = _SERVER_AUTH_CACHE.get('wire_response', '')
                    if not expected:
                        log_action(f'Auth cache miss from {ip}')
                        send_json(conn, {'type': 'auth_failed'})
                        return

                    expected_response = hashlib.sha256(f"{nonce}:{expected}".encode()).hexdigest()

                    if not _hmac.compare_digest(provided, expected_response):
                        send_json(conn, {'type': 'auth_failed'})
                        log_action(f'Failed auth from {ip} (user: {msg.get("username","?")})')
                        _record_auth_failure(ip)
                        return

                    session = finalize_session_crypto(kyber_sk, x25519_priv, nonce, msg)
                    if HAVEN_CRYPTO and session is None:
                        log_action(f'Crypto handshake failed for {ip}, rejecting')
                        send_json(conn, {'type': 'error', 'message': 'Crypto handshake failed'})
                        return

                    raw_username = msg.get('username', '').strip()
                    username = sanitize_username(raw_username)
                    if not username:
                        send_json(conn, {'type': 'error', 'message': 'Invalid username'})
                        return

                    udp_port   = msg.get('udp_port', 0)
                    user_color = msg.get('user_color') or generate_random_color()

                    with clients_lock:
                        if username in clients:
                            send_json(conn, {'type': 'error', 'message': 'Username taken'})
                            return
                        clients[username] = {
                            'tcp': conn, 'addr': addr,
                            'udp_port': udp_port,
                            'authenticated': True,
                            'color': user_color,
                            'session': session,
                            'last_seen': time.time(),
                        }
                        authenticated = True

                    if session:
                        with voice_sessions_lock:
                            voice_sessions[(ip, udp_port)] = session.voice_key

                    conn.settimeout(RECV_TIMEOUT)

                    crypto_info = {
                        'enabled': HAVEN_CRYPTO and session is not None,
                        'kem': 'kyber512+x25519' if HAVEN_CRYPTO else 'none',
                        'chat_enc': 'aes-256-gcm' if CRYPTO_AVAILABLE else 'shake256-hmac',
                        'voice_enc': 'chacha20-poly1305' if CRYPTO_AVAILABLE else 'shake256-hmac',
                        'pw_kdf': 'argon2id' if ARGON2_AVAILABLE else 'pbkdf2-sha256',
                    }
                    send_json(conn, {'type': 'auth_ok', 'user_color': user_color,
                                     'crypto': crypto_info})
                    log_action(f'User {username} joined from {ip} | crypto={crypto_info["enabled"]} kem={crypto_info["kem"]}')
                    with _auth_lock:
                        _auth_failures.pop(ip, None)
                        _auth_lockouts.pop(ip, None)

                    # History sent encrypted — session is passed in
                    send_chat_history(conn, session)

                    with clients_lock:
                        user_list = [{'username': u, 'color': i.get('color')}
                                      for u, i in clients.items() if i.get('authenticated')]
                    send_json(conn, {'type': 'userlist_full', 'users': user_list})
                    broadcast_full_userlist()

                    join_text = f'{username} has joined the chat'
                    broadcast_encrypted_chat('System', join_text, exclude_conn=conn)
                    add_to_history('System', join_text)
                    continue

                if not authenticated:
                    continue

                if username:
                    with clients_lock:
                        if username in clients:
                            clients[username]['last_seen'] = time.time()

                if mtype == 'chat':
                    if msg.get('encrypted') and session:
                        plaintext = session.decrypt_chat(msg.get('ct', ''))
                        if plaintext is None:
                            log_action(f'Decryption failed from {username} — message dropped')
                            continue
                    elif session:
                        log_action(f'Unencrypted message from {username} rejected (session active)')
                        continue
                    else:
                        log_action(f'Unexpected unencrypted message from {username} — dropped')
                        continue
                    plaintext = plaintext[:MAX_MESSAGE_LENGTH]
                    if plaintext and username:
                        log_action(f'Chat from {username}: {plaintext[:80]}')
                        broadcast_encrypted_chat(username, plaintext, exclude_conn=conn)
                        add_to_history(username, plaintext)

                elif mtype == 'ping':
                    try:
                        send_json(conn, {'type': 'pong'})
                    except: pass
                    continue

                elif mtype == 'pong':
                    if username:
                        with clients_lock:
                            if username in clients:
                                clients[username]['last_seen'] = time.time()
                    continue

                elif mtype == 'voice_start':
                    if username:
                        with active_speakers_lock:
                            active_speakers.add(username)
                        broadcast_tcp({'type': 'voice_start', 'user': username})

                elif mtype == 'voice_stop':
                    if username:
                        with active_speakers_lock:
                            active_speakers.discard(username)
                        broadcast_tcp({'type': 'voice_stop', 'user': username})

                elif mtype == 'change_username':
                    new_raw  = msg.get('new_username', '').strip()
                    new_name = sanitize_username(new_raw)
                    new_color = msg.get('user_color')

                    if not username: continue

                    with clients_lock:
                        if username not in clients: continue
                        current_color = clients[username].get('color', generate_random_color())
                        old_username  = username

                        if new_name and new_name != username:
                            if new_name in clients:
                                send_json(conn, {'type': 'error', 'message': 'Username already taken'})
                                continue
                            clients[new_name] = clients.pop(username)
                            clients[new_name]['tcp'] = conn
                            username = new_name
                            with active_speakers_lock:
                                if old_username in active_speakers:
                                    active_speakers.discard(old_username)
                                    active_speakers.add(new_name)

                        clients[username]['color'] = new_color if new_color else current_color

                    send_json(conn, {'type': 'username_changed', 'new_username': username,
                                     'user_color': clients[username]['color']})
                    log_action(f'{old_username} → {username}')
                    broadcast_full_userlist()

                    if new_name and new_name != old_username:
                        rename_text = f'{old_username} is now known as {username}'
                        broadcast_encrypted_chat('System', rename_text, exclude_conn=conn)
                        add_to_history('System', rename_text)

                    broadcast_tcp({'type': 'user_color_changed', 'username': username,
                                   'color': clients[username]['color']})

    except ssl.SSLError as e:
        log_action(f'TLS error from {ip}: {e}')
    except Exception as e:
        import traceback
        log_action(f"TCP error ({username or 'unknown'}@{ip}): {e}")
        log_action(traceback.format_exc())
    finally:
        with connections_lock:
            active_connections -= 1
            connections_by_ip[ip] = max(0, connections_by_ip[ip] - 1)
            if connections_by_ip[ip] == 0:
                del connections_by_ip[ip]

        if username:
            udp_port = None
            with clients_lock:
                info = clients.pop(username, {})
                udp_port = info.get('udp_port')
            if udp_port:
                with voice_sessions_lock:
                    voice_sessions.pop((ip, udp_port), None)
            with active_speakers_lock:
                active_speakers.discard(username)
            log_action(f'User {username} disconnected')
            broadcast_full_userlist()
            leave_text = f'{username} has left the chat'
            broadcast_encrypted_chat('System', leave_text)
            add_to_history('System', leave_text)
        conn.close()

# ---------- Server Heartbeat --------------------------------------------------

HEARTBEAT_INTERVAL = 300
HEARTBEAT_TIMEOUT  = 60

def server_heartbeat():
    while True:
        time.sleep(HEARTBEAT_INTERVAL)
        now      = time.time()
        deadline = now - HEARTBEAT_INTERVAL - HEARTBEAT_TIMEOUT

        dead_users = []
        with clients_lock:
            for uname, info in clients.items():
                if not info.get('authenticated'):
                    continue
                last_seen = info.get('last_seen', now)
                if last_seen < deadline:
                    dead_users.append(uname)
                else:
                    try:
                        send_json(info['tcp'], {'type': 'ping'})
                    except Exception:
                        dead_users.append(uname)

        for uname in dead_users:
            log_action(f'Heartbeat timeout — removing {uname}')
            with clients_lock:
                info = clients.pop(uname, {})
            if info:
                try: info['tcp'].close()
                except: pass
            with active_speakers_lock:
                active_speakers.discard(uname)
            broadcast_full_userlist()
            leave_text = f'{uname} has left the chat'
            broadcast_encrypted_chat('System', leave_text)
            add_to_history('System', leave_text)

# ---------- TCP Server --------------------------------------------------------

def tcp_server():
    ssl_ctx = create_ssl_context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((TCP_HOST, TCP_PORT))
        raw_sock.listen()
        with ssl_ctx.wrap_socket(raw_sock, server_side=True) as server_sock:
            while True:
                try:
                    conn, addr = server_sock.accept()
                    ip = addr[0]
                    with connections_lock:
                        if active_connections >= MAX_CONNECTIONS:
                            conn.close(); continue
                        if connections_by_ip.get(ip, 0) >= MAX_CONNECTIONS_PER_IP:
                            conn.close(); continue
                    threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()
                except ssl.SSLError as e:
                    log_action(f'TLS handshake error: {e}')
                except Exception as e:
                    log_action(f'TCP accept error: {e}')

# ---------- UDP Voice Server --------------------------------------------------

def udp_check_rate_limit(ip):
    now = time.monotonic()
    with udp_rate_lock:
        ts = udp_rate_tracker[ip]
        while ts and now - ts[0] > UDP_RATE_WINDOW:
            ts.popleft()
        if len(ts) >= UDP_RATE_LIMIT:
            return False
        ts.append(now)
        return True

def udp_server():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((UDP_HOST, UDP_PORT))

    while True:
        try:
            data, addr = udp_sock.recvfrom(8192)
            ip = addr[0]

            if ip in BANNED_IPS: continue
            if not udp_check_rate_limit(ip): continue

            with clients_lock:
                sender = None
                sender_info = None
                for uname, info in clients.items():
                    if not info.get('authenticated'): continue
                    if info['addr'][0] == ip and info['udp_port'] == addr[1]:
                        sender = uname
                        sender_info = info
                        break
                if not sender: continue

                recipients = [
                    (u, i) for u, i in clients.items()
                    if i.get('authenticated') and u != sender
                ]

            if HAVEN_CRYPTO and sender_info.get('session'):
                sender_session = sender_info['session']
                pcm = sender_session.decrypt_voice(data)
                if pcm is None:
                    continue

                for uname, info in recipients:
                    recv_session = info.get('session')
                    if recv_session:
                        enc = recv_session.encrypt_voice(pcm)
                        try:
                            udp_sock.sendto(enc, (info['addr'][0], info['udp_port']))
                        except: pass
            else:
                pass

        except Exception as e:
            log_action(f'UDP error: {e}')

# ---------- Wire Password Cache -----------------------------------------------

_SERVER_AUTH_CACHE = {}

def _setup_wire_auth():
    if _SERVER_AUTH_CACHE.get('wire_response'):
        return True

    if os.path.exists(SERVER_CONFIG_FILE):
        try:
            with open(SERVER_CONFIG_FILE, 'r') as f:
                stored = json.load(f).get('password_hash', '')
            if stored:
                pw = getpass.getpass("  Enter server password (one-time — will be cached): ")
                if not verify_password(pw, stored):
                    print("  ✗ Wrong password.")
                    sys.exit(1)
                wire_hash = hashlib.sha256(pw.encode()).hexdigest()
                _SERVER_AUTH_CACHE['wire_response'] = wire_hash
                save_config()
                print("  ✓ Wire auth cached. Future startups will not require a password prompt.")
                return True
        except Exception as e:
            print(f"  ✗ Error: {e}")
            sys.exit(1)
    return False

# ---------- Admin Console -----------------------------------------------------

def admin_console():
    print("\n" + "="*60)
    print("  HAVEN CHAT SERVER - ADMIN CONSOLE")
    print("="*60)
    print("  /kick <user>         - Kick a user")
    print("  /ban <IP>            - Ban an IP")
    print("  /unban <IP>          - Unban an IP")
    print("  /password            - Change server password")
    print("  /list                - List connected users")
    print("  /history [n]         - Show last n messages")
    print("  /stats               - Connection stats")
    print("  /crypto              - Show crypto status")
    print("  /save                - Save chat history")
    print("  /help                - This help")
    print("="*60 + "\n")

    while True:
        try:
            cmd = input().strip()
        except EOFError:
            time.sleep(60); continue

        if cmd.startswith('/kick '):
            username = cmd[6:].strip()
            with clients_lock:
                if username in clients:
                    ip = clients[username]['addr'][0]
                    try:
                        clients[username]['tcp'].send(json.dumps({'type': 'kicked'}).encode() + b'\n')
                        clients[username]['tcp'].close()
                    except: pass
                    del clients[username]
                    with active_speakers_lock:
                        active_speakers.discard(username)
                    log_action(f'Admin kicked {username} ({ip})')
                    broadcast_full_userlist()
                    print(f'  ✓ Kicked {username}')
                else:
                    print('  ✗ User not found')

        elif cmd.startswith('/ban '):
            ip = cmd[5:].strip(); BANNED_IPS.add(ip)
            with clients_lock:
                to_remove = [u for u, i in clients.items() if i['addr'][0] == ip]
                for uname in to_remove:
                    try:
                        clients[uname]['tcp'].send(json.dumps({'type': 'banned'}).encode() + b'\n')
                        clients[uname]['tcp'].close()
                    except: pass
                    del clients[uname]
                    with active_speakers_lock:
                        active_speakers.discard(uname)
            log_action(f'Admin banned {ip}'); broadcast_full_userlist()
            print(f'  ✓ Banned {ip}')

        elif cmd.startswith('/unban '):
            ip = cmd[7:].strip()
            if ip in BANNED_IPS:
                BANNED_IPS.remove(ip); log_action(f'Unbanned {ip}'); print(f'  ✓ Unbanned {ip}')
            else:
                print('  ✗ Not in ban list')

        elif cmd == '/password':
            print("  Changing password...")
            try:
                pw = getpass.getpass("  New password (min 8 chars): ")
                if len(pw) < 8:
                    print("  ✗ Too short"); continue
                confirm = getpass.getpass("  Confirm: ")
                if pw != confirm:
                    print("  ✗ Mismatch"); continue
                global SERVER_PASSWORD_HASH
                SERVER_PASSWORD_HASH = hash_password(pw)
                wire_hash = hashlib.sha256(pw.encode()).hexdigest()
                _SERVER_AUTH_CACHE['wire_response'] = wire_hash
                save_config()
                log_action('Admin changed server password')
                print('  ✓ Password updated and cached. Existing sessions remain active.')
            except Exception as e:
                print(f'  ✗ Error: {e}')

        elif cmd == '/crypto':
            print(f"\n  Crypto status:")
            print(f"  haven_crypto module : {'loaded' if HAVEN_CRYPTO else 'MISSING'}")
            if HAVEN_CRYPTO:
                print(f"  cryptography lib    : {'yes' if CRYPTO_AVAILABLE else 'no (stdlib fallback)'}")
                print(f"  argon2-cffi         : {'yes' if ARGON2_AVAILABLE else 'no (PBKDF2 fallback)'}")
                print(f"  KEM                 : Kyber-512 + X25519 (hybrid PQ)")
                print(f"  Chat encryption     : {'AES-256-GCM' if CRYPTO_AVAILABLE else 'SHAKE256+HMAC-SHA256'}")
                print(f"  Voice encryption    : {'ChaCha20-Poly1305' if CRYPTO_AVAILABLE else 'SHAKE256+HMAC-SHA256'}")
                print(f"  History delivery    : encrypted per-recipient (AES-256-GCM)")
                print(f"  History storage     : {'AES-256-GCM' if CRYPTO_AVAILABLE else 'SHAKE256+HMAC (legacy)'}")
                print(f"  Password KDF        : {'Argon2id' if ARGON2_AVAILABLE else 'PBKDF2-SHA256 (600k)'}")
                with clients_lock:
                    encrypted_users = sum(1 for i in clients.values() if i.get('session'))
                    total_users = sum(1 for i in clients.values() if i.get('authenticated'))
                print(f"  Users with E2E      : {encrypted_users}/{total_users}")
            print()

        elif cmd == '/list':
            with clients_lock:
                authed = {u: i for u, i in clients.items() if i.get('authenticated')}
            if authed:
                print(f'\n  {"Username":<20} {"IP":<16} {"Crypto":<8} {"Voice"}')
                print('  ' + '-'*56)
                for uname, info in authed.items():
                    with active_speakers_lock:
                        speaking = uname in active_speakers
                    voice  = '🔴 live' if speaking else '○ idle'
                    crypto = 'E2E' if info.get('session') else 'plain'
                    print(f'  {uname:<20} {info["addr"][0]:<16} {crypto:<8} {voice}')
                print()
            else:
                print('  No users connected\n')

        elif cmd == '/stats':
            with connections_lock:
                total = active_connections; by_ip = dict(connections_by_ip)
            print(f'\n  Active: {total}/{MAX_CONNECTIONS}')
            for ip, count in by_ip.items():
                print(f'    {ip}: {count}')
            print()

        elif cmd.startswith('/history'):
            parts = cmd.split(); n = 10
            if len(parts) > 1:
                try: n = int(parts[1])
                except: print('  ✗ Invalid number'); continue
            with history_lock:
                messages = list(chat_history)[-n:]
            for m in messages:
                print(f'  [{m["timestamp"]}] {m["user"]}: {m["text"]}')
            print()

        elif cmd == '/save':
            save_chat_history(); print('  ✓ Saved')

        elif cmd == '/help':
            print("  /kick /ban /unban /password /list /history /stats /crypto /save /help")

        else:
            if cmd: print('  ✗ Unknown command. /help for help.')

# ---------- Entry Point -------------------------------------------------------

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  HAVEN CHAT SERVER  (PQ Secure Edition)")
    print("="*60 + "\n")

    load_or_create_config()

    if os.path.exists(SERVER_CONFIG_FILE) and not _SERVER_AUTH_CACHE.get('wire_response'):
        _setup_wire_auth()

    if not ensure_tls_cert():
        print("\n  ⚠ TLS certificate required. Exiting.")
        sys.exit(1)

    print_network_info()
    load_chat_history()

    threading.Thread(target=tcp_server,        daemon=True).start()
    threading.Thread(target=udp_server,        daemon=True).start()
    threading.Thread(target=admin_console,     daemon=True).start()
    threading.Thread(target=server_heartbeat,  daemon=True).start()

    print("  Server running. Type /help for admin commands.")
    print()
    while True:
        time.sleep(1)
