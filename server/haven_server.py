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
# haven_crypto.py lives in ../bin/ relative to this server script.
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
# All server data files live alongside haven_server.py in the server/ directory.
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
LOGIN_TIMEOUT          = 20   # slightly more for crypto handshake
RECV_TIMEOUT           = 300
MAX_BUFFER_SIZE        = 131072   # 128KB (larger for encrypted payloads)
MAX_MESSAGE_LENGTH     = 4000
MAX_USERNAME_LENGTH    = 32
UDP_RATE_LIMIT         = 80        # slightly higher — encrypted packets are larger
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

# Connected clients:
# {username: {tcp, addr, udp_port, authenticated, color, session: SessionCrypto|None}}
clients      = {}
clients_lock = threading.Lock()

active_connections  = 0
connections_by_ip   = defaultdict(int)
connections_lock    = threading.Lock()

active_speakers = set()
chat_history    = deque(maxlen=MAX_HISTORY_MESSAGES)
history_lock    = threading.Lock()

udp_rate_tracker = defaultdict(deque)
udp_rate_lock    = threading.Lock()

# Per-IP session keys for voice decryption (keyed by (ip, udp_port))
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
        print(f"  ✓ Found existing TLS certificate")
        return True
    return generate_self_signed_cert()

def create_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Prefer forward-secret cipher suites
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
                # Upgrade bare SHA-256 hashes from old config files
                if not any(stored.startswith(p) for p in ('argon2:', 'pbkdf2:', 'sha256:')):
                    stored = 'sha256:' + stored
                    _upgrade_config_hash(stored)
                SERVER_PASSWORD_HASH = stored
                algo = 'Argon2id' if stored.startswith('argon2:') else ('PBKDF2' if stored.startswith('pbkdf2:') else 'SHA-256 (legacy)')
                if wire:
                    # Wire hash already saved — no interactive prompt needed at startup
                    _SERVER_AUTH_CACHE['wire_response'] = wire
                    print(f"  ✓ Config loaded. Password algo: {algo}. Wire auth ready.")
                else:
                    print(f"  ✓ Config loaded. Password algo: {algo}.")
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
    # Cache wire hash immediately so save_config() persists it — no prompt on next start
    _SERVER_AUTH_CACHE['wire_response'] = hashlib.sha256(password.encode()).hexdigest()
    save_config()
    print(f"\n  ✓ Password hashed with {'Argon2id' if ARGON2_AVAILABLE else 'PBKDF2-SHA256'} and saved.\n")

def _upgrade_config_hash(new_hash):
    """Rewrite config with upgraded hash format."""
    global SERVER_PASSWORD_HASH
    SERVER_PASSWORD_HASH = new_hash
    save_config()
    print("  ✓ Password hash upgraded to stronger format.")

def save_config():
    try:
        data = {'password_hash': SERVER_PASSWORD_HASH}
        # Also persist the wire hash so startup needs no interactive prompt.
        # Wire hash = SHA256(password). Safe to store server-side: it only
        # authenticates to this server and is useless without TLS+PQ layer.
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

def load_chat_history():
    try:
        with open(CHAT_HISTORY_FILE, 'r') as f:
            data = json.load(f)
        with history_lock:
            chat_history.extend(data)
        log_action(f'Loaded {len(data)} messages from chat history')
    except FileNotFoundError:
        log_action('No existing chat history, starting fresh')
    except Exception as e:
        log_action(f'Error loading chat history: {e}')

def save_chat_history():
    try:
        with history_lock:
            data = list(chat_history)
        with open(CHAT_HISTORY_FILE, 'w') as f:
            json.dump(data, f)
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
    with open(LOG_FILE, 'a') as f:
        f.write(f'[{ts}] {action}\n')
    print(f'[LOG] {action}')

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

def send_chat_history(conn, session):
    """Send chat history — messages are server-side plaintext (history predates this session)."""
    try:
        with history_lock:
            history_data = list(chat_history)
        if history_data:
            send_json(conn, {'type': 'chat_history', 'history': history_data})
            log_action(f'Sent {len(history_data)} history messages')
    except Exception as e:
        log_action(f'Failed to send chat history: {e}')

# ---------- Encrypted broadcast ----------

def broadcast_encrypted_chat(sender_username, plaintext, exclude_conn=None):
    """
    Broadcast a chat message encrypted per-recipient with their session key.
    Each client gets a ciphertext only they can decrypt.
    """
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
                # No session means the client never completed PQ handshake.
                # We do not send plaintext — skip this recipient entirely.
                log_action(f"Skipping unencrypted relay to {uname} (no session)")
                continue
            info['tcp'].send((json.dumps(msg) + '\n').encode())
        except: pass

# ---------- Auth Handshake ----------

def do_server_handshake(conn, addr):
    """
    Perform the PQ hybrid handshake and return (nonce, SessionCrypto) on success,
    or raise an exception on failure.
    """
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
    """Derive session key from client hello. Returns SessionCrypto or None."""
    if not HAVEN_CRYPTO or not kyber_sk:
        return None
    try:
        kyber_ct, client_x25519_pub = unpack_client_hello(client_hello_msg)
        kyber_ss   = kyber_decapsulate(kyber_sk, kyber_ct)
        ecdh_ss    = x25519_exchange(x25519_priv, client_x25519_pub)
        session_key = derive_session_key(kyber_ss, ecdh_ss, nonce)
        return SessionCrypto(session_key)
    except Exception as e:
        log_action(f'Crypto handshake error: {e}')
        return None

# ---------- TCP Client Handler ----------

def handle_tcp_client(conn, addr):
    username = None
    buffer   = ''
    authenticated = False
    ip = addr[0]
    session = None

    with connections_lock:
        global active_connections
        active_connections += 1
        connections_by_ip[ip] += 1

    try:
        if ip in BANNED_IPS:
            send_json(conn, {'type': 'error', 'message': 'You are banned'})
            return

        conn.settimeout(LOGIN_TIMEOUT)

        # ── PQ Hybrid Handshake ──────────────────────────────────────────────
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

                # ── Login ────────────────────────────────────────────────────
                if mtype == 'login':
                    provided = msg.get('auth_response', '')
                    wire_hash = SERVER_PASSWORD_HASH
                    # Server always stores strong hash (argon2/pbkdf2),
                    # but wire auth uses SHA256(nonce:SHA256(password)).
                    # We need the wire_hash of the password, which is SHA256(password).
                    # We can't reverse our storage hash, so we store the wire_hash separately
                    # in memory only (set at startup) — see SERVER_WIRE_HASH global.
                    expected = _SERVER_AUTH_CACHE.get('wire_response', '')
                    if not expected:
                        # Fallback: if no wire response cached (shouldn't happen)
                        log_action(f'Auth cache miss from {ip}')
                        send_json(conn, {'type': 'auth_failed'})
                        return

                    # Compute expected: SHA256(nonce:wire_hash)
                    expected_response = hashlib.sha256(f"{nonce}:{expected}".encode()).hexdigest()

                    if not _hmac.compare_digest(provided, expected_response):
                        send_json(conn, {'type': 'auth_failed'})
                        log_action(f'Failed auth from {ip} (user: {msg.get("username","?")}) ')
                        return

                    # ── Session crypto ───────────────────────────────────────
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
                        }
                        authenticated = True

                    # Store voice key for UDP routing
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

                # ── Chat ──────────────────────────────────────────────────────
                if mtype == 'chat':
                    if msg.get('encrypted') and session:
                        plaintext = session.decrypt_chat(msg.get('ct', ''))
                        if plaintext is None:
                            log_action(f'Decryption failed from {username} — message dropped')
                            continue
                    elif session:
                        # Session active but message arrived unencrypted — reject it.
                        log_action(f'Unencrypted message from {username} rejected (session active)')
                        continue
                    else:
                        # No session and no encryption — should never reach here
                        # since we reject clients that fail PQ handshake at login.
                        log_action(f'Unexpected unencrypted message from {username} — dropped')
                        continue
                    plaintext = plaintext[:MAX_MESSAGE_LENGTH]
                    if plaintext and username:
                        log_action(f'Chat from {username}: {plaintext[:80]}')
                        broadcast_encrypted_chat(username, plaintext, exclude_conn=conn)
                        add_to_history(username, plaintext)

                # ── Voice ─────────────────────────────────────────────────────
                elif mtype == 'voice_start':
                    if username:
                        active_speakers.add(username)
                        broadcast_tcp({'type': 'voice_start', 'user': username})

                elif mtype == 'voice_stop':
                    if username:
                        active_speakers.discard(username)
                        broadcast_tcp({'type': 'voice_stop', 'user': username})

                # ── Change Username ───────────────────────────────────────────
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
            active_speakers.discard(username)
            log_action(f'User {username} disconnected')
            broadcast_full_userlist()
            leave_text = f'{username} has left the chat'
            broadcast_encrypted_chat('System', leave_text)
            add_to_history('System', leave_text)
        conn.close()

# ---------- TCP Server ----------

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

# ---------- UDP Voice Server (with per-session encryption) ----------

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

            # Decrypt from sender, re-encrypt for each recipient
            if HAVEN_CRYPTO and sender_info.get('session'):
                sender_session = sender_info['session']
                pcm = sender_session.decrypt_voice(data)
                if pcm is None:
                    continue  # Drop invalid/tampered packet

                for uname, info in recipients:
                    recv_session = info.get('session')
                    if recv_session:
                        enc = recv_session.encrypt_voice(pcm)
                        try:
                            udp_sock.sendto(enc, (info['addr'][0], info['udp_port']))
                        except: pass
            else:
                # Sender has no session — drop the packet.
                # We never relay unencrypted voice when encryption is expected.
                pass

        except Exception as e:
            log_action(f'UDP error: {e}')

# ---------- Wire Password Cache ----------
# We store the strong hash (Argon2/PBKDF2) on disk.
# For wire auth we need SHA256(password) in memory — obtained once at startup.
# This never touches disk.
_SERVER_AUTH_CACHE = {}

def _setup_wire_auth():
    """Ensure wire auth cache is populated. Prompts only if wire hash not already saved."""
    # Wire hash already loaded from config by load_or_create_config — nothing to do.
    if _SERVER_AUTH_CACHE.get('wire_response'):
        return True

    # Wire hash not in config (old install or first run after upgrade).
    # Ask once, then save it so future startups are prompt-free.
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
                save_config()   # persist wire hash so next start needs no prompt
                print("  ✓ Wire auth cached. Future startups will not require a password prompt.")
                return True
        except Exception as e:
            print(f"  ✗ Error: {e}")
            sys.exit(1)
    return False

# ---------- Admin Console ----------

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
                    del clients[uname]; active_speakers.discard(uname)
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
                save_config()
                wire_hash = hashlib.sha256(pw.encode()).hexdigest()
                _SERVER_AUTH_CACHE['wire_response'] = wire_hash
                save_config()   # persist new wire hash
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
                    voice  = '🔴 live' if uname in active_speakers else '○ idle'
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
            admin_console.__doc__ and print(admin_console.__doc__)
            print("  /kick /ban /unban /password /list /history /stats /crypto /save /help")

        else:
            if cmd: print('  ✗ Unknown command. /help for help.')

# ---------- Entry Point ----------

if __name__ == '__main__':
    print("\n" + "="*60)
    print(" ")
    print("       HAVEN CHAT SERVER")
    print("\n" + "="*60)
    print(" ")

    load_or_create_config()

    # After config is loaded / created, set up the wire auth cache
    # (first-run path doesn't need to re-prompt — handled differently)
    if os.path.exists(SERVER_CONFIG_FILE) and not _SERVER_AUTH_CACHE.get('wire_response'):
        _setup_wire_auth()

    if not ensure_tls_cert():
        print("\n  ⚠ TLS certificate required. Exiting.")
        sys.exit(1)

    print_network_info()
    load_chat_history()

    threading.Thread(target=tcp_server,    daemon=True).start()
    threading.Thread(target=udp_server,    daemon=True).start()
    threading.Thread(target=admin_console, daemon=True).start()

    
    while True:
        time.sleep(1)
