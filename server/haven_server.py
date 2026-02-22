import socket
import ssl
import threading
import json
import datetime
import time
import hashlib
import hmac
import secrets
import random
import os
import getpass
import subprocess
from collections import defaultdict, deque

# ---------- Configuration ----------
TCP_HOST = '0.0.0.0'
TCP_PORT = 5000
UDP_HOST = '0.0.0.0'
UDP_PORT = 5001
LOG_FILE = 'server.log'
CHAT_HISTORY_FILE = 'chat_history.json'
SERVER_CONFIG_FILE = 'server_config.json'
TLS_CERT_FILE = 'server.crt'
TLS_KEY_FILE = 'server.key'
MAX_HISTORY_MESSAGES = 1000

# Security limits
MAX_CONNECTIONS = 100           # Hard cap on simultaneous connections
MAX_CONNECTIONS_PER_IP = 3      # Max connections from one IP
LOGIN_TIMEOUT = 15              # Seconds to complete login before disconnect
RECV_TIMEOUT = 300              # 5-minute idle timeout
MAX_BUFFER_SIZE = 65536         # 64KB max buffer per client (prevent memory exhaustion)
MAX_MESSAGE_LENGTH = 4000       # Max chat message length
MAX_USERNAME_LENGTH = 32        # Max username length
UDP_RATE_LIMIT = 50             # Max UDP packets per second per IP
UDP_RATE_WINDOW = 1.0           # Rate limit window in seconds

BANNED_IPS = set()
# -----------------------------------

# Vibrant color palette for usernames
USER_COLOR_PALETTE = [
    '#ff006e', '#ff4d6d', '#ff6b9d', '#ff8fab',
    '#00ff88', '#06ffa5', '#4ecca3', '#78e08f',
    '#8338ec', '#a855f7', '#c084fc', '#e0aaff',
    '#ffd60a', '#ffb703', '#fb8500', '#ff9500',
    '#06d6a0', '#00b4d8', '#0096c7', '#48cae4',
    '#f72585', '#b5179e', '#7209b7', '#560bad'
]

# Connected clients: {username: {'tcp': socket, 'addr': (ip,port), 'udp_port': int, 'authenticated': bool, 'color': str}}
clients = {}
clients_lock = threading.Lock()

# Active connection count tracking
active_connections = 0
connections_by_ip = defaultdict(int)
connections_lock = threading.Lock()

# Track who's currently transmitting voice
active_speakers = set()

# Chat history
chat_history = deque(maxlen=MAX_HISTORY_MESSAGES)
history_lock = threading.Lock()

# UDP rate limiting: {ip: deque of timestamps}
udp_rate_tracker = defaultdict(deque)
udp_rate_lock = threading.Lock()

# Global password hash
SERVER_PASSWORD_HASH = ''

# ---------- TLS Certificate Generation ----------

def generate_self_signed_cert():
    """Generate a self-signed TLS cert using openssl CLI."""
    print("  Generating self-signed TLS certificate...")
    try:
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', TLS_KEY_FILE,
            '-out', TLS_CERT_FILE,
            '-days', '3650',
            '-nodes',
            '-subj', '/CN=haven-chat-server'
        ], check=True, capture_output=True)
        print(f"  ✓ TLS certificate generated ({TLS_CERT_FILE}, {TLS_KEY_FILE})")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"  ✗ Failed to generate cert via openssl: {e}")
        print("  To manually generate: openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 3650 -nodes -subj '/CN=haven-chat'")
        return False

def ensure_tls_cert():
    """Make sure TLS cert and key exist, generate if not."""
    if os.path.exists(TLS_CERT_FILE) and os.path.exists(TLS_KEY_FILE):
        print(f"  ✓ Found existing TLS certificate ({TLS_CERT_FILE})")
        return True
    return generate_self_signed_cert()

def create_ssl_context():
    """Create SSL context for the server."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
    # Disable old/weak protocols
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx

# ---------- Config / Password Setup ----------

def load_or_create_config():
    global SERVER_PASSWORD_HASH

    if os.path.exists(SERVER_CONFIG_FILE):
        try:
            with open(SERVER_CONFIG_FILE, 'r') as f:
                config = json.load(f)
            SERVER_PASSWORD_HASH = config.get('password_hash', '')
            if SERVER_PASSWORD_HASH:
                print(f"  ✓ Loaded server config from '{SERVER_CONFIG_FILE}'")
                return
        except Exception as e:
            print(f"  ⚠ Could not read config file: {e}")

    print("\n" + "="*60)
    print("  FIRST TIME SETUP — Haven Chat Server")
    print("="*60)
    print("No config file found. Let's set up your server password.\n")

    while True:
        password = getpass.getpass("  Enter server password (min 6 chars): ")
        if len(password) < 6:
            print("  ✗ Password must be at least 6 characters. Try again.\n")
            continue
        confirm = getpass.getpass("  Confirm password: ")
        if password != confirm:
            print("  ✗ Passwords do not match. Try again.\n")
            continue
        break

    SERVER_PASSWORD_HASH = hashlib.sha256(password.encode()).hexdigest()
    save_config()
    print(f"\n  ✓ Password set and saved to '{SERVER_CONFIG_FILE}'\n")

def save_config():
    config = {'password_hash': SERVER_PASSWORD_HASH}
    try:
        with open(SERVER_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"⚠ Could not save config: {e}")

# ---------- Network Info ----------

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

def get_external_ip():
    try:
        import urllib.request
        with urllib.request.urlopen('https://api.ipify.org', timeout=4) as resp:
            return resp.read().decode().strip()
    except Exception:
        pass
    try:
        import urllib.request
        with urllib.request.urlopen('https://checkip.amazonaws.com', timeout=4) as resp:
            return resp.read().decode().strip()
    except Exception:
        pass
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
    print(f"  TCP Port   : {TCP_PORT}  (chat, TLS)")
    print(f"  UDP Port   : {UDP_PORT}  (voice)")
    print()
    print(f"  LAN clients connect to  : {local_ip}:{TCP_PORT}")
    print(f"  WAN clients connect to  : {external_ip}:{TCP_PORT}")
    print("  (WAN requires port forwarding on your router)")
    print("  NOTE: Clients must trust the self-signed cert (or you")
    print("        supply a real cert). See TLS notes below.")
    print("="*60 + "\n")

# ---------- Utility ----------

def generate_random_color():
    return random.choice(USER_COLOR_PALETTE)

def sanitize_username(username):
    """Allow alphanumerics, underscores, hyphens only."""
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
        log_action('No existing chat history found, starting fresh')
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
    timestamp = datetime.datetime.now().strftime('%H:%M')
    user_color = None
    with clients_lock:
        if user in clients and user != 'System':
            user_color = clients[user].get('color')
    with history_lock:
        chat_history.append({'user': user, 'text': text, 'timestamp': timestamp, 'color': user_color})
    threading.Thread(target=save_chat_history, daemon=True).start()

def log_action(action):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as f:
        f.write(f'[{timestamp}] {action}\n')
    print(f'[LOG] {action}')

def broadcast_tcp(message, exclude=None):
    with clients_lock:
        for username, info in clients.items():
            if not info.get('authenticated', False):
                continue
            if exclude and info['tcp'] == exclude:
                continue
            try:
                info['tcp'].send((json.dumps(message) + '\n').encode())
            except:
                pass

def broadcast_full_userlist():
    with clients_lock:
        user_list = [
            {'username': uname, 'color': info.get('color', generate_random_color())}
            for uname, info in clients.items()
            if info.get('authenticated', False)
        ]
    broadcast_tcp({'type': 'userlist_full', 'users': user_list})

def send_chat_history(conn):
    try:
        with history_lock:
            history_data = list(chat_history)
        if history_data:
            conn.send((json.dumps({'type': 'chat_history', 'history': history_data}) + '\n').encode())
            log_action(f'Sent {len(history_data)} messages of history to new client')
    except Exception as e:
        log_action(f'Failed to send chat history: {e}')

def send_json(conn, obj):
    conn.send((json.dumps(obj) + '\n').encode())

# ---------- Challenge-Response Auth ----------
# Login flow:
#   1. Client connects, server sends a random nonce.
#   2. Client computes: response = SHA256(nonce + ":" + SHA256(password))
#   3. Server verifies. This means captured traffic cannot be replayed.

def compute_auth_response(nonce, password_hash):
    """Compute the expected challenge response."""
    return hashlib.sha256(f"{nonce}:{password_hash}".encode()).hexdigest()

# ---------- TCP Client Handler ----------

def handle_tcp_client(conn, addr):
    username = None
    buffer = ''
    authenticated = False
    ip = addr[0]

    # Track connection count
    with connections_lock:
        global active_connections
        active_connections += 1
        connections_by_ip[ip] += 1

    try:
        if ip in BANNED_IPS:
            send_json(conn, {'type': 'error', 'message': 'You are banned'})
            return

        # Set login timeout first — must auth within LOGIN_TIMEOUT seconds
        conn.settimeout(LOGIN_TIMEOUT)

        # Send challenge nonce immediately
        nonce = secrets.token_hex(32)
        send_json(conn, {'type': 'challenge', 'nonce': nonce})

        while True:
            try:
                data = conn.recv(4096).decode('utf-8', errors='replace')
            except socket.timeout:
                if not authenticated:
                    log_action(f'Login timeout from {ip}')
                    return
                # After auth, timeout just means idle — keep going
                continue

            if not data:
                break

            buffer += data

            # Prevent memory exhaustion
            if len(buffer) > MAX_BUFFER_SIZE:
                log_action(f'Buffer overflow from {ip} ({username or "unauthenticated"}), dropping connection')
                return

            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue

                mtype = msg.get('type', '')

                # --- Login ---
                if mtype == 'login':
                    provided_response = msg.get('auth_response', '')
                    expected_response = compute_auth_response(nonce, SERVER_PASSWORD_HASH)

                    if not hmac.compare_digest(provided_response, expected_response):
                        send_json(conn, {'type': 'auth_failed'})
                        log_action(f'Failed auth from {ip} (user: {msg.get("username", "unknown")})')
                        return

                    raw_username = msg.get('username', '').strip()
                    username = sanitize_username(raw_username)

                    if not username:
                        send_json(conn, {'type': 'error', 'message': 'Invalid username'})
                        return

                    udp_port = msg.get('udp_port', 0)
                    user_color = msg.get('user_color') or generate_random_color()

                    with clients_lock:
                        if username in clients:
                            send_json(conn, {'type': 'error', 'message': 'Username taken'})
                            return
                        clients[username] = {
                            'tcp': conn,
                            'addr': addr,
                            'udp_port': udp_port,
                            'authenticated': True,
                            'color': user_color
                        }
                        authenticated = True

                    # Switch to longer idle timeout now that we're authed
                    conn.settimeout(RECV_TIMEOUT)

                    send_json(conn, {'type': 'auth_ok', 'user_color': user_color})
                    log_action(f'User {username} joined from {ip}:{addr[1]} (color {user_color})')

                    send_chat_history(conn)

                    with clients_lock:
                        user_list = [
                            {'username': u, 'color': i.get('color')}
                            for u, i in clients.items() if i.get('authenticated')
                        ]
                    send_json(conn, {'type': 'userlist_full', 'users': user_list})
                    broadcast_full_userlist()

                    broadcast_tcp({'type': 'chat', 'user': 'System', 'text': f'{username} has joined the chat'}, exclude=conn)
                    add_to_history('System', f'{username} has joined the chat')
                    continue

                if not authenticated:
                    continue

                # --- Chat ---
                if mtype == 'chat':
                    text = msg.get('text', '')
                    if not isinstance(text, str):
                        continue
                    text = text[:MAX_MESSAGE_LENGTH]
                    if text and username:
                        log_action(f'Chat from {username}: {text}')
                        broadcast_tcp({'type': 'chat', 'user': username, 'text': text}, exclude=conn)
                        add_to_history(username, text)

                # --- Voice ---
                elif mtype == 'voice_start':
                    if username:
                        active_speakers.add(username)
                        broadcast_tcp({'type': 'voice_start', 'user': username})

                elif mtype == 'voice_stop':
                    if username:
                        active_speakers.discard(username)
                        broadcast_tcp({'type': 'voice_stop', 'user': username})

                # --- Change Username ---
                elif mtype == 'change_username':
                    new_username_raw = msg.get('new_username', '').strip()
                    new_username = sanitize_username(new_username_raw)
                    new_color = msg.get('user_color')

                    if not username:
                        continue

                    with clients_lock:
                        if username not in clients:
                            continue
                        current_color = clients[username].get('color', generate_random_color())

                        old_username = username
                        if new_username and new_username != username:
                            if new_username in clients:
                                send_json(conn, {'type': 'error', 'message': 'Username already taken'})
                                continue
                            clients[new_username] = clients.pop(username)
                            clients[new_username]['tcp'] = conn
                            username = new_username
                            if old_username in active_speakers:
                                active_speakers.discard(old_username)
                                active_speakers.add(new_username)

                        clients[username]['color'] = new_color if new_color else current_color

                    send_json(conn, {
                        'type': 'username_changed',
                        'new_username': username,
                        'user_color': clients[username]['color']
                    })

                    log_action(f'{old_username} changed to {username}')
                    broadcast_full_userlist()

                    if new_username and new_username != old_username:
                        broadcast_tcp({'type': 'chat', 'user': 'System',
                                       'text': f'{old_username} is now known as {username}'}, exclude=conn)
                        add_to_history('System', f'{old_username} is now known as {username}')

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
            with clients_lock:
                clients.pop(username, None)
            active_speakers.discard(username)
            log_action(f'User {username} disconnected')
            broadcast_full_userlist()
            broadcast_tcp({'type': 'chat', 'user': 'System', 'text': f'{username} has left the chat'})
            add_to_history('System', f'{username} has left the chat')
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

                    # Check hard limits before spawning thread
                    with connections_lock:
                        if active_connections >= MAX_CONNECTIONS:
                            log_action(f'Connection refused (max {MAX_CONNECTIONS} reached) from {ip}')
                            conn.close()
                            continue
                        if connections_by_ip.get(ip, 0) >= MAX_CONNECTIONS_PER_IP:
                            log_action(f'Connection refused (per-IP limit {MAX_CONNECTIONS_PER_IP}) from {ip}')
                            conn.close()
                            continue

                    threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()
                except ssl.SSLError as e:
                    log_action(f'TLS handshake error: {e}')
                except Exception as e:
                    log_action(f'TCP accept error: {e}')

# ---------- UDP Server ----------

def udp_check_rate_limit(ip):
    """Token bucket: True if packet is allowed, False if rate limited."""
    now = time.monotonic()
    with udp_rate_lock:
        timestamps = udp_rate_tracker[ip]
        # Drop entries outside the window
        while timestamps and now - timestamps[0] > UDP_RATE_WINDOW:
            timestamps.popleft()
        if len(timestamps) >= UDP_RATE_LIMIT:
            return False
        timestamps.append(now)
        return True

def udp_server():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((UDP_HOST, UDP_PORT))

    while True:
        try:
            data, addr = udp_sock.recvfrom(4096)
            ip = addr[0]

            if ip in BANNED_IPS:
                continue

            if not udp_check_rate_limit(ip):
                continue  # Drop packet silently

            with clients_lock:
                sender = None
                for uname, info in clients.items():
                    if not info.get('authenticated'):
                        continue
                    if info['addr'][0] == ip and info['udp_port'] == addr[1]:
                        sender = uname
                        break

                if not sender:
                    continue

                for uname, info in clients.items():
                    if not info.get('authenticated') or uname == sender:
                        continue
                    try:
                        udp_sock.sendto(data, (info['addr'][0], info['udp_port']))
                    except:
                        pass
        except Exception as e:
            log_action(f'UDP error: {e}')

# ---------- Admin Console ----------

def admin_console():
    print("\n" + "="*60)
    print("  HAVEN CHAT SERVER - ADMIN CONSOLE")
    print("="*60)
    print("  /kick <username>     - Kick a user")
    print("  /ban <IP>            - Ban an IP address")
    print("  /unban <IP>          - Unban an IP")
    print("  /password <newpass>  - Change server password")
    print("  /list                - List connected users")
    print("  /history [n]         - Show last n messages (default 10)")
    print("  /stats               - Show connection stats")
    print("  /save                - Save chat history")
    print("  /help                - Show this help")
    print("="*60 + "\n")

    while True:
        try:
            cmd = input().strip()
        except EOFError:
            # stdin closed (e.g., running headless) — just sleep
            time.sleep(60)
            continue

        if cmd.startswith('/kick '):
            username = cmd[6:].strip()
            with clients_lock:
                if username in clients:
                    ip = clients[username]['addr'][0]
                    try:
                        clients[username]['tcp'].send(json.dumps({'type': 'kicked'}).encode() + b'\n')
                        clients[username]['tcp'].close()
                    except:
                        pass
                    del clients[username]
                    active_speakers.discard(username)
                    log_action(f'Admin kicked {username} ({ip})')
                    broadcast_full_userlist()
                    print(f'  ✓ Kicked {username}')
                else:
                    print('  ✗ User not found')

        elif cmd.startswith('/ban '):
            ip = cmd[5:].strip()
            BANNED_IPS.add(ip)
            with clients_lock:
                to_remove = [u for u, i in clients.items() if i['addr'][0] == ip]
                for uname in to_remove:
                    try:
                        clients[uname]['tcp'].send(json.dumps({'type': 'banned'}).encode() + b'\n')
                        clients[uname]['tcp'].close()
                    except:
                        pass
                    del clients[uname]
                    active_speakers.discard(uname)
            log_action(f'Admin banned IP {ip}')
            broadcast_full_userlist()
            print(f'  ✓ Banned {ip}')

        elif cmd.startswith('/unban '):
            ip = cmd[7:].strip()
            if ip in BANNED_IPS:
                BANNED_IPS.remove(ip)
                log_action(f'Admin unbanned IP {ip}')
                print(f'  ✓ Unbanned {ip}')
            else:
                print('  ✗ IP not in ban list')

        elif cmd.startswith('/password '):
            new_password = cmd[10:].strip()
            if len(new_password) < 6:
                print('  ✗ Password must be at least 6 characters')
            else:
                global SERVER_PASSWORD_HASH
                SERVER_PASSWORD_HASH = hashlib.sha256(new_password.encode()).hexdigest()
                save_config()
                log_action('Admin changed server password')
                print(f'  ✓ Password updated. Note: existing sessions remain active.')

        elif cmd == '/list':
            with clients_lock:
                authed = {u: i for u, i in clients.items() if i.get('authenticated')}
            if authed:
                print(f'\n  {"Username":<20} {"IP":<16} {"Color":<12} {"Voice"}')
                print('  ' + '-'*56)
                for uname, info in authed.items():
                    voice = '🔴 live' if uname in active_speakers else '○ idle'
                    print(f'  {uname:<20} {info["addr"][0]:<16} {info.get("color","N/A"):<12} {voice}')
                print()
            else:
                print('  No users connected\n')

        elif cmd == '/stats':
            with connections_lock:
                total = active_connections
                by_ip = dict(connections_by_ip)
            print(f'\n  Active connections: {total} / {MAX_CONNECTIONS}')
            if by_ip:
                print('  By IP:')
                for ip, count in by_ip.items():
                    print(f'    {ip}: {count}')
            print()

        elif cmd.startswith('/history'):
            parts = cmd.split()
            n = 10
            if len(parts) > 1:
                try:
                    n = int(parts[1])
                except:
                    print('  ✗ Invalid number')
                    continue
            with history_lock:
                messages = list(chat_history)[-n:]
            if messages:
                print(f'\n  --- Last {len(messages)} messages ---')
                for m in messages:
                    print(f'  [{m["timestamp"]}] {m["user"]}: {m["text"]}')
                print()
            else:
                print('  No chat history\n')

        elif cmd == '/save':
            save_chat_history()
            print('  ✓ Chat history saved')

        elif cmd == '/help':
            print("\n  /kick <username>     - Kick a user")
            print("  /ban <IP>            - Ban an IP address")
            print("  /unban <IP>          - Unban an IP")
            print("  /password <newpass>  - Change server password")
            print("  /list                - List connected users")
            print("  /history [n]         - Show last n messages (default 10)")
            print("  /stats               - Show connection stats")
            print("  /save                - Save chat history")
            print("  /help                - Show this help\n")

        else:
            if cmd:
                print('  ✗ Unknown command. Type /help for help.')

# ---------- Entry Point ----------

if __name__ == '__main__':
    print("\n" + "⚡"*30)
    print("       HAVEN CHAT SERVER")
    print("⚡"*30 + "\n")

    load_or_create_config()

    if not ensure_tls_cert():
        print("\n  ⚠ WARNING: Could not set up TLS certificate.")
        print("  The server will NOT start without TLS.")
        print("  Run: openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 3650 -nodes -subj '/CN=haven-chat'")
        exit(1)

    print_network_info()
    load_chat_history()

    threading.Thread(target=tcp_server, daemon=True).start()
    threading.Thread(target=udp_server, daemon=True).start()
    threading.Thread(target=admin_console, daemon=True).start()

    print("  Server running. Type /help for admin commands.\n")
    while True:
        time.sleep(1)
