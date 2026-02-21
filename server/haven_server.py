import socket
import threading
import json
import datetime
import time
import hashlib
import secrets
import random
import os
import getpass
from collections import defaultdict, deque

# ---------- Configuration ----------
TCP_HOST = '0.0.0.0'
TCP_PORT = 5000
UDP_HOST = '0.0.0.0'
UDP_PORT = 5001
LOG_FILE = 'server.log'
CHAT_HISTORY_FILE = 'chat_history.json'
SERVER_CONFIG_FILE = 'server_config.json'
MAX_HISTORY_MESSAGES = 1000  # Keep last 1000 messages
BANNED_IPS = set()          # persistent ban list (in memory for now)
# -----------------------------------

# Vibrant color palette for usernames
USER_COLOR_PALETTE = [
    '#ff006e', '#ff4d6d', '#ff6b9d', '#ff8fab',  # Pinks/Reds
    '#00ff88', '#06ffa5', '#4ecca3', '#78e08f',  # Greens
    '#8338ec', '#a855f7', '#c084fc', '#e0aaff',  # Purples
    '#ffd60a', '#ffb703', '#fb8500', '#ff9500',  # Yellows/Oranges
    '#06d6a0', '#00b4d8', '#0096c7', '#48cae4',  # Blues/Cyans
    '#f72585', '#b5179e', '#7209b7', '#560bad'   # Deep Purples/Pinks
]

# Connected clients: {username: {'tcp': socket, 'addr': (ip,port), 'udp_port': int, 'authenticated': bool, 'color': str}}
clients = {}
clients_lock = threading.Lock()

# Track who's currently transmitting voice
active_speakers = set()

# Chat history: list of {user, text, timestamp, color?}
chat_history = deque(maxlen=MAX_HISTORY_MESSAGES)
history_lock = threading.Lock()

# Global password hash (loaded from config)
SERVER_PASSWORD_HASH = ''

# ---------- Config / Password Setup ----------

def load_or_create_config():
    """Load server config from file, or prompt user to create it on first run."""
    global SERVER_PASSWORD_HASH

    if os.path.exists(SERVER_CONFIG_FILE):
        try:
            with open(SERVER_CONFIG_FILE, 'r') as f:
                config = json.load(f)
            SERVER_PASSWORD_HASH = config.get('password_hash', '')
            if SERVER_PASSWORD_HASH:
                print(f"✓ Loaded server config from '{SERVER_CONFIG_FILE}'")
                return
        except Exception as e:
            print(f"⚠ Could not read config file: {e}")

    # First run — prompt for password
    print("\n" + "="*60)
    print("  FIRST TIME SETUP — Haven Chat Server")
    print("="*60)
    print("No config file found. Let's set up your server password.")
    print("This will be saved to 'server_config.json' for future runs.\n")

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
    print(f"\n✓ Password set and saved to '{SERVER_CONFIG_FILE}'\n")

def save_config():
    """Save current server config to file."""
    config = {
        'password_hash': SERVER_PASSWORD_HASH
    }
    try:
        with open(SERVER_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"⚠ Could not save config: {e}")

# ---------- Network Info ----------

def get_local_ip():
    """Get the local network IP of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'

def get_external_ip():
    """Attempt to retrieve the external/public IP."""
    # Try a few lightweight methods without external deps
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
    return 'unavailable (no internet access?)'

def print_network_info():
    """Print local IP, external IP, and ports to the terminal."""
    local_ip = get_local_ip()
    print("  Fetching external IP...")
    external_ip = get_external_ip()

    print("\n" + "="*60)
    print("  SERVER CONNECTIVITY INFO")
    print("="*60)
    print(f"  Local IP   : {local_ip}")
    print(f"  External IP: {external_ip}")
    print(f"  TCP Port   : {TCP_PORT}  (chat)")
    print(f"  UDP Port   : {UDP_PORT}  (voice)")
    print()
    print(f"  LAN clients connect to  : {local_ip}:{TCP_PORT}")
    print(f"  WAN clients connect to  : {external_ip}:{TCP_PORT}")
    print("  (WAN requires port forwarding on your router)")
    print("="*60 + "\n")

# ---------- Utility ----------

def generate_random_color():
    return random.choice(USER_COLOR_PALETTE)

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
        chat_history.append({
            'user': user,
            'text': text,
            'timestamp': timestamp,
            'color': user_color
        })
    def save_async():
        try:
            save_chat_history()
        except Exception as e:
            log_action(f'Error in async save: {e}')
    threading.Thread(target=save_async, daemon=True).start()

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
        user_list = []
        for uname, info in clients.items():
            if info.get('authenticated', False):
                user_list.append({
                    'username': uname,
                    'color': info.get('color', generate_random_color())
                })
    broadcast_tcp({
        'type': 'userlist_full',
        'users': user_list
    })

def send_chat_history(conn):
    try:
        with history_lock:
            history_data = list(chat_history)
        if history_data:
            msg = {'type': 'chat_history', 'history': history_data}
            conn.send((json.dumps(msg) + '\n').encode())
            log_action(f'Sent {len(history_data)} messages of history to new client')
        else:
            log_action('No chat history to send to new client')
    except Exception as e:
        log_action(f'Failed to send chat history to client: {e}')

# ---------- TCP Client Handler ----------

def handle_tcp_client(conn, addr):
    username = None
    buffer = ''
    authenticated = False

    if addr[0] in BANNED_IPS:
        conn.send(json.dumps({'type': 'error', 'message': 'You are banned'}).encode() + b'\n')
        conn.close()
        return

    try:
        while True:
            data = conn.recv(4096).decode()
            if not data:
                break
            buffer += data
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except:
                    continue

                if msg['type'] == 'login':
                    password_hash = msg.get('password_hash', '')
                    if password_hash != SERVER_PASSWORD_HASH:
                        conn.send(json.dumps({'type': 'auth_failed'}).encode() + b'\n')
                        log_action(f'Failed auth attempt from {addr[0]} (user: {msg.get("username", "unknown")})')
                        conn.close()
                        return

                    username = msg['username']
                    udp_port = msg.get('udp_port', 0)
                    user_color = msg.get('user_color') or generate_random_color()

                    with clients_lock:
                        if username in clients:
                            conn.send(json.dumps({'type': 'error', 'message': 'Username taken'}).encode() + b'\n')
                            conn.close()
                            return
                        clients[username] = {
                            'tcp': conn,
                            'addr': addr,
                            'udp_port': udp_port,
                            'authenticated': True,
                            'color': user_color
                        }
                        authenticated = True

                    conn.send(json.dumps({'type': 'auth_ok', 'user_color': user_color}).encode() + b'\n')
                    log_action(f'User {username} joined from {addr[0]}:{addr[1]} with color {user_color}')
                    send_chat_history(conn)

                    with clients_lock:
                        user_list_with_colors = [
                            {'username': uname, 'color': info.get('color', generate_random_color())}
                            for uname, info in clients.items()
                            if info.get('authenticated', False)
                        ]
                    conn.send(json.dumps({'type': 'userlist_full', 'users': user_list_with_colors}).encode() + b'\n')
                    broadcast_full_userlist()

                    try:
                        broadcast_tcp({'type': 'chat', 'user': 'System',
                                       'text': f'{username} has joined the chat'}, exclude=conn)
                        add_to_history('System', f'{username} has joined the chat')
                    except Exception as e:
                        log_action(f'Error broadcasting join message: {e}')
                    continue

                if not authenticated:
                    continue

                if msg['type'] == 'chat':
                    if username:
                        log_action(f'Chat from {username}: {msg["text"]}')
                        broadcast_tcp({'type': 'chat', 'user': username, 'text': msg['text']}, exclude=conn)
                        add_to_history(username, msg['text'])

                elif msg['type'] == 'voice_start':
                    if username:
                        active_speakers.add(username)
                        log_action(f'{username} started voice transmission')
                        broadcast_tcp({'type': 'voice_start', 'user': username})

                elif msg['type'] == 'voice_stop':
                    if username:
                        active_speakers.discard(username)
                        log_action(f'{username} stopped voice transmission')
                        broadcast_tcp({'type': 'voice_stop', 'user': username})

                elif msg['type'] == 'change_username':
                    new_username = msg.get('new_username', '').strip()
                    new_color = msg.get('user_color')

                    if username:
                        with clients_lock:
                            if username not in clients:
                                continue
                            current_info = clients[username]
                            current_color = current_info.get('color', generate_random_color())

                            if new_username and new_username != username:
                                if new_username in clients:
                                    conn.send(json.dumps({'type': 'error',
                                             'message': 'Username already taken'}).encode() + b'\n')
                                    continue
                                clients[new_username] = clients.pop(username)
                                clients[new_username]['tcp'] = conn
                                old_username = username
                                username = new_username
                                if old_username in active_speakers:
                                    active_speakers.remove(old_username)
                                    active_speakers.add(new_username)
                            else:
                                old_username = username

                            clients[username]['color'] = new_color if new_color else current_color

                        conn.send(json.dumps({
                            'type': 'username_changed',
                            'new_username': username,
                            'user_color': clients[username]['color']
                        }).encode() + b'\n')

                        log_action(f'{old_username} changed to {username} with color {clients[username]["color"]}')
                        broadcast_full_userlist()

                        if new_username and new_username != old_username:
                            broadcast_tcp({'type': 'chat', 'user': 'System',
                                           'text': f'{old_username} is now known as {username}'}, exclude=conn)
                            add_to_history('System', f'{old_username} is now known as {username}')

                        broadcast_tcp({'type': 'user_color_changed', 'username': username,
                                       'color': clients[username]['color']})

    except Exception as e:
        import traceback
        log_action(f"TCP client error ({username or 'unknown'}): {e}")
        log_action(f"Traceback: {traceback.format_exc()}")
    finally:
        if username:
            with clients_lock:
                if username in clients:
                    del clients[username]
            active_speakers.discard(username)
            log_action(f'User {username} disconnected')
            broadcast_full_userlist()
            broadcast_tcp({'type': 'chat', 'user': 'System', 'text': f'{username} has left the chat'})
            add_to_history('System', f'{username} has left the chat')
        conn.close()

# ---------- TCP/UDP Servers ----------

def tcp_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((TCP_HOST, TCP_PORT))
        s.listen()
        log_action(f'TCP server listening on {TCP_HOST}:{TCP_PORT}')
        log_action(f'Password authentication enabled (hash: {SERVER_PASSWORD_HASH[:16]}...)')
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True).start()

def udp_server():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((UDP_HOST, UDP_PORT))
    log_action(f'UDP voice server listening on {UDP_HOST}:{UDP_PORT}')
    while True:
        data, addr = udp_sock.recvfrom(2048)
        with clients_lock:
            sender = None
            for uname, info in clients.items():
                if not info.get('authenticated', False):
                    continue
                if info['addr'][0] == addr[0] and info['udp_port'] == addr[1]:
                    sender = uname
                    break
            if not sender:
                continue
            for uname, info in clients.items():
                if not info.get('authenticated', False):
                    continue
                if uname != sender:
                    try:
                        udp_sock.sendto(data, (info['addr'][0], info['udp_port']))
                    except:
                        pass

# ---------- Admin Console ----------

def admin_console():
    print("\n" + "="*60)
    print("HAVEN CHAT SERVER - ADMIN CONSOLE")
    print("="*60)
    print("Commands:")
    print("  /kick <username>     - Kick a user")
    print("  /ban <IP>           - Ban an IP address")
    print("  /unban <IP>         - Unban an IP address")
    print("  /password <newpass> - Change server password")
    print("  /list               - List connected users (with colors)")
    print("  /history [n]        - Show last n messages (default 10)")
    print("  /save               - Manually save chat history")
    print("  /help               - Show this help")
    print("="*60 + "\n")

    while True:
        cmd = input().strip()

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
                    log_action(f'Admin kicked {username} (IP {ip})')
                    broadcast_full_userlist()
                    print(f'✓ Kicked {username}')
                else:
                    print('✗ User not found')

        elif cmd.startswith('/ban '):
            ip = cmd[5:].strip()
            BANNED_IPS.add(ip)
            with clients_lock:
                to_remove = []
                for uname, info in clients.items():
                    if info['addr'][0] == ip:
                        try:
                            info['tcp'].send(json.dumps({'type': 'banned'}).encode() + b'\n')
                            info['tcp'].close()
                        except:
                            pass
                        to_remove.append(uname)
                for uname in to_remove:
                    del clients[uname]
                    active_speakers.discard(uname)
            log_action(f'Admin banned IP {ip}')
            broadcast_full_userlist()
            print(f'✓ Banned {ip}')

        elif cmd.startswith('/unban '):
            ip = cmd[7:].strip()
            if ip in BANNED_IPS:
                BANNED_IPS.remove(ip)
                log_action(f'Admin unbanned IP {ip}')
                print(f'✓ Unbanned {ip}')
            else:
                print('✗ IP not in ban list')

        elif cmd.startswith('/password '):
            new_password = cmd[10:].strip()
            if len(new_password) < 6:
                print('✗ Password must be at least 6 characters')
            else:
                global SERVER_PASSWORD_HASH
                SERVER_PASSWORD_HASH = hashlib.sha256(new_password.encode()).hexdigest()
                save_config()
                log_action('Admin changed server password')
                print(f'✓ Password changed and saved. New hash: {SERVER_PASSWORD_HASH[:16]}...')
                print('  Note: Existing connections remain active')

        elif cmd == '/list':
            with clients_lock:
                if clients:
                    print(f'\n{"Username":<20} {"IP":<15} {"Color":<10} {"Voice":<6}')
                    print('-' * 60)
                    for uname, info in clients.items():
                        color = info.get('color', 'N/A')
                        voice_status = '🔴' if uname in active_speakers else '○'
                        print(f'{uname:<20} {info["addr"][0]:<15} {color:<10} {voice_status:<6}')
                    print()
                else:
                    print('No users connected\n')

        elif cmd.startswith('/history'):
            parts = cmd.split()
            n = 10
            if len(parts) > 1:
                try:
                    n = int(parts[1])
                except:
                    print('✗ Invalid number')
                    continue
            with history_lock:
                messages = list(chat_history)[-n:]
            if messages:
                print(f'\n--- Last {len(messages)} messages ---')
                for msg in messages:
                    print(f'[{msg["timestamp"]}] {msg["user"]}: {msg["text"]}')
                print()
            else:
                print('No chat history\n')

        elif cmd == '/save':
            save_chat_history()
            print('✓ Chat history saved\n')

        elif cmd == '/help':
            print("\nCommands:")
            print("  /kick <username>     - Kick a user")
            print("  /ban <IP>           - Ban an IP address")
            print("  /unban <IP>         - Unban an IP address")
            print("  /password <newpass> - Change server password")
            print("  /list               - List connected users (with colors)")
            print("  /history [n]        - Show last n messages (default 10)")
            print("  /save               - Manually save chat history")
            print("  /help               - Show this help\n")

        else:
            print('✗ Unknown command. Type /help for command list')

# ---------- Entry Point ----------

if __name__ == '__main__':
    print("\n" + "⚡"*30)
    print("      HAVEN CHAT SERVER")
    print("⚡"*30)

    # Load config or run first-time setup
    load_or_create_config()

    # Print network info (local + external IP + ports)
    print_network_info()

    # Load chat history
    load_chat_history()

    # Start TCP, UDP, and admin threads
    threading.Thread(target=tcp_server, daemon=True).start()
    threading.Thread(target=udp_server, daemon=True).start()
    threading.Thread(target=admin_console, daemon=True).start()

    # Keep main thread alive
    while True:
        time.sleep(1)
