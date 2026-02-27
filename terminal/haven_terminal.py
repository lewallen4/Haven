#!/usr/bin/env python3
"""
haven_terminal.py — Haven terminal client for Android (Termux)

Install deps:
    pkg install python
    pip install cryptography   # for PQ crypto (optional but needed for full servers)

Run:
    python haven_terminal.py
    python haven_terminal.py 192.168.1.10 5000 myusername

Controls:
    Type and press Enter to send
    /quit or /q   — disconnect and exit
    /users        — show online users
    /world        — show world lore
    /clear        — clear screen
    /help         — show commands
    Ctrl+C        — exit
"""

import sys, os, socket, ssl, json, hashlib, threading, time, getpass, re
import signal, textwrap, shutil, datetime

# ── Optional PQ crypto (haven_crypto) ────────────────────────────────────────
# Script lives in mobile/, haven_crypto.py is in ../bin/
_HERE   = os.path.dirname(os.path.abspath(__file__))
_ROOT   = os.path.dirname(_HERE)          # one level up → project root
_BIN    = os.path.join(_ROOT, 'bin')      # ../bin/
for _p in [_HERE, _ROOT, _BIN]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

HAVEN_CRYPTO = False
try:
    from haven_crypto import (
        generate_kyber_keypair, kyber_encapsulate,
        generate_x25519_keypair, x25519_exchange,
        derive_session_key, SessionCrypto,
        compute_wire_password_hash, pack_client_hello, unpack_server_hello,
    )
    def _auth_response(nonce, wire_hash):
        from haven_crypto import compute_auth_response
        return compute_auth_response(nonce, wire_hash)
    HAVEN_CRYPTO = True
except ImportError:
    def compute_wire_password_hash(p):
        return hashlib.sha256(p.encode()).hexdigest()
    def _auth_response(nonce, wire_hash):
        return hashlib.sha256(f"{nonce}:{wire_hash}".encode()).hexdigest()
    def pack_client_hello(auth_resp, kyber_ct, x25519_pub, username, udp_port, color):
        return {'type':'client_hello','auth_response':auth_resp,
                'username':username,'udp_port':udp_port,'user_color':color}
    def unpack_server_hello(msg):
        return msg.get('nonce'), None, None
    SessionCrypto = None

SERVER_TCP_PORT = 5000
CONFIG_FILE     = os.path.join(_HERE, '.haven_mobile_config.json')
TOFU_DIR        = os.path.join(_HERE, 'auth')   # mobile/auth/

# ── Terminal width ────────────────────────────────────────────────────────────
def term_width():
    try:    return shutil.get_terminal_size().columns
    except: return 80

# ── ANSI colors ───────────────────────────────────────────────────────────────
RESET  = '\033[0m'
BOLD   = '\033[1m'
DIM    = '\033[2m'
ITALIC = '\033[3m'

def rgb(r, g, b):        return f'\033[38;2;{r};{g};{b}m'
def bg_rgb(r, g, b):     return f'\033[48;2;{r};{g};{b}m'

ACCENT   = rgb(62, 207, 207)   # teal
DIM_C    = rgb(80, 100, 140)
SYS_C    = rgb(100, 120, 160)
ERR_C    = rgb(200, 60, 70)
OK_C     = rgb(62, 207, 130)
WARN_C   = rgb(200, 160, 60)
LORE_C   = rgb(100, 100, 160)
TIME_C   = rgb(60, 80, 120)

def hex_to_rgb(h):
    h = h.lstrip('#')
    if len(h) == 6:
        return int(h[:2],16), int(h[2:4],16), int(h[4:],16)
    return (150, 180, 220)

def color_name(name, color_hex):
    if color_hex:
        r, g, b = hex_to_rgb(color_hex)
        return f'{rgb(r,g,b)}{BOLD}{name}{RESET}'
    return f'{ACCENT}{BOLD}{name}{RESET}'

# ── TOFU cert pinning ─────────────────────────────────────────────────────────
def _cert_fingerprint(der):
    d = hashlib.sha256(der).hexdigest()
    return ':'.join(d[i:i+2] for i in range(0, len(d), 2))

def _tofu_check(host, port, der):
    os.makedirs(TOFU_DIR, exist_ok=True)
    safe = re.sub(r'[^a-zA-Z0-9._-]', '_', host)
    path = os.path.join(TOFU_DIR, f'{safe}_{port}.tofu')
    fp   = _cert_fingerprint(der)

    if os.path.exists(path):
        saved = open(path).read().strip()
        if saved == fp:
            return True
        print(f'\n{ERR_C}{BOLD}⚠ CERTIFICATE CHANGED{RESET}')
        print(f'{ERR_C}Saved:   {saved[:47]}…{RESET}')
        print(f'{ERR_C}Current: {fp[:47]}…{RESET}')
        ans = input('Trust new certificate? (yes/no): ').strip().lower()
        if ans != 'yes':
            return False
        open(path, 'w').write(fp)
        return True

    print(f'\n{WARN_C}New server certificate:{RESET}')
    print(f'  {DIM_C}{fp}{RESET}')
    ans = input('Trust and remember? (yes/no): ').strip().lower()
    if ans == 'yes':
        open(path, 'w').write(fp)
        return True
    return False

# ── Config ────────────────────────────────────────────────────────────────────
def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            return json.load(open(CONFIG_FILE))
    except: pass
    return {}

def save_config(cfg):
    try: json.dump(cfg, open(CONFIG_FILE,'w'), indent=2)
    except: pass

# ── Display ───────────────────────────────────────────────────────────────────
_print_lock = threading.Lock()

def _now():
    return datetime.datetime.now().strftime('%H:%M')

def print_line(line=''):
    with _print_lock:
        print(line)

def print_msg(user, text, ts=None, color=None):
    w      = term_width()
    try:    ts_fmt = datetime.datetime.fromtimestamp(float(ts)).strftime('%H:%M') if ts is not None else _now()
    except: ts_fmt = _now()
    t_str  = f'{TIME_C}{ts_fmt}{RESET} '
    prefix = f'{t_str}{color_name(user, color)}{DIM_C}:{RESET} '
    # Strip ANSI for length calculation
    ansi_re = re.compile(r'\033\[[^m]*m')
    raw_pfx = ansi_re.sub('', prefix)
    indent  = ' ' * len(raw_pfx)
    wrapped = textwrap.wrap(text, w - len(raw_pfx) - 1)
    if not wrapped:
        wrapped = ['']
    with _print_lock:
        print(prefix + wrapped[0])
        for l in wrapped[1:]:
            print(indent + l)

def print_sys(text, color=SYS_C):
    w = term_width()
    lines = textwrap.wrap(text, w - 4)
    with _print_lock:
        for l in lines:
            print(f'{color}  {l}{RESET}')

def print_sep(char='─', color=DIM_C):
    with _print_lock:
        print(f'{color}{char * term_width()}{RESET}')

def print_banner():
    print_sep('═')
    w = term_width()
    title = '✦  HAVEN  ✦'
    pad   = (w - len(title)) // 2
    print(f'{ACCENT}{BOLD}{" " * pad}{title}{RESET}')
    mode = 'PQ ENCRYPTED' if HAVEN_CRYPTO else 'UNENCRYPTED (install haven_crypto)'
    mpad = (w - len(mode)) // 2
    print(f'{DIM_C}{" " * mpad}{mode}{RESET}')
    print_sep('═')

def print_help():
    cmds = [
        ('/quit, /q',  'Disconnect and exit'),
        ('/users',     'Show online users'),
        ('/world',     'Show world lore'),
        ('/clear',     'Clear the screen'),
        ('/help',      'Show this help'),
        ('Ctrl+C',     'Force exit'),
    ]
    print_sys('Commands:', ACCENT)
    for cmd, desc in cmds:
        print(f'  {ACCENT}{cmd:<14}{RESET}{DIM_C}{desc}{RESET}')

# ── Session ───────────────────────────────────────────────────────────────────
class HavenSession:
    def __init__(self):
        self.sock        = None
        self.session     = None   # SessionCrypto
        self.username    = None
        self.color       = None
        self.users       = {}     # name → color
        self.world       = {}
        self.running     = False
        self._buf        = ''
        self._recv_thread= None

    def connect(self, host, port, username, password):
        print_sys(f'Connecting to {host}:{port}…')

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(15)
        raw.connect((host, port))
        sock = ctx.wrap_socket(raw, server_hostname=host)

        # TOFU
        der = sock.getpeercert(binary_form=True)
        if not der:
            sock.close(); raise ConnectionError('No TLS cert from server')
        if not _tofu_check(host, port, der):
            sock.close(); raise ConnectionError('Certificate not trusted')

        # Receive server hello
        self._buf = ''
        server_msg = self._recv_one(sock)
        if server_msg.get('type') == 'error':
            sock.close(); raise ConnectionError(server_msg.get('message','Server error'))
        if server_msg.get('type') not in ('server_hello', 'challenge'):
            sock.close(); raise ConnectionError(f'Unexpected message: {server_msg.get("type")}')

        nonce     = server_msg['nonce']
        wire_hash = compute_wire_password_hash(password)
        auth_resp = _auth_response(nonce, wire_hash)

        # PQ handshake
        session = None
        if HAVEN_CRYPTO and server_msg.get('type') == 'server_hello':
            print_sys('PQ key exchange…', DIM_C)
            try:
                _, kyber_pk, srv_x25519_pub = unpack_server_hello(server_msg)
                kyber_ct, kyber_ss          = kyber_encapsulate(kyber_pk)
                cli_priv, cli_pub           = generate_x25519_keypair()
                ecdh_ss                     = x25519_exchange(cli_priv, srv_x25519_pub)
                session_key                 = derive_session_key(kyber_ss, ecdh_ss, nonce)
                session                     = SessionCrypto(session_key)
                login_msg = pack_client_hello(auth_resp, kyber_ct, cli_pub,
                                              username, 0, self._pick_color())
            except Exception as e:
                sock.close(); raise ConnectionError(f'PQ handshake failed: {e}')
        else:
            if server_msg.get('type') == 'server_hello' and not HAVEN_CRYPTO:
                sock.close()
                raise ConnectionError(
                    'Server requires PQ crypto but haven_crypto is not installed.\n'
                    '  Run: pip install cryptography\n'
                    '  Then place haven_crypto.py alongside this script.')
            login_msg = {'type':'client_hello','auth_response':auth_resp,
                         'username':username,'udp_port':0,
                         'user_color':self._pick_color()}

        sock.send((json.dumps(login_msg)+'\n').encode())
        print_sys('Authenticating…', DIM_C)

        # Wait for auth result
        while True:
            msg = self._recv_one(sock)
            if msg.get('type') == 'auth_ok':
                break
            elif msg.get('type') == 'auth_failed':
                sock.close(); raise ConnectionError('Incorrect password')
            elif msg.get('type') == 'error':
                sock.close(); raise ConnectionError(msg.get('message','Auth error'))

        self.sock     = sock
        self.session  = session
        self.username = username
        self.color    = msg.get('user_color', '#3ecfcf')
        self.running  = True
        sock.settimeout(None)
        print_sys(f'Connected as {color_name(username, self.color)}', OK_C)

        crypto_info = msg.get('crypto', {})
        if crypto_info.get('enabled'):
            print_sys(f'Encryption: {crypto_info.get("kem","?")} + {crypto_info.get("chat_enc","?")}', OK_C)
        else:
            print_sys('No encryption active', WARN_C)

        print_sep()
        return True

    def _recv_one(self, sock=None):
        """Read exactly one newline-delimited JSON message."""
        s = sock or self.sock
        while True:
            if '\n' in self._buf:
                line, self._buf = self._buf.split('\n', 1)
                line = line.strip()
                if not line: continue
                try: return json.loads(line)
                except: continue
            chunk = s.recv(8192).decode('utf-8', errors='replace')
            if not chunk:
                raise ConnectionError('Server closed connection')
            self._buf += chunk

    def _send(self, obj):
        if self.sock:
            try: self.sock.send((json.dumps(obj)+'\n').encode())
            except: pass

    def send_chat(self, text):
        if not self.session:
            print_sys('No crypto session — cannot send', ERR_C)
            return
        try:
            ct = self.session.encrypt_chat(text)
            self._send({'type':'chat','encrypted':True,'ct':ct})
        except Exception as e:
            print_sys(f'Send error: {e}', ERR_C)

    def _pick_color(self):
        import random
        colors = ['#3ecfcf','#7c5cbf','#4a9eff','#cf8f3e','#cf3e7a','#5ecf3e']
        return random.choice(colors)

    def start_recv(self):
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

    def _recv_loop(self):
        try:
            while self.running:
                msg = self._recv_one()
                self._dispatch(msg)
        except ConnectionError:
            if self.running:
                print_sys('\nDisconnected from server.', ERR_C)
                self.running = False
        except Exception as e:
            if self.running:
                print_sys(f'\nReceive error: {e}', ERR_C)
                self.running = False

    def _dispatch(self, msg):
        t = msg.get('type')

        if t == 'chat':
            user = msg.get('user','?')
            ts   = msg.get('timestamp')
            clr  = msg.get('color') or self.users.get(user)
            text = None
            if msg.get('encrypted') and self.session:
                try:   text = self.session.decrypt_chat(msg['ct'])
                except: text = f'{ERR_C}[decryption failed]{RESET}'
            elif msg.get('text'):
                text = msg['text']
            elif msg.get('ct') and self.session:
                try:   text = self.session.decrypt_chat(msg['ct'])
                except: text = f'{ERR_C}[decryption failed]{RESET}'
            else:
                text = f'{DIM_C}[encrypted — no session]{RESET}'
            if text is not None:
                # Mirror main client: hide System messages from non-admins
                if user == 'System':
                    if not (self.username or '').startswith('admin_'):
                        return
                print_msg(user, text, ts, clr)

        elif t == 'chat_history':
            hist = msg.get('history', [])
            if hist:
                hist = hist[-100:]  # last 100 only
                print_sys(f'── last {len(hist)} messages ──', DIM_C)
                for h in hist:
                    # History is stored as plaintext on the server (pre-session)
                    huser = h.get('user','?')
                    # Hide System messages from non-admins (match main client)
                    if huser == 'System':
                        if not (self.username or '').startswith('admin_'):
                            continue
                    text = h.get('text', '')
                    if not text and h.get('ct') and self.session:
                        try:    text = self.session.decrypt_chat(h['ct'])
                        except: text = '[encrypted]'
                    if not text:
                        text = '[encrypted]'
                    print_msg(huser, text, h.get('timestamp'), h.get('color', h.get('user_color')))
                print_sep()

        elif t == 'userlist_full':
            self.users = {u['username']: u.get('color') for u in msg.get('users',[])}

        elif t == 'userlist_update':
            for u in msg.get('users',[]):
                self.users[u['username']] = u.get('color')
            if msg.get('remove'):
                self.users.pop(msg['remove'], None)

        elif t == 'user_join':
            u = msg.get('username')
            if u:
                self.users[u] = msg.get('color')
                print_sys(f'{color_name(u, msg.get("color"))} {SYS_C}joined', SYS_C)

        elif t == 'user_leave':
            u = msg.get('username')
            if u:
                clr = self.users.pop(u, None)
                print_sys(f'{color_name(u, clr)} {SYS_C}left', SYS_C)

        elif t == 'world_update':
            # summary is nested under 'summary' key
            self.world = msg.get('summary', msg)

        elif t == 'world_identity':
            summary = msg.get('summary', {})
            if summary:
                self.world = summary
            identity = msg.get('identity', {})
            if identity:
                self.world['own_identity'] = identity

        elif t in ('voice_start', 'voice_stop'):
            pass  # no voice in terminal client

    def show_users(self):
        if not self.users:
            print_sys('No users online', DIM_C); return
        print_sys(f'{len(self.users)} online:', ACCENT)
        for name, clr in sorted(self.users.items()):
            marker = '▶ ' if name == self.username else '  '
            print(f'  {DIM_C}{marker}{RESET}{color_name(name, clr)}')

    def show_world(self):
        w = self.world
        if not w:
            print_sys('No world data yet — world panel requires Expansion Worlds to be enabled on the server', DIM_C)
            return
        print_sep('─')
        print_sys('✦ THE WORLD', ACCENT)

        # Core stats
        if w.get('season'):
            print(f'  {DIM_C}Season :{RESET} {w["season"]}')
        if w.get('world_age'):
            print(f'  {DIM_C}Age    :{RESET} {w["world_age"]}')
        if w.get('total_souls') is not None:
            print(f'  {DIM_C}Souls  :{RESET} {w["total_souls"]}')
        if w.get('bond_count') is not None:
            print(f'  {DIM_C}Bonds  :{RESET} {w["bond_count"]}')
        if w.get('event_count') is not None:
            print(f'  {DIM_C}Events :{RESET} {w["event_count"]}')

        # Own identity
        ident = w.get('own_identity', {})
        if ident:
            print()
            soul = ident.get('soul_type','mortal')
            icon = {'seraph':'✦','daemon':'⬡','mortal':'·'}.get(soul,'·')
            print(f'  {ACCENT}{icon} {ident.get("title","Unknown")}{RESET}')
            if ident.get('origin'):
                print(f'  {DIM_C}{ident["origin"]}{RESET}')
            if ident.get('faction'):
                print(f'  {DIM_C}{ident["faction"]}{RESET}')
            if ident.get('trait'):
                print(f'  {LORE_C}{ITALIC}"{ident["trait"]}"{RESET}')

        # Recent lore
        recent = w.get('recent_lore', [])
        if recent:
            print()
            print(f'  {DIM_C}Recent lore:{RESET}')
            for event in recent[-5:]:
                if isinstance(event, dict):
                    lines = event.get('text', [])
                    if isinstance(lines, str): lines = [lines]
                elif isinstance(event, str):
                    lines = [event]
                else:
                    lines = []
                for l in lines[:2]:  # first 2 lines of each event
                    if l: print(f'  {LORE_C}{ITALIC}{l}{RESET}')

        print_sep('─')

    def disconnect(self):
        self.running = False
        try: self.sock.close()
        except: pass


# ── Input loop ────────────────────────────────────────────────────────────────
def input_loop(session):
    """Read input lines and dispatch commands or chat."""
    while session.running:
        try:
            # Simple input — works reliably on Termux
            line = input()
        except EOFError:
            break
        except KeyboardInterrupt:
            break

        line = line.strip()
        if not line:
            continue

        if line.lower() in ('/quit', '/q', '/exit'):
            break
        elif line.lower() == '/users':
            session.show_users()
        elif line.lower() == '/world':
            session.show_world()
        elif line.lower() == '/clear':
            with _print_lock:
                os.system('clear' if os.name != 'nt' else 'cls')
            print_banner()
        elif line.lower() in ('/help', '/?'):
            print_help()
        elif line.startswith('/'):
            print_sys(f'Unknown command: {line}  (type /help)', WARN_C)
        else:
            session.send_chat(line)

    session.disconnect()
    print_sys('Goodbye.', DIM_C)


# ── Login prompt ──────────────────────────────────────────────────────────────
def prompt_login(args):
    cfg = load_config()

    if len(args) >= 3:
        host     = args[0]
        port     = int(args[1])
        username = args[2]
    else:
        print()
        default_host = cfg.get('host', '')
        default_user = cfg.get('username', '')

        if default_host:
            h = input(f'Server [{default_host}]: ').strip() or default_host
        else:
            h = input('Server (host:port or host): ').strip()
            if not h:
                print_sys('Server required.', ERR_C); sys.exit(1)

        if ':' in h:
            parts = h.rsplit(':', 1)
            host  = parts[0]
            port  = int(parts[1])
        else:
            host = h
            port = SERVER_TCP_PORT

        if default_user:
            u = input(f'Username [{default_user}]: ').strip() or default_user
        else:
            u = input('Username: ').strip()
        username = u

    password = getpass.getpass('Password: ')
    return host, port, username, password


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    print_banner()

    if not HAVEN_CRYPTO:
        print_sys('haven_crypto not found — install cryptography and add haven_crypto.py', WARN_C)
        print_sys('Most Haven servers require PQ crypto. Connection will likely fail.', WARN_C)
        print_sep()

    args = sys.argv[1:]  # [host, port, username]

    while True:
        try:
            host, port, username, password = prompt_login(args)
        except (KeyboardInterrupt, EOFError):
            print(); sys.exit(0)

        session = HavenSession()
        try:
            session.connect(host, port, username, password)
        except ConnectionError as e:
            print_sys(f'Connection failed: {e}', ERR_C)
            retry = input('Retry? (y/n): ').strip().lower()
            if retry != 'y':
                sys.exit(1)
            args = []  # re-prompt
            continue

        # Save successful config
        save_config({'host': host, 'port': port, 'username': username})

        print_help()
        print()

        session.start_recv()
        input_loop(session)
        break


if __name__ == '__main__':
    main()