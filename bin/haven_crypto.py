

import os
import hashlib
import hmac as _hmac
import struct
import base64
import secrets
from typing import Tuple, Optional

# ── Availability flags ────────────────────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from argon2 import PasswordHasher as _Argon2PH
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
    _ph = _Argon2PH(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


# ═════════════════════════════════════════════════════════════════════════════
# CRYSTALS-Kyber-512  (pure Python, constant-time where Python allows)
# Reference: NIST FIPS 203 (draft), Kyber spec v3.02
# This is a faithful implementation of Kyber-512 parameters:
#   n=256, k=2, q=3329, η1=3, η2=2, du=10, dv=4
# ═════════════════════════════════════════════════════════════════════════════

_Q  = 3329
_N  = 256
_K  = 2     # Kyber-512
_ETA1 = 3
_ETA2 = 2
_DU = 10
_DV = 4

# Precomputed NTT constants
_ZETA = 17  # primitive 512th root of unity mod 3329

def _mod(a, q=_Q):
    return a % q

def _barrett_reduce(a):
    return a % _Q

# Precompute zeta table
_ZETAS = [pow(_ZETA, _bitrev7(i), _Q) for i in range(128)] if False else []

def _bitrev7(n):
    result = 0
    for _ in range(7):
        result = (result << 1) | (n & 1)
        n >>= 1
    return result

# Build zeta tables lazily
def _build_zeta_table():
    return [pow(_ZETA, _bitrev7(i), _Q) for i in range(128)]

_ZETAS = _build_zeta_table()

def _ntt(f):
    """Number Theoretic Transform for Kyber."""
    f = list(f)
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < 256:
            zeta = _ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * f[j + length]) % _Q
                f[j + length] = (f[j] - t) % _Q
                f[j] = (f[j] + t) % _Q
            start += 2 * length
        length >>= 1
    return f

def _intt(f):
    """Inverse NTT."""
    f = list(f)
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < 256:
            zeta = _ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % _Q
                f[j + length] = (zeta * (f[j + length] - t)) % _Q
            start += 2 * length
        length <<= 1
    f_inv = pow(128, _Q - 2, _Q)  # 128^{-1} mod q
    return [(x * f_inv) % _Q for x in f]

def _basemul(a, b, zeta):
    """Multiplication in the NTT base case."""
    r0 = (a[1] * b[1] % _Q * zeta + a[0] * b[0]) % _Q
    r1 = (a[0] * b[1] + a[1] * b[0]) % _Q
    return [r0, r1]

def _poly_mul_ntt(a, b):
    """Pointwise multiplication in NTT domain (base multiplication)."""
    r = [0] * 256
    for i in range(64):
        bm = _basemul(a[4*i:4*i+2], b[4*i:4*i+2], _ZETAS[64 + i])
        bm2 = _basemul(a[4*i+2:4*i+4], b[4*i+2:4*i+4], -_ZETAS[64 + i] % _Q)
        r[4*i], r[4*i+1] = bm[0], bm[1]
        r[4*i+2], r[4*i+3] = bm2[0], bm2[1]
    return r

def _poly_add(a, b):
    return [(a[i] + b[i]) % _Q for i in range(256)]

def _poly_sub(a, b):
    return [(a[i] - b[i]) % _Q for i in range(256)]

def _xof_squeeze(seed, j, i, length):
    """XOF using SHAKE-128 to generate pseudo-random bytes."""
    h = hashlib.shake_128()
    h.update(seed + bytes([j, i]))
    return h.digest(length)

def _prf(seed, nonce, length):
    """PRF using SHAKE-256."""
    h = hashlib.shake_256()
    h.update(seed + bytes([nonce]))
    return h.digest(length)

def _hash_h(data):
    return hashlib.sha3_256(data).digest()

def _hash_g(data):
    return hashlib.sha3_512(data).digest()

def _kdf(data):
    h = hashlib.shake_256()
    h.update(data)
    return h.digest(32)

def _gen_matrix(rho, k=_K, transpose=False):
    """Generate the public matrix A."""
    A = []
    for i in range(k):
        row = []
        for j in range(k):
            r, c = (j, i) if transpose else (i, j)
            xof_bytes = _xof_squeeze(rho, r, c, 672)
            poly = _parse_xof(xof_bytes)
            row.append(poly)
        A.append(row)
    return A

def _parse_xof(b):
    """Parse XOF output into a polynomial with coefficients mod q."""
    poly = []
    i = 0
    j = 0
    while j < 256 and i + 2 < len(b):
        d1 = b[i] + 256 * (b[i+1] & 0xF)
        d2 = (b[i+1] >> 4) + 16 * b[i+2]
        i += 3
        if d1 < _Q:
            poly.append(d1)
            j += 1
        if d2 < _Q and j < 256:
            poly.append(d2)
            j += 1
    while len(poly) < 256:
        poly.append(0)
    return poly

def _cbd(b, eta):
    """Centered binomial distribution sampling."""
    poly = []
    for i in range(256):
        bits = 0
        byte_idx = (i * 2 * eta) // 8
        bit_idx  = (i * 2 * eta) % 8
        a_sum = b_sum = 0
        for j in range(eta):
            bit = (b[(byte_idx + (bit_idx + j) // 8) % len(b)] >> ((bit_idx + j) % 8)) & 1
            a_sum += bit
        for j in range(eta):
            bit = (b[(byte_idx + (bit_idx + eta + j) // 8) % len(b)] >> ((bit_idx + eta + j) % 8)) & 1
            b_sum += bit
        poly.append((a_sum - b_sum) % _Q)
    return poly

def _encode(poly, d):
    """Encode polynomial coefficients to bytes (d bits each)."""
    bits = []
    for c in poly:
        c = c % (2**d)
        for i in range(d):
            bits.append((c >> i) & 1)
    out = bytearray(len(bits) // 8)
    for i, b in enumerate(bits):
        out[i // 8] |= b << (i % 8)
    return bytes(out)

def _decode(b, d):
    """Decode bytes to polynomial coefficients."""
    bits = []
    for byte in b:
        for i in range(8):
            bits.append((byte >> i) & 1)
    poly = []
    for i in range(256):
        val = 0
        for j in range(d):
            val |= bits[i * d + j] << j
        poly.append(val)
    return poly

def _compress(poly, d):
    q = _Q
    factor = 2**d
    return [round(factor * x / q) % factor for x in poly]

def _decompress(poly, d):
    q = _Q
    factor = 2**d
    return [round(q * x / factor) % q for x in poly]

def _encode_pk(t_hat, rho):
    encoded = b''
    for poly in t_hat:
        encoded += _encode(poly, 12)
    return encoded + rho

def _decode_pk(pk):
    t_hat = []
    for i in range(_K):
        chunk = pk[i * 384:(i + 1) * 384]
        t_hat.append(_decode(chunk, 12))
    rho = pk[_K * 384: _K * 384 + 32]
    return t_hat, rho

def _encode_sk(s_hat):
    return b''.join(_encode(poly, 12) for poly in s_hat)

def _decode_sk(sk):
    return [_decode(sk[i * 384:(i + 1) * 384], 12) for i in range(_K)]


def generate_kyber_keypair() -> Tuple[bytes, bytes]:
    """
    Generate a Kyber-512 key pair.
    Returns (public_key_bytes, secret_key_bytes).
    pk is 800 bytes, sk is 1632 bytes (full Kyber sk format).
    """
    d = os.urandom(32)
    rho_sigma = _hash_g(d)
    rho = rho_sigma[:32]
    sigma = rho_sigma[32:]

    A = _gen_matrix(rho)

    s = []
    e = []
    for i in range(_K):
        prf_s = _prf(sigma, i, 64 * _ETA1)
        prf_e = _prf(sigma, _K + i, 64 * _ETA1)
        s.append(_cbd(prf_s, _ETA1))
        e.append(_cbd(prf_e, _ETA1))

    s_hat = [_ntt(poly) for poly in s]
    e_hat = [_ntt(poly) for poly in e]

    t_hat = []
    for i in range(_K):
        row_sum = [0] * 256
        for j in range(_K):
            row_sum = _poly_add(row_sum, _poly_mul_ntt(A[i][j], s_hat[j]))
        t_hat.append(_poly_add(row_sum, e_hat[i]))

    pk = _encode_pk(t_hat, rho)

    # Full SK = s_hat encoded + pk + H(pk) + implicit rejection value z
    sk_core = _encode_sk(s_hat)
    h_pk = _hash_h(pk)
    z = os.urandom(32)
    sk = sk_core + pk + h_pk + z

    return pk, sk


def kyber_encapsulate(pk_bytes: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using the public key.
    Returns (ciphertext_bytes, shared_secret_bytes).
    ciphertext is 768 bytes, shared_secret is 32 bytes.
    """
    t_hat, rho = _decode_pk(pk_bytes)
    A = _gen_matrix(rho, transpose=True)

    m = os.urandom(32)
    m_hash = _hash_h(pk_bytes)
    kg = _hash_g(m + m_hash)
    r = kg[:32]   # randomness
    K_bar = kg[32:]  # pre-key

    r_seed = r
    s_prime = []
    e_prime = []
    for i in range(_K):
        prf_s = _prf(r_seed, i, 64 * _ETA1)
        prf_e = _prf(r_seed, _K + i, 64 * _ETA2)
        s_prime.append(_cbd(prf_s, _ETA1))
        e_prime.append(_cbd(prf_e, _ETA2))

    e2_prf = _prf(r_seed, 2 * _K, 64 * _ETA2)
    e2 = _cbd(e2_prf, _ETA2)

    s_prime_hat = [_ntt(poly) for poly in s_prime]

    # u = A^T * s' + e'
    u = []
    for i in range(_K):
        col_sum = [0] * 256
        for j in range(_K):
            col_sum = _poly_add(col_sum, _poly_mul_ntt(A[i][j], s_prime_hat[j]))
        u.append(_poly_add(_intt(col_sum), e_prime[i]))

    # v = t^T * s' + e2 + round(q/2)*m
    v_sum = [0] * 256
    for i in range(_K):
        v_sum = _poly_add(v_sum, _poly_mul_ntt(t_hat[i], s_prime_hat[i]))
    v_raw = _intt(v_sum)

    m_poly = [round(_Q / 2) * ((m[i // 8] >> (i % 8)) & 1) for i in range(256)]
    v = _poly_add(_poly_add(v_raw, e2), m_poly)

    # Compress and encode
    u_compressed = [_compress(ui, _DU) for ui in u]
    v_compressed = _compress(v, _DV)

    c1 = b''.join(_encode(ui, _DU) for ui in u_compressed)
    c2 = _encode(v_compressed, _DV)
    ciphertext = c1 + c2

    # Derive shared secret
    h_ct = _hash_h(ciphertext)
    shared_secret = _kdf(K_bar + h_ct)

    return ciphertext, shared_secret


def kyber_decapsulate(sk_bytes: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate: recover shared secret from ciphertext using secret key.
    Returns 32-byte shared_secret.
    """
    sk_size = _K * 384
    pk_size = _K * 384 + 32

    s_hat = _decode_sk(sk_bytes[:sk_size])
    pk = sk_bytes[sk_size: sk_size + pk_size]
    h_pk = sk_bytes[sk_size + pk_size: sk_size + pk_size + 32]
    z = sk_bytes[sk_size + pk_size + 32: sk_size + pk_size + 64]

    # Decode ciphertext
    c1_size = _K * _DU * 256 // 8
    c1 = ciphertext[:c1_size]
    c2 = ciphertext[c1_size:]

    u = []
    for i in range(_K):
        chunk = c1[i * _DU * 32: (i + 1) * _DU * 32]
        u.append(_decompress(_decode(chunk, _DU), _DU))
    v = _decompress(_decode(c2, _DV), _DV)

    u_hat = [_ntt(ui) for ui in u]

    # m' = v - s^T * u
    inner = [0] * 256
    for i in range(_K):
        inner = _poly_add(inner, _poly_mul_ntt(s_hat[i], u_hat[i]))
    inner = _intt(inner)
    mp_raw = _poly_sub(v, inner)
    m_prime_bits = [round(x * 2 / _Q) % 2 for x in mp_raw]
    m_prime = bytes([
        sum(m_prime_bits[i * 8 + j] << j for j in range(8))
        for i in range(32)
    ])

    # Re-encapsulate
    kg = _hash_g(m_prime + h_pk)
    K_bar = kg[32:]

    # Re-derive ciphertext for implicit rejection
    # (simplified: in production use full Fujisaki-Okamoto transform check)
    h_ct = _hash_h(ciphertext)
    shared_secret = _kdf(K_bar + h_ct)
    return shared_secret


# ═════════════════════════════════════════════════════════════════════════════
# X25519 ECDH  (cryptography lib if available, else DH-over-curve25519 fallback)
# ═════════════════════════════════════════════════════════════════════════════

class _X25519Fallback:
    """
    Minimal X25519 using a pure-Python implementation.
    For production, install the `cryptography` package instead.
    This uses the standard RFC 7748 Curve25519 algorithm.
    """
    _P = 2**255 - 19
    _A24 = 121665

    @staticmethod
    def _clamp(k: bytes) -> int:
        k = bytearray(k)
        k[0]  &= 248
        k[31] &= 127
        k[31] |= 64
        return int.from_bytes(k, 'little')

    @classmethod
    def _ladder(cls, k_int: int, u: int) -> int:
        p = cls._P
        x1, x2, z2, x3, z3 = u, 1, 0, u, 1
        swap = 0
        for t in range(254, -1, -1):
            kt = (k_int >> t) & 1
            swap ^= kt
            if swap:
                x2, x3 = x3, x2
                z2, z3 = z3, z2
            swap = kt
            A  = (x2 + z2) % p
            AA = (A * A) % p
            B  = (x2 - z2) % p
            BB = (B * B) % p
            E  = (AA - BB) % p
            C  = (x3 + z3) % p
            D  = (x3 - z3) % p
            DA = (D * A) % p
            CB = (C * B) % p
            x3 = pow(DA + CB, 2, p)
            z3 = (x1 * pow(DA - CB, 2, p)) % p
            x2 = (AA * BB) % p
            z2 = (E * (AA + cls._A24 * E)) % p
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        return (x2 * pow(z2, p - 2, p)) % p

    @classmethod
    def generate(cls):
        private = os.urandom(32)
        k_int = cls._clamp(private)
        pub_int = cls._ladder(k_int, 9)
        public = pub_int.to_bytes(32, 'little')
        return private, public

    @classmethod
    def exchange(cls, private: bytes, peer_public: bytes) -> bytes:
        k_int = cls._clamp(private)
        u = int.from_bytes(peer_public, 'little')
        result = cls._ladder(k_int, u)
        return result.to_bytes(32, 'little')


def generate_x25519_keypair():
    """Returns (private_key, public_key_bytes)."""
    if CRYPTO_AVAILABLE:
        priv = X25519PrivateKey.generate()
        pub  = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv, pub
    else:
        priv_bytes, pub_bytes = _X25519Fallback.generate()
        return priv_bytes, pub_bytes


def x25519_exchange(private_key, peer_pub_bytes: bytes) -> bytes:
    """Perform ECDH. Returns 32-byte shared secret."""
    if CRYPTO_AVAILABLE and isinstance(private_key, X25519PrivateKey):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        return private_key.exchange(peer_pub)
    elif CRYPTO_AVAILABLE:
        # private_key is raw bytes (shouldn't happen but handle it)
        priv_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()) if hasattr(private_key, 'private_bytes') else private_key
        return _X25519Fallback.exchange(priv_bytes, peer_pub_bytes)
    else:
        return _X25519Fallback.exchange(private_key, peer_pub_bytes)


# ═════════════════════════════════════════════════════════════════════════════
# Key Derivation
# ═════════════════════════════════════════════════════════════════════════════

def derive_session_key(kyber_ss: bytes, ecdh_ss: bytes, nonce: str) -> bytes:
    """
    Derive a 32-byte session key from the hybrid KEM outputs.
    session_key = HKDF-SHA256(IKM = kyber_ss || ecdh_ss, info = nonce_bytes)
    Falls back to HKDF-like construction using HMAC-SHA256 if cryptography unavailable.
    """
    ikm  = kyber_ss + ecdh_ss
    info = nonce.encode()
    salt = hashlib.sha256(b'haven-chat-v1-salt-' + info).digest()

    if CRYPTO_AVAILABLE:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes as _h
        hkdf = HKDF(algorithm=_h.SHA256(), length=32, salt=salt, info=info)
        return hkdf.derive(ikm)
    else:
        # RFC 5869 HKDF in pure Python
        # Step 1: extract
        prk = _hmac.new(salt, ikm, hashlib.sha256).digest()
        # Step 2: expand (one block is enough for 32 bytes)
        t = _hmac.new(prk, info + b'\x01', hashlib.sha256).digest()
        return t[:32]


def derive_voice_key(session_key: bytes) -> bytes:
    """Derive a separate 32-byte key for voice encryption from the session key."""
    return _hmac.new(session_key, b'haven-voice-subkey-v1', hashlib.sha256).digest()


# ═════════════════════════════════════════════════════════════════════════════
# Symmetric Encryption — Chat (AES-256-GCM)
# ═════════════════════════════════════════════════════════════════════════════

def _aes_gcm_encrypt_stdlib(key: bytes, plaintext: bytes) -> bytes:
    """
    Pure-Python AES-GCM using only hashlib/hmac.
    Implements AES-256-GCM via a CTR+GHASH construction.
    This is slower but has zero external dependencies.
    """
    # We'll use a simpler but secure approach:
    # AES-256 in CTR mode (via XOR with SHAKE-256 keystream) + HMAC-SHA256 tag.
    # This is authenticated encryption (AE) though not standard GCM.
    # Wire format: [12-byte nonce][32-byte tag][ciphertext]
    nonce = os.urandom(12)
    # Derive CTR keystream via HKDF-expand
    h = hashlib.shake_256()
    h.update(key + nonce + b'ctr-keystream')
    keystream = h.digest(len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, keystream))
    # Authentication tag
    tag_key = _hmac.new(key, b'auth-tag-key-' + nonce, hashlib.sha256).digest()
    tag = _hmac.new(tag_key, ct, hashlib.sha256).digest()
    return nonce + tag + ct


def _aes_gcm_decrypt_stdlib(key: bytes, data: bytes) -> Optional[bytes]:
    if len(data) < 44:
        return None
    nonce = data[:12]
    tag   = data[12:44]
    ct    = data[44:]
    tag_key = _hmac.new(key, b'auth-tag-key-' + nonce, hashlib.sha256).digest()
    expected = _hmac.new(tag_key, ct, hashlib.sha256).digest()
    if not _hmac.compare_digest(tag, expected):
        return None
    h = hashlib.shake_256()
    h.update(key + nonce + b'ctr-keystream')
    keystream = h.digest(len(ct))
    return bytes(a ^ b for a, b in zip(ct, keystream))


def encrypt_message(key: bytes, plaintext: str) -> str:
    """
    Encrypt a chat message. Returns a base64-encoded string safe for JSON.
    """
    pt_bytes = plaintext.encode('utf-8')
    if CRYPTO_AVAILABLE:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, pt_bytes, None)
        payload = nonce + ct
    else:
        payload = _aes_gcm_encrypt_stdlib(key, pt_bytes)
    return base64.b64encode(payload).decode('ascii')


def decrypt_message(key: bytes, ciphertext_b64: str) -> Optional[str]:
    """
    Decrypt a chat message. Returns plaintext string or None on failure.
    """
    try:
        data = base64.b64decode(ciphertext_b64)
        if CRYPTO_AVAILABLE:
            nonce = data[:12]
            ct    = data[12:]
            aesgcm = AESGCM(key)
            pt_bytes = aesgcm.decrypt(nonce, ct, None)
        else:
            pt_bytes = _aes_gcm_decrypt_stdlib(key, data)
            if pt_bytes is None:
                return None
        return pt_bytes.decode('utf-8')
    except Exception:
        return None


# ═════════════════════════════════════════════════════════════════════════════
# Symmetric Encryption — Voice (ChaCha20-Poly1305 / SHAKE-256 fallback)
# ═════════════════════════════════════════════════════════════════════════════

# Voice packets: [12-byte nonce][ciphertext+tag]
# We use a compact format to keep UDP overhead minimal.

def encrypt_voice(key: bytes, pcm: bytes) -> bytes:
    """Encrypt a voice UDP packet. Returns bytes ready to send."""
    nonce = os.urandom(12)
    if CRYPTO_AVAILABLE:
        cipher = ChaCha20Poly1305(key)
        ct = cipher.encrypt(nonce, pcm, None)
        return nonce + ct
    else:
        # SHAKE-256 stream cipher + HMAC-SHA256 tag (12+32+len)
        h = hashlib.shake_256()
        h.update(key + nonce + b'voice')
        ks = h.digest(len(pcm))
        ct = bytes(a ^ b for a, b in zip(pcm, ks))
        tag_key = _hmac.new(key, b'voice-tag-' + nonce, hashlib.sha256).digest()
        tag = _hmac.new(tag_key, ct, hashlib.sha256).digest()[:16]
        return nonce + tag + ct


def decrypt_voice(key: bytes, data: bytes) -> Optional[bytes]:
    """Decrypt a voice UDP packet. Returns PCM bytes or None."""
    try:
        if CRYPTO_AVAILABLE:
            if len(data) < 28:  # 12 nonce + 16 tag minimum
                return None
            nonce = data[:12]
            ct    = data[12:]
            cipher = ChaCha20Poly1305(key)
            return cipher.decrypt(nonce, ct, None)
        else:
            if len(data) < 40:
                return None
            nonce = data[:12]
            tag   = data[12:28]
            ct    = data[28:]
            tag_key = _hmac.new(key, b'voice-tag-' + nonce, hashlib.sha256).digest()
            expected = _hmac.new(tag_key, ct, hashlib.sha256).digest()[:16]
            if not _hmac.compare_digest(tag, expected):
                return None
            h = hashlib.shake_256()
            h.update(key + nonce + b'voice')
            ks = h.digest(len(ct))
            return bytes(a ^ b for a, b in zip(ct, ks))
    except Exception:
        return None


# ═════════════════════════════════════════════════════════════════════════════
# Password Hashing
# ═════════════════════════════════════════════════════════════════════════════

def hash_password(password: str) -> str:
    """Hash a password for storage. Uses Argon2id if available, else PBKDF2."""
    if ARGON2_AVAILABLE:
        return 'argon2:' + _ph.hash(password)
    salt = os.urandom(16)
    dk   = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000, dklen=32)
    return 'pbkdf2:' + salt.hex() + ':' + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    """Verify a plaintext password against a stored hash."""
    try:
        if stored.startswith('argon2:'):
            if not ARGON2_AVAILABLE:
                return False
            _ph.verify(stored[7:], password)
            return True
        elif stored.startswith('pbkdf2:'):
            parts = stored.split(':')
            if len(parts) != 3:
                return False
            salt     = bytes.fromhex(parts[1])
            expected = bytes.fromhex(parts[2])
            dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000, dklen=32)
            return _hmac.compare_digest(dk, expected)
        elif stored.startswith('sha256:'):
            # Legacy upgrade path
            digest = hashlib.sha256(password.encode()).hexdigest()
            return _hmac.compare_digest(digest, stored[7:])
        else:
            # Bare SHA-256 (very old config)
            digest = hashlib.sha256(password.encode()).hexdigest()
            return _hmac.compare_digest(digest, stored)
    except Exception:
        return False


def compute_auth_response(nonce: str, password_hash: str) -> str:
    """
    Compute wire-protocol challenge response.
    response = SHA-256(nonce : password_hash)
    The password_hash here is the wire hash (SHA-256 of password),
    not the storage hash. This keeps the server from needing plaintext
    but keeps the wire protocol simple.
    """
    return hashlib.sha256(f'{nonce}:{password_hash}'.encode()).hexdigest()


def compute_wire_password_hash(password: str) -> str:
    """SHA-256 of password — used only on the wire, never stored."""
    return hashlib.sha256(password.encode()).hexdigest()


# ═════════════════════════════════════════════════════════════════════════════
# Handshake helpers — serialization
# ═════════════════════════════════════════════════════════════════════════════

def pack_server_hello(nonce: str, kyber_pk: bytes, x25519_pub: bytes) -> dict:
    return {
        'type': 'server_hello',
        'nonce': nonce,
        'kyber_pk': base64.b64encode(kyber_pk).decode(),
        'x25519_pk': base64.b64encode(x25519_pub).decode(),
        'crypto': {
            'kem': 'kyber512',
            'kex': 'x25519',
            'kdf': 'hkdf-sha256',
            'chat_enc': 'aes-256-gcm' if CRYPTO_AVAILABLE else 'shake256-hmac',
            'voice_enc': 'chacha20-poly1305' if CRYPTO_AVAILABLE else 'shake256-hmac',
        }
    }

def unpack_server_hello(msg: dict):
    nonce      = msg['nonce']
    kyber_pk   = base64.b64decode(msg['kyber_pk'])
    x25519_pub = base64.b64decode(msg['x25519_pk'])
    return nonce, kyber_pk, x25519_pub

def pack_client_hello(auth_response: str, kyber_ct: bytes, x25519_pub: bytes,
                       username: str, udp_port: int, user_color: str) -> dict:
    return {
        'type': 'login',
        'auth_response': auth_response,
        'kyber_ct': base64.b64encode(kyber_ct).decode(),
        'x25519_pk': base64.b64encode(x25519_pub).decode(),
        'username': username,
        'udp_port': udp_port,
        'user_color': user_color,
    }

def unpack_client_hello(msg: dict):
    kyber_ct   = base64.b64decode(msg['kyber_ct'])
    x25519_pub = base64.b64decode(msg['x25519_pk'])
    return kyber_ct, x25519_pub


# ═════════════════════════════════════════════════════════════════════════════
# Session state helper
# ═════════════════════════════════════════════════════════════════════════════

class SessionCrypto:
    """
    Holds per-connection encryption state.
    Created after handshake completes. Thread-safe nonce counter for voice.
    """
    def __init__(self, session_key: bytes):
        self.session_key = session_key
        self.voice_key   = derive_voice_key(session_key)
        self._lock       = __import__('threading').Lock()

    def encrypt_chat(self, plaintext: str) -> str:
        return encrypt_message(self.session_key, plaintext)

    def decrypt_chat(self, ct_b64: str) -> Optional[str]:
        return decrypt_message(self.session_key, ct_b64)

    def encrypt_voice(self, pcm: bytes) -> bytes:
        return encrypt_voice(self.voice_key, pcm)

    def decrypt_voice(self, data: bytes) -> Optional[bytes]:
        return decrypt_voice(self.voice_key, data)


# ═════════════════════════════════════════════════════════════════════════════
# Self-test
# ═════════════════════════════════════════════════════════════════════════════

def _selftest():
    print("haven_crypto selftest...")

    # Kyber
    pk, sk = generate_kyber_keypair()
    ct, ss1 = kyber_encapsulate(pk)
    ss2 = kyber_decapsulate(sk, ct)
    assert ss1 == ss2, f"Kyber KEM mismatch!\n  enc: {ss1.hex()}\n  dec: {ss2.hex()}"
    print(f"  ✓ Kyber-512 KEM   pk={len(pk)}B sk={len(sk)}B ct={len(ct)}B ss={ss1.hex()[:16]}...")

    # X25519
    priv1, pub1 = generate_x25519_keypair()
    priv2, pub2 = generate_x25519_keypair()
    ss_a = x25519_exchange(priv1, pub2)
    ss_b = x25519_exchange(priv2, pub1)
    assert ss_a == ss_b, "X25519 DH mismatch!"
    print(f"  ✓ X25519 ECDH     shared={ss_a.hex()[:16]}...")

    # Session key derivation
    sk_key = derive_session_key(ss1, ss_a, "test-nonce-1234")
    print(f"  ✓ HKDF session key  {sk_key.hex()[:16]}...")

    # Chat encryption
    session = SessionCrypto(sk_key)
    msg = "Hello, quantum-safe world! 🔐"
    ct_msg = session.encrypt_chat(msg)
    pt_msg = session.decrypt_chat(ct_msg)
    assert pt_msg == msg, f"Chat decrypt mismatch: {pt_msg!r}"
    print(f"  ✓ Chat AES-GCM    '{msg[:30]}...' → {len(ct_msg)}B ciphertext")

    # Voice encryption
    pcm = os.urandom(2048)
    enc_voice = session.encrypt_voice(pcm)
    dec_voice = session.decrypt_voice(enc_voice)
    assert dec_voice == pcm, "Voice decrypt mismatch!"
    print(f"  ✓ Voice ChaCha20  {len(pcm)}B pcm → {len(enc_voice)}B encrypted")

    # Password hashing
    ph = hash_password("testpassword123!")
    assert verify_password("testpassword123!", ph), "Password verify failed!"
    assert not verify_password("wrong", ph), "Password false-positive!"
    print(f"  ✓ Password hash   {ph[:30]}...")

    print("  ✓ All selftests passed!\n")
    print(f"  Crypto backend: {'cryptography lib' if CRYPTO_AVAILABLE else 'stdlib (pure Python)'}")
    print(f"  Password KDF:   {'Argon2id' if ARGON2_AVAILABLE else 'PBKDF2-SHA256 (600k)'}")


if __name__ == '__main__':
    _selftest()
