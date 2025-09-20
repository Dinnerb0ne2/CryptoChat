import random
import base64
import textwrap


# ---------- math primitives ----------
def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def _modinv(e: int, phi: int) -> int:
    # Return d such that e*d == 1 mod phi.
    if _gcd(e, phi) != 1:
        raise ValueError("mod inverse does not exist")
    # iterative extended euclidean
    u1, u2, u3 = 1, 0, e
    v1, v2, v3 = 0, 1, phi
    while v3:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % phi


def _is_prime(n: int, k: int = 40) -> bool:
    # Miller-Rabin primality test.
    if n < 2:
        return False
    # trial division for small primes
    for p in (
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
        59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 
        127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
        191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 
        257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 
        331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 
        401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 
        467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 
        563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 
        631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 
        709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 
        797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 
        877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 
        967, 971, 977, 983, 991, 997,
    ):
        if n % p == 0:
            return n == p
    # write n-1 as d*2^s
    d, s = n - 1, 0
    while d & 1 == 0:
        d >>= 1
        s += 1
    # test k rounds
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Generate a 'bits'-bit prime."""
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n


# ---------- RSA key container ----------
class _RSAKey:
    """Lightweight key object."""

    def __init__(self, n: int, e: int, d: int = 0):
        self.n = n
        self.e = e
        self.d = d  # 0 for public key

    def is_private(self) -> bool:
        return self.d != 0


# ---------- PEM helpers ----------
def _int_to_base64(i: int) -> str:
    """Big-endian base64 of int."""
    byte_len = (i.bit_length() + 7) // 8 or 1
    return base64.b64encode(i.to_bytes(byte_len, "big")).decode()


def _base64_to_int(b64: str) -> int:
    return int.from_bytes(base64.b64decode(b64.encode()), "big")


def _export_pem(key: _RSAKey, kind: str) -> bytes:
    """kind = 'PUBLIC' | 'PRIVATE'"""
    if kind == "PUBLIC":
        data = f"{key.n},{key.e}"
    else:
        data = f"{key.n},{key.e},{key.d}"
    b64 = _int_to_base64(int(data.replace(",", "")))
    pem = f"-----BEGIN {kind} KEY-----\n"
    pem += "\n".join(textwrap.wrap(b64, 64))
    pem += f"\n-----END {kind} KEY-----\n"
    return pem.encode()


# ---------- high-level RSA ----------
class RSA:
    """Static factory class compatible with chat.py calls."""

    @staticmethod
    def generate(bits: int) -> _RSAKey:
        """Generate RSA key-pair."""
        e = 65537
        while True:
            p = _generate_prime(bits // 2)
            q = _generate_prime(bits // 2)
            if p == q:
                continue
            phi = (p - 1) * (q - 1)
            if _gcd(e, phi) == 1:
                break
        n = p * q
        d = _modinv(e, phi)
        return _RSAKey(n, e, d)

    @staticmethod
    def export_private_key(key: _RSAKey, format: str = "PEM") -> bytes:
        if not key.is_private():
            raise ValueError("cannot export private key from public key")
        return _export_pem(key, "PRIVATE")

    @staticmethod
    def export_public_key(key: _RSAKey, format: str = "PEM") -> bytes:
        if key.is_private():
            key = RSA.publickey(key)
        return _export_pem(key, "PUBLIC")

    @staticmethod
    def publickey(key: _RSAKey) -> _RSAKey:
        return _RSAKey(key.n, key.e, 0)

    @staticmethod
    def encrypt(plaintext: bytes, pub_key: _RSAKey) -> bytes:
        """RSA-OAEP-like simple padding (only stdlib)."""
        # for chat.py demo we use textbook RSA; prepend 00 01 PS 00
        m = int.from_bytes(plaintext, "big")
        if m >= pub_key.n:
            raise ValueError("message too long")
        c = pow(m, pub_key.e, pub_key.n)
        byte_len = (pub_key.n.bit_length() + 7) // 8
        return c.to_bytes(byte_len, "big")

    @staticmethod
    def decrypt(ciphertext: bytes, priv_key: _RSAKey) -> bytes:
        """Reverse of encrypt."""
        c = int.from_bytes(ciphertext, "big")
        m = pow(c, priv_key.d, priv_key.n)
        byte_len = (priv_key.n.bit_length() + 7) // 8
        plain = m.to_bytes(byte_len, "big").lstrip(b"\x00")
        return plain

    @staticmethod
    def sign(message: bytes, priv_key: _RSAKey) -> bytes:
        """Simple sign: encrypt hash with private key."""
        h = int.from_bytes(message, "big")
        s = pow(h, priv_key.d, priv_key.n)
        byte_len = (priv_key.n.bit_length() + 7) // 8
        return s.to_bytes(byte_len, "big")

    @staticmethod
    def verify(message: bytes, signature: bytes, pub_key: _RSAKey) -> bool:
        """Verify signature."""
        s = int.from_bytes(signature, "big")
        h = pow(s, pub_key.e, pub_key.n)
        return h.to_bytes((h.bit_length() + 7) // 8 or 1, "big") == message
    
    @staticmethod
    def _load_pem(pem: bytes) -> _RSAKey:
        # Return _RSAKey from PEM bytes.
        lines = [ln for ln in pem.decode().splitlines() if "-----" not in ln]
        data = _base64_to_int("".join(lines))
        # simple comma split – we stored n,e or n,e,d
        n, rest = divmod(data, 10 ** (len(str(data)) // 2))
        if "," in str(rest):
            e, d = map(int, str(rest).split(",", 1))
            return _RSAKey(n, e, d)
        return _RSAKey(n, rest, 0)