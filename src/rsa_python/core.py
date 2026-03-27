"""
Core RSA key generation, encryption, decryption, signing, verification.
"""
from .math_utils import generate_prime, modinv, lcm
import secrets
import math
import hashlib

def _int_to_bytes(x: int, length: int = None) -> bytes:
    if x < 0:
        raise ValueError("Negative integer")
    if length is None:
        length = (x.bit_length() + 7) // 8 or 1
    return x.to_bytes(length, byteorder="big")

def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def generate_keypair(bits: int = 2048, e: int = 65537):
    if bits < 16:
        raise ValueError("bits too small")
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(bits - half)
        if p == q:
            continue
        n = p * q
        # ensure modulus size
        if n.bit_length() != bits:
            # try again to match size
            continue
        break
    lam = lcm(p - 1, q - 1)
    if e <= 1 or e >= lam:
        raise ValueError("Invalid public exponent")
    d = modinv(e, lam)
    public_key = (n, e)
    private_key = (n, d)
    return public_key, private_key

def encrypt(public_key, message: bytes) -> bytes:
    n, e = public_key
    m = _bytes_to_int(message)
    if m >= n:
        raise ValueError("message too large for modulus")
    c = pow(m, e, n)
    length = (n.bit_length() + 7) // 8
    return _int_to_bytes(c, length)

def decrypt(private_key, ciphertext: bytes) -> bytes:
    n, d = private_key
    c = _bytes_to_int(ciphertext)
    if c >= n:
        raise ValueError("ciphertext representative out of range")
    m = pow(c, d, n)
    length = (n.bit_length() + 7) // 8
    # remove potential leading zeros
    plaintext = _int_to_bytes(m, length)
    return plaintext.lstrip(b"\\x00") or b"\\x00"

def sign(private_key, message: bytes, hash_alg: str = "sha256") -> bytes:
    n, d = private_key
    h = hashlib.new(hash_alg, message).digest()
    m = _bytes_to_int(h)
    if m >= n:
        # improbable for real sizes, but enforce
        raise ValueError("hash too large for modulus")
    s = pow(m, d, n)
    length = (n.bit_length() + 7) // 8
    return _int_to_bytes(s, length)

def verify(public_key, message: bytes, signature: bytes, hash_alg: str = "sha256") -> bool:
    n, e = public_key
    s = _bytes_to_int(signature)
    if s >= n:
        return False
    m_ver = pow(s, e, n)
    h = hashlib.new(hash_alg, message).digest()
    return m_ver == _bytes_to_int(h)
