'''Encoding helpers and high-level byte-oriented RSA operations.
'''
from __future__ import annotations
import secrets
from typing import Optional
from .core import PublicKey, PrivateKey, encrypt_int, decrypt_int

def bytes_to_int(data: bytes) -> int: return int.from_bytes(data, 'big')
def int_to_bytes(v: int, l: Optional[int] = None) -> bytes:
    if v < 0: raise ValueError('negative')
    if l is None: l = (v.bit_length() + 7) // 8
    return v.to_bytes(l, 'big')

def _pad(m: bytes, k: int) -> bytes:
    if len(m) > k - 11: raise ValueError('too long')
    ps = bytearray()
    while len(ps) < k - len(m) - 3:
        b = secrets.token_bytes(1)
        if b != b'\x00': ps.extend(b)
    return b'\x00\x02' + ps + b'\x00' + m

def _unpad(em: bytes) -> bytes:
    if len(em) < 11 or em[:2] != b'\x00\x02': raise ValueError('bad pad')
    idx = em.index(b'\x00', 2)
    return em[idx+1:]

def encrypt_bytes(m: bytes, pub: PublicKey) -> bytes:
    k = pub.size_in_bytes
    em = _pad(m, k)
    return int_to_bytes(encrypt_int(bytes_to_int(em), pub), k)

def decrypt_bytes(c: bytes, priv: PrivateKey) -> bytes:
    k = priv.size_in_bytes
    em = int_to_bytes(decrypt_int(bytes_to_int(c), priv), k)
    return _unpad(em)
