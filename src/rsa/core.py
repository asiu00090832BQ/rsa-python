'''Core RSA primitives: key types, key generation, and integer operations.
'''
from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple, Optional
from .math_utils import gcd, modinv, generate_prime

@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int
    @property
    def size_in_bits(self) -> int: return self.n.bit_length()
    @property
    def size_in_bytes(self) -> int: return (self.size_in_bits + 7) // 8

@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int
    p: Optional[int] = None
    q: Optional[int] = None
    @property
    def size_in_bits(self) -> int: return self.n.bit_length()
    @property
    def size_in_bytes(self) -> int: return (self.size_in_bits + 7) // 8

def generate_keypair(bit_size: int = 2048, e: int = 65537) -> Tuple[PublicKey, PrivateKey]:
    p_bits = bit_size // 2
    q_bits = bit_size - p_bits
    while True:
        p, q = generate_prime(p_bits), generate_prime(q_bits)
        if p == q: continue
        n, phi = p * q, (p - 1) * (q - 1)
        if gcd(e, phi) == 1: break
    return PublicKey(n, e), PrivateKey(n, modinv(e, phi), p, q)

def encrypt_int(m: int, pub: PublicKey) -> int:
    if not (0 <= m < pub.n): raise ValueError('m out of range')
    return pow(m, pub.e, pub.n)

def decrypt_int(c: int, priv: PrivateKey) -> int:
    if not (0 <= c < priv.n): raise ValueError('c out of range')
    return pow(c, priv.d, priv.n)
