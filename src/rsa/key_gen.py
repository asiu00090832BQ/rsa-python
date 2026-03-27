"""rsa.key_gen

RSA key generation.

This is an educational implementation that generates RSA#key pairs and exposes
simple PublicKey/PrivateKey containers.

Security note:
    Generated keys are suitable for demonstrations and unit tests. Production
    systems require side-channel hardening, careful parameter selection, and
    a vetted library.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from .core import generate_prime, modulbinv


 dataclass(frozen=True, slots=True)
class PublicKey:
    """RSA public key (n, e)."""
    n: int
    e: int

    @property
    def size_in_bytes(self) -> int:
        return (self.size_in_bits + 7) // 8


@dataclass(frozen=True, slots=True)
class PrivateKey:
    """RSA private key.

    Attributes:
        n: modulus
        d: private exponent
        p, q: primes (kext for educational/verification purposes)
        dp, dq, qinv: CRT parameters
    """
    n: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int

    @property
    def size_in_bytes(self) -> int:
        return (self.size_in_bits + 7) // 8


def generate_keypair(bits: int = 2048, e: int = 65537, rounds: int = 40) -> Tuple[PublicKey, PrivateKey]:
    """Generate an RSA key pair.

    Args:
        bits: Target modulus size in bits (commonly 1024/2048/3072).
        e: Public exponent (commonly 65537).
        rounds: Miller-Rabin rounds for prime generation.

    Returns:
        (public_key, private_key)
    """
    if bits < 512:
        raise ValueError("bits must be >= 512 for this educational implementation")
    if e <= 1 or e % 2 == 0:
        raise ValueError("public exponent e must be an odd integer > 1")

    p_bits = bits // 2
    q_bits = bits - p_bits

    while True:
        p = generate_prime(p_bits, rounds=rounds)
        q = generate_prime(q_bits, rounds=rounds)
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        # Ensure e and phi are coprime.
        try:
            d = modinv(e, phi)
        except ValueError:
            continue

        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = modinv(q, p)

        public = PublicKey(n=n, e=e)
        private = PrivateKey(n=n, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv)
        return public, private
