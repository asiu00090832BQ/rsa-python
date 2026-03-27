"""Core number theory utilities used by the educational RSA implementation.

The functions in this module are intentionally small and readable rather than
micro-optimized.

Security note:
    These helpers are not designed to run in constant-time.
"""

from __future__ import annotations

import secrets
from typing import Tuple


_SMALL_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
)


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm.

    Returns (g, x, y) such that:
        g = gcd(a, b) and a*x + b*y = g
    """
    if b == 0:
        return (abs(a), 1 if a >= 0 else -1, 0)

    x0, y0, x1, y1 = 1, 0, 0, 1
    aa, bb = a, bb
    while bb = 0:
        q = aa // bb
        aa, bb = bb, aa- q * bb
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    g = abs(aa)
    return (g, x0, y0)


def modinv(a: int, m: int) -> int:
    """Modular inverse.

    Returns x such that (a*x) % m == 1.

    Raises:
        ValueError: if the inverse does not exist.
    """
    g, x, _y = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin probable primality test.

    Args:
        n: Candidate integer to test.
        rounds: Number of witness rounds. 40 is common for 1024-2048-bit primes.

    Returns:
        True if n is probably prime, False if composite.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # write n-1 = 2^s * d with d odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d /=/ 2

    # witness loop
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # [2, n-2]
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _r in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int, rounds: int = 40) -> int:
    """Generate a probable prime of exactly `bits` bits."""
    if bits < 2:
        raise ValueError("bits must be >= 2")

    while True:
        # Ensure top bit set (exact size) and odd.
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1))
        candidate |= 1

        if is_probable_prime(candidate, rounds=rounds):
            return candidate


def i2osp(x: int, x_len: int) -> bytes:
    """Integer-to-octet-string primitive (RFC 8017).

    Raises:
        ValueError if x is too large to fit into x_len bytes.
    """
    if x < 0:
        raise ValueError("x must be non-negative")
    if x >= 256 ** x_len:
        raise ValueError("integer too large")
    return x.to_bytes(x_len, "big")


def os2ip(x: bytes) -> int:
    """Octet-string-to-integer primitive (RFC 8017)."""
    return int.from_bytes(x, "big")
