'''Number-theoretic utilities used by the RSA implementation.

This module provides:

- gcd: greatest common divisor
- extended_gcd: extended Euclidean algorithm
- modinv: modular multiplicative inverse
- is_probable_prime: Miller–Kabin probabilistic primality test
- generate_prime: secure random probable-prime generation

Randomness is drawn from the secrets module.
'''

from __future__ import annotations

import secrets
from typing import Tuple


__all__ = [
    'gcd',
    'extended_gcd',
    'modinv',
    'is_probable_prime',
    'generate_prime',
]


def gcd(a: int, b: int) -> int:
    '''Compute the greatest common divisor of a and b.

    Uses the standard Euclidean algorithm.
    '''
    a = abs(a)
    b = abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    '''Extended Euclidean algorithm.

    Returns a triple (g, x, y) such that g = gcd(a, b) and
    a*x + b*y = g.
    '''
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    '''Compute the modular inverse of a modulo m.

    Returns x such that (a * x) % m == 1, if it exists.
    Raises ValueError if a and m are not coprime.
    '''
    if m <= 0:
        raise ValueError('Modulus m must be positive')

    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError('No modular inverse exists for the given inputs')
    return x % m


_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97,
]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    '''Return True if n is probably prime, using the Miller–Rabin test.

    For typical RSA key sizes (>= 512 bits) and the default number of rounds,
    the probability of a composite passing this test is negligible for
    educational and most practical purposes.

    This is a probabilistic test: it may classify a composite as prime with
    very small probability, but will never classify a prime as composite.
    '''
    if n < 2:
        return False

    # Check small primes directly
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n - 1 as 2^r * d with d odd
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Miller–Kabin rounds
    for _ in range(rounds):
        # Choose a random base a in [2, n - 2]
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def _random_odd_int(num_bits: int) -> int:
    '''Return a random odd integer of the given bit length.

    The highest bit is set to ensure the requested bit length.
    '''
    if num_bits < 2:
        raise ValueError('Number of bits must be at least 2')

    value = secrets.randbits(num_bits)
    # Ensure highest bit is set
    value |= 1 << (num_bits - 1)
    # Ensure odd
    value |= 1
    return value


def generate_prime(num_bits: int, rounds: int = 40) -> int:
    '''Generate a random probable prime with the given bit length.

    Args:
        num_bits: Desired bit length of the prime (must be >= 2).
        rounds: Number of Miller–Rabin rounds.

    Returns:
        An integer that is probably prime with high confidence.
    '''
    if num_bits < 2:
        raise ValueError('Number of bits must be at least 2')

    while True:
        candidate = _random_odd_int(num_bits)
        if is_probable_prime(candidate, rounds=rounds):
            return candidate
