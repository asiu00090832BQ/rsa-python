"""
High-integrity math utilities for RSA operations.
"""
import secrets
import math

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)

def lcm(a: int, b: int) -> int:
    return abs(a // gcd(a, b) * b)

def egcd(a: int, b: int):
    if b == 0:
        return (1, 0, a)
    x0, y0, g = egcd(b, a % b)
    return (y0, x0 - (a // b) * y0, g)

def modinv(a: int, m: int) -> int:
    x, y, g = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m

def is_probable_prime(n: int, k: int = 40) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d*2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    def try_composite(a):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return False
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                return False
        return True
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        if try_composite(a):
            return False
    return True

def generate_prime(bits: int) -> int:
    if bits < 2:
        raise ValueError("bits must be >=2")
    while True:
        # ensure top bit and odd
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p
