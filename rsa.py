import secrets
from dataclasses import dataclass

def gcd(a, b):
    while b: a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1: raise ValueError('no inverse')
    return x % m

def is_probable_prime(n, k=40):
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0: r += 1; d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 4) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def generate_prime(bits):
    while True:
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_probable_prime(p): return p

@dataclass
class PublicKey: n: int; e: int
@dataclass
class PrivateKey: n: int; d: int

def generate_keypair(bits=2048):
    p, q = generate_prime(bits // 2), generate_prime(bits // 2)
    n, phi = p * q, (p - 1) * (q - 1)
    e = 65537
    return PublicKey(n, e), PrivateKey(n, modinv(e, phi))

def encrypt(m, pub): return pow(m, pub.e, pub.n)
def decrypt(c, priv): return pow(c, priv.d, priv.n)
