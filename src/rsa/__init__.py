"""Top-level package for the `rsa` educational implementation.

This package provides:
- Core number theory helpers (primality testing, modular inverses)
- RSA key generation
- RSA encryption/decryption using RSAES-OAEP (SHA-256 by default)

Security note:
    This is a pure-Python reference-style implementation intended for learning
    and verification. It is not hardened against side channels (timing/cache)
    and should not be used to protect real secrets in production.
"""

from .key_gen import PublicKey, PrivateKey, generate_keypair
from .cipher import encrypt, decrypt

__all__ = [
    "PublicKey",
    "PrivateKey",
    "generate_keypair",
    "encrypt",
    "decrypt",
]
