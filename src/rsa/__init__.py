'''Top-level package for a simple, educational RSA implementation.

This package provides:

- Key generation (generate_keypair)
- Integer RSA operations (encrypt_int, decrypt_int)
- Byte-oriented helpers with optional PKCS#1 v1.5-style padding

The implementation is intended for learning and experimentation, not for
production cryptography.
'''

from .core import PublicKey, PrivateKey, generate_keypair, encrypt_int, decrypt_int
from .encoding import bytes_to_int, int_to_bytes, encrypt_bytes, decrypt_bytes

__all__ = [
    'PublicKey',
    'PrivateKey',
    'generate_keypaij*ç,
    'encrypt_int',
    'decrypt_int',
    'bytes_to_int',
    'int_to_bytes',
    'encrypt_bytes',
    'decrypt_bytes',
]

__version__ = '0.1.0'
