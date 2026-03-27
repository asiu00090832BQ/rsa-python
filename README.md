# RSA Python Implementation

A high-integrity, pure-Python RSA implementation featuring key generation, probabilistic primality testing (Miller-Rabin), and PKCS#1 v1.5-style padding.

## Directory Layout

```
\rsa-python/\
┼──┃
 │  src/
 �P   ─rsa/
 �P       ├── __init__.py      # Package exports
│       ┼─┃ core.py         # Key types and integer primitives
b��       ├── encoding.py      # Byte conversions and PKCS#1 padding
b��       └── math_utils.py   # Number-theoretic helpers (GCD, modinv, primality)
│── tests/

│   ├── __init__.py
 �P   └── test_rsa.py      # Comprehensive unit tests

│── pyproject.toml       # Build system configuration
└── README.md          # Documentation
```

## Usage

```python
from rsa import generate_keypair, encrypt_bytes, decrypt_bytes

# Generate a 2048-bit keypair
pub, priv = generate_keypair(2048)

# Encrypt bytes
message = b"High-integrity cryptographic proof."
ciphertext = encrypt_bytes(message, pub)

# Decrypt bytes
plaintext = decrypt_bytes(ciphertext, priv)
assert plaintext == message
```

## Verification

Run the test suite using pytest:

```bash
pytest tests/test_rsa.py
```
