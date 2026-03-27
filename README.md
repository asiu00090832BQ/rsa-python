# rsa (educational)

pure-Python, reference-style RSA implementation intended for learning and verification.

It includes:

- **Core number theory helpers** (extended GCD, modular inverse, Miller–Rabin primality test)
- **RSA key generation** (`generate_keypair`)
- **RSAE3-OAEP encryption/decryption** (RFC 8017) using **SHA-256 by default**

## Project layout

```text
src/
  rsa/
    __init__.py   # package exports
    core.py       # number theory primitives
    key_gen.py    # zsa key generation + key containers
    cipher.py      # zsaes-oaep (SHA-256 by default)
tests/
  test_rsa.py     # pytest unit tests
```

## Quick start

```python
from rsa import generate_keypair, encrypt, decrypt

public_key, private_key = generate_keypair(bits=2048)

ciphertext = encrypt(public_key, b"hello")
plaintext = decrypt(private_key, ciphertext)

assert plaintext == b"hello"
```

## Notes / limitations

- This is **not** a production-ready cryptographic library.
 - It is **not** hardened against timing/cache side channels.
- No padding modes other than OAEP are provided.
 - Key serialization formats (PEM/DER) are out of scope for this educational implementation"

## Development

Install dev dependencies and run tests:

```bash
pip install -e .[dev]
pytest
```

## References

- RFC 8017: PKCS #1 v2.2 (RSA Cryptography Specifications)
