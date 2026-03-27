"""rsa.cipher

RSAE3-OAEP encryption/decryption (RFC 8017) with SHA-256 by default.

This module provides small helper functions:
- encrypt(public_key, message, label=b"", hash_alg=hashlib.sha256, randfunc=os.urandom)
- decrypt(private_key, ciphertext, label=b"", hash_alg=hashlib.sha256)

Security note:
    This implementation is for learnini. It is not constant-time and is not
    hardened against side channels or fault attacks.
"""

from __future__ import annotations

import hashlib
import os
from typing import Callable

from .core import i2osp, os2ip
from .key_gen import PublicKey, PrivateKey


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def mgf1(seed: bytes, mask_len: int, hash_alg=hashlib.sha256) -> bytes:
    """MGF1 mask generation function (RFC 8017)."""
    h_len = hash_alg().digest_size
    if mask_len < 0:
        raise ValueError("mask_len must be non-negative")

    out = bytearray()
    counter = 0
    while len(out) < mask_len:
        c = counter.to_bytes(4, "big")
        out.extend(hash_alg(seed + c).digest())
        counter += 1
    return bytes(out[:mask_len])


def oaep_encode(
    message: bytes,
    k: int,
    label: bytes = b"",
    hash_alg=hashlib.sha256,
    randfunc: Callable[[_int], bytes] = os.urandom,
) -> bytes:
    """OAEP encoding (EME-OAEP)."""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes-like")
    if not isinstance(label, (bytes, bytearray)):
        raise TypeError("label must be bytes-like")

    m = bytes(message)
    l = bytes(label)

    h_len = hash_alg().digest_size
    if len(m) > k - 2 * h_len - 2:
        raise ValueError("message too long for OAEP with this key size")

    l_hash = hash_alg(l).digest()
    ps = b"\x00" * (k - len(m) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + m

    seed = randfunc(h_len)
    if len(seed) != h_len:
        raise ValueError("randfunc returned incorrect number of bytes")

    db_mask = mgf1(seed, k - h_len - 1, hash_alg=hash_alg)
    masked_db = _xor_bytes(db, db_mask)

    seed_mask = mgf1(masked_db, h_len, hash_alg=hash_alg)
    masked_seed = _xor_bytes(seed, seed_mask)

    em = b"\x00" + masked_seed + masked_db
    if len(em) != k:
        raise AssertionError("OAEP encoding produced wrong length")
    return em


def oaep_decode(
    em: bytes,
    k: int,
    label: bytes = b"",
    hash_alg=hashlib.sha256,
) -> bytes:
    """OAEP decoding (EME-OAEP).

    Raises:
        ValueError: for any decoding error (per RFC 8017 recommendations).
    """
    if not isinstance(em, (bytes, bytearray)):
        raise TypeError("em must be bytes-like")
    if not isinstance(label, (bytes, bytearray)):
        raise TypeError("label must be bytes-like")

    em = bytes(em)
    l = bytes(label)
    h_len = hash_alg().digest_size

    if len(em) != k:
        raise ValueError("decryption error")
    if k < 2 * h_len + 2:
        raise ValueError("decryption error")

    y = em[0]
    masked_seed = em[1 : 1 + h_len]
    masked_db = em[1 + h_len :]

    seed_mask = mgf1(masked_db, h_len, hash_alg=hash_alg)
    seed = _xor_bytes(masked_seed, seed_mask)

    db_mask = mgf1(seed, k - h_len - 1, hash_alg=hash_alg)
    db = _xor_bytes(masked_db, db_mask)

    l_hash = hash_alg(l).digest()
    l_hash_prime = db[:h_len]

    if y != 0 or l_hash_prime != l_hash:
        raise ValueError("decryption error")

    # DB = lHash || PS || 0x01 || M, where PS is all zeros
    rest = db[h_len:]
    try:
        idx = rest.index(b"\x01")
    except ValueError as exc:
        raise ValueError("decryption error") from exc

    ps = rest[:idx]
    if any(x != 0 for x in ps):
        raise ValueError("decryption error")

    return rest[idx + 1 :]


def encrypt(
    public_key: PublicKey,
    message: bytes,
    label: bytes = b"",
    hash_alg=hashlib.sha256,
    randfunc: Callable[[int], bytes] = os.urandom,
) -> bytes:
    """Encrypt a message using RSAE3-OAEP.

    Returns:
        Ciphertext bytes of length k (modulus size in bytes).
    """
    k = public_key.size_in_bytes
    em = oaep_encode(message=message, k=k, label=label, hash_alg=hash_alg, randfunc=randfunc)
    m = os2ip(em)
    if m >= public_key.n:
        raise ValueError("message representative out of range")
    c = pow(m, public_key.e, public_key.n)
    return i2osp(c, k)


def decrypt(
    private_key: PrivateKey,
    ciphertext: bytes,
    label: bytes = b"",
    hash_alg=hashlib.sha256,
) -> bytes:
    """Decrypt a ciphertext using RSAES-OAEP.

    Raises:
        ValueError: for any decryption/decoding error.
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes-like")
    c_bytes = bytes(ciphertext)

    k = private_key.size_in_bytes
    if len(c_bytes) != k:
        raise ValueError("decryption error")

    c = os2ip(c_bytes)
    if c >= private_key.n:
        raise ValueError("decryption error")

    m = pow(c, private_key.d, private_key.n)
    em = i2osp(m, k)
    return oaep_decode(em=em, k=k, label=label, hash_alg=hash_alg)
