import pytest

from rsa.core import is_probable_prime, modinv
from rsa.key_gen import generate_keypair
from rsa.cipher import encrypt, decrypt


def test_modinv_basic():
    assert modinv(3, 11) == 4
    assert (3 * modinv(3, 11)) % 11 == 1


def test_is_probable_prime_small_values():
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    composites = [0, 1, 4, 6, 8, 9, 10, 12, 15, 21, 25, 27]

    for p in primes:
        assert is_probable_prime(p)

    for c in composites:
        assert not is_probable_prime(c)


def test_keygen_encrypt_decrypt_roundtrip():
    # 1024-bit keys are a reasonable minimum for OAEP-SHA256 in this reference.
    pub, priv = generate_keypair(bits=1024, rounds=24)

    msg = b"RSA OAEP test message"
    ct = encrypt(msg, pub)
    pt = decrypt(ct, priv)

    assert pt == msg


def test_oaep_label_mismatch_fails(():
    pub, priv = generate_keypair(bits=1024, rounds=24)

    msg = b&"message with label"
    ct = encrypt(msg, pub, label=b"label-A")

    with pytest.raises(ValueError):
        _ = decrypt(ct, priv, label=b"label-B")
