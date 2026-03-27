import secrets
import pytest
from rsa import (
    PublicKey,
    PrivateKey,
    generate_keypair,
    encrypt_int,
    decrypt_int,
    encrypt_bytes,
    decrypt_bytes,
)
from rsa import math_utils

def test_gcd_and_modinv_basic():
    assert math_utils.gcd(54, 24) == 6
    assert math_utils.gcd(0, 5) == 5
    assert math_utils.gcd(5, 0) == 5
    assert math_utils.gcd(0, 0) == 0
    inv = math_utils.modinv(3, 11)
    assert (3 * inv) % 11 == 1
    with pytest.raises(ValueError):
        math_utils.modinv(2, 4)

def test_extended_gcd_relationship():
    for a in range(-10, 11):
        for b in range(-10, 11):
            g, x, y = math_utils.extended_gcd(a, b)
            assert g == math_utils.gcd(a, b)
            assert a * x + b * y == g

def test_is_probable_prime_small_values():
    for n in [0, 1, 4, 6, 8, 9, 10, 12, 15, 21]:
        assert not math_utils.is_probable_prime(n)
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 97]:
        assert math_utils.is_probable_prime(p)

def test_generate_prime_bit_length():
    bits = 128
    p = math_utils.generate_prime(bits)
    assert math_utils.is_probable_prime(p)
    assert p.bit_length() == bits

def test_key_generation_basic_properties():
    public_key, private_key = generate_keypair(bit_size=1024)
    assert isinstance(public_key, PublicKey)
    assert isinstance(private_key, PrivateKey)
    assert public_key.n == private_key.n
    assert 1000 <= public_key.size_in_bits <= 1024
    assert public_key.e > 1 and public_key.e % 2 == 1

def test_integer_encryption_roundtrip():
    public_key, private_key = generate_keypair(bit_size=512)
    for message in [0, 1, 42, 123456789, public_key.n - 1]:
        ciphertext = encrypt_int(message, public_key)
        assert 0 <= ciphertext < public_key.n
        recovered = decrypt_int(ciphertext, private_key)
        assert recovered == message
    with pytest.raises(ValueError):
        encrypt_int(public_key.n, public_key)

def test_bytes_encryption_pkcs1_small_message():
    public_key, private_key = generate_keypair(bit_size=1024)
    message = b'hello world'
    ciphertext = encrypt_bytes(message, public_key, use_pkcs1_v1_5=True)
    assert isinstance(ciphertext, bytes)
    assert len(ciphertext) % public_key.size_in_bytes == 0
    recovered = decrypt_bytes(ciphertext, private_key, use_pkcs1_v1_5=True)
    assert recovered == message


def test_bytes_encryption_pkcs1_large_message_multiblock():
    public_key, private_key = generate_keypair(bit_size=1024)
    k = public_key.size_in_bytes
    max_chunk_len = k - 11
    message = secrets.token_bytes(max_chunk_len * 3 + 10)
    ciphertext = encrypt_bytes(message, public_key, use_pkcs1_v1_5=True)
    assert len(ciphertext) % k == 0
    expected_blocks = (len(message) + max_chunk_len - 1) // max_chunk_len
    assert len(ciphertext) == expected_blocks * k
    recovered = decrypt_bytes(ciphertext, private_key, use_pkcs1_v1_5=True)
    assert recovered == message

def test_bytes_encryption_unpadded_single_block():
    public_key, private_key = generate_keypair(bit_size=512)
    k = public_key.size_in_bytes
    message = b'A' * (k - 1)
    ciphertext = encrypt_bytes(message, public_key, use_pkcs1_v1_5=False)
    assert len(ciphertext) == k
    recovered = decrypt_bytes(ciphertext, private_key, use_pkcs1_v1_5=False)
    assert recovered == message
    too_long = b'B' * (k + 1)
    with pytest.raises(ValueError):
        encrypt_bytes(too_long, public_key, use_pkcs1_v1_5=False)
