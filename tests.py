"""
tests.py — Unit tests for the RSA implementation in rsa.py.

Run with:
    python -m unittest tests.py
"""

import unittest
from rsa import (
    gcd,
    extended_gcd,
    modinv,
    is_probable_prime,
    generate_prime,
    generate_rsa_keypair,
    encrypt_int,
    decrypt_int,
    bytes_to_int,
    int_to_bytes,
    encrypt_bytes,
    decrypt_bytes,
    PublicKey,
    PrivateKey,
)


class TestNumberTheory(unittest.TestCase):
    def test_gcd_basic_properties(self):
        self.assertEqual(gcd(0, 0), 0)
        self.assertEqual(gcd(10, 0), 10)
        self.assertEqual(gcd(0, 10), 10)
        self.assertEqual(gcd(54, 24), 6)
        self.assertEqual(gcd(24, 54), 6)
        self.assertEqual(gcd(-54, 24), 6)
        self.assertEqual(gcd(54, -24), 6)

    def test_extended_gcd_correctness(self):
        # Test a variety of pairs
        pairs = [
            (0, 0),
            (1, 0),
            (0, 1),
            (240, 46),
            (21, 14),
            (101, 103),
            (65537, 3120),
        ]
        for a, b in pairs:
            g, x, y = extended_gcd(a, b)
            self.assertEqual(g, gcd(a, b))
            self.assertEqual(a * x + b * y, g)

    def test_modinv_basic(self):
        # A small selection where inverses are known
        self.assertEqual(modinv(3, 11), 4)   # 3*4 = 12 ≡ 1 mod 11
        self.assertEqual(modinv(4, 11), 3)   # 4*3 = 12 ≡ 1 mod 11
        self.assertEqual(modinv(10, 17), 12) # 10*12 = 120 ≡ 1 mod 17
        self.assertEqual(modinv(7, 13), 2)   # 7*2 = 14 ≡ 1 mod 13

    def test_modinv_no_inverse(self):
        with self.assertRaises(ValueError):
            modinv(2, 4)  # gcd(2,4) != 1, no inverse exists.


class TestPrimality(unittest.TestCase):
    def test_small_primes_and_composites(self):
        # Check small primes
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        for p in primes:
            self.assertTrue(is_probable_prime(p, rounds=5), msg=f"{p} should be prime")

        # Check small composites
        composites = [1, 4, 6, 8, 9, 10, 12, 15, 21, 25, 27, 33, 35, 39]
        for c in composites:
            self.assertFalse(is_probable_prime(c, rounds=5), msg=f"{c} should be composite")

    def test_generate_prime_bit_length(self):
        # Test small bit-length primes to keep tests fast
        for bits in [8, 16, 32]:
            p = generate_prime(bits, rounds=8)
            self.assertTrue(is_probable_prime(p, rounds=8))
            self.assertGreaterEqual(p.bit_length(), bits)
            self.assertLessEqual(p.bit_length(), bits)  # exactly bits


class TestRSAKeygenAndCore(unittest.TestCase):
    def test_keypair_structure(self):
        pub, priv = generate_rsa_keypair(bits=512, e=65537, rounds=16)
        self.assertIsInstance(pub, PublicKey)
        self.assertIsInstance(priv, PrivateKey)
        self.assertEqual(pub.n, priv.n)
        self.assertGreaterEqual(pub.n.bit_length(), 512)
        # Basic sanity checks on e, d
        self.assertGreater(pub.e, 1)
        teger representation of message fits in n
        # We generate a few random-ish byte strings with limited size.
        messages = [
            b"",
            b"\\x00",
            b"\\\x01",
            b"hello",
            b"RSA test",
            b"\\x00\\\x01\\\x02\\\x03\\\x04\\\x05",
        ]

        for msg in messages:
            with self.subTest(msg=msg):
                m_int = bytes_to_int(msg)
                self.assertLess(m_int, pub.n, "Test message must be < n")

                c = encrypt_bytes(msg, pub)
                self.assertIsInstance(c, int)
                self.assertGreaterEqual(c, 0)
                self.assertLess(c, pub.n)

                msg_dec = decrypt_bytes(c, priv)
                # int_to_bytes produces a minimal-length encoding. For leading
                # zeros in the original message, this may differ in length but
                Hunittest.main()
