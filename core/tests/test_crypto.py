"""现代密码学工具测试：标准测试向量（FIPS-197、FIPS 46-3、RFC 6229）与各种 RSA 攻击的构造用例。"""

import hashlib
import math
import random
import unittest

from ctfkit.crypto import ciphers, hashext, nt
from ctfkit.crypto.rsa import attack, parse_key, parse_params
from ctfkit.registry import run
from ctfkit.util import b2i, i2b

FLAG = b"flag{unit_test}"
M = b2i(FLAG)


def prime(bits, rng):
    while True:
        x = rng.getrandbits(bits) | 1 | (1 << (bits - 1))
        if nt.is_prime(x):
            return x


class TestCiphers(unittest.TestCase):
    def test_aes_fips197(self):
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        for klen, ct in ((16, "69c4e0d86a7b0430d8cdb78070b4c55a"), (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
                         (32, "8ea2b7ca516745bfeafc49904b496089")):
            a = ciphers.AES(bytes(range(klen)))
            self.assertEqual(a.encrypt_block(pt).hex(), ct)
            self.assertEqual(a.decrypt_block(bytes.fromhex(ct)), pt)

    def test_des(self):
        d = ciphers.DES(bytes.fromhex("133457799BBCDFF1"))
        self.assertEqual(d.encrypt_block(bytes.fromhex("0123456789ABCDEF")).hex(), "85e813540f0ab405")
        t = ciphers.TripleDES(bytes.fromhex("0123456789abcdef23456789abcdef01456789abcdef0123"))
        ct = t.encrypt_block(b"The qufc")
        self.assertEqual(t.decrypt_block(ct), b"The qufc")

    def test_rc4(self):
        self.assertEqual(ciphers.rc4(b"Key", b"Plaintext").hex(), "bbf316e8d940af0ad3")
        self.assertEqual(ciphers.rc4(b"Wiki", b"pedia").hex(), "1021bf0420")

    def test_modes_roundtrip(self):
        rng = random.Random(1)
        for mode in ("ECB", "CBC", "CFB", "OFB", "CTR"):
            key, iv = bytes(rng.getrandbits(8) for _ in range(16)), bytes(rng.getrandbits(8) for _ in range(16))
            data = ciphers.pad(b"x" * 37, 16) if mode in ("ECB", "CBC") else b"y" * 37
            c = ciphers.mode_encrypt(ciphers.AES(key), mode, data, iv)
            self.assertEqual(ciphers.mode_decrypt(ciphers.AES(key), mode, c, iv), data)

    def test_block_tool_roundtrip(self):
        enc = run("modern.block", {"text": "flag{tool}", "action": "加密", "key": "k" * 16, "input_format": "文本",
                                   "output_format": "Base64", "mode": "ECB"})["output"]["value"]
        dec = run("modern.block", {"text": enc, "action": "解密", "key": "k" * 16, "mode": "ECB"})["output"]["value"]
        self.assertEqual(dec, "flag{tool}")

    def test_padding(self):
        for scheme in ("PKCS#7", "ANSI X9.23", "ISO/IEC 7816-4"):
            for n in range(0, 33):
                d = b"a" * n
                self.assertEqual(ciphers.unpad(ciphers.pad(d, 16, scheme), 16, scheme), d)


class TestXor(unittest.TestCase):
    def test_repeating_key(self):
        text = (b"In cryptography, a simple XOR cipher is a type of additive cipher. With this logic, a string of text "
                b"can be encrypted by applying the bitwise XOR operator to every character using a given key. flag{xor}")
        key = b"secret"
        ct = bytes(b ^ key[i % len(key)] for i, b in enumerate(text)).hex()
        r = run("modern.xor", {"text": ct, "mode": "重复密钥破解"})["output"]
        self.assertEqual(r["rows"][0][1], "secret")


class TestHash(unittest.TestCase):
    def test_pure_hashes(self):
        hashext.self_check()

    def test_length_extension(self):
        for algo in ("md5", "sha1", "sha256"):
            secret, data = b"0123456789", b"user=guest"
            h = hashlib.new(algo, secret + data).hexdigest()
            nd, nh = hashext.extend(algo, h, data, b"&admin=1", len(secret))
            self.assertEqual(hashlib.new(algo, secret + nd).hexdigest(), nh)


class TestNumberTheory(unittest.TestCase):
    def test_basics(self):
        self.assertEqual(nt.invert(17, 3120), 2753)
        self.assertEqual(nt.crt([2, 3, 2], [3, 5, 7])[0], 23)
        self.assertEqual(nt.iroot(10 ** 300 + 1, 3), (10 ** 100, False))
        self.assertTrue(nt.is_prime(2 ** 127 - 1))
        self.assertFalse(nt.is_prime(561))
        self.assertEqual(nt.factor(2 ** 64 + 1)[0], [274177, 67280421310721])


class TestRsa(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(2026)

    def solve(self, params):
        m, steps = attack(params)
        self.assertIsNotNone(m, steps)
        return i2b(m)

    def test_known_factors_and_dp(self):
        p, q, e = prime(512, self.rng), prime(512, self.rng), 65537
        n = p * q
        c = pow(M, e, n)
        self.assertEqual(self.solve({"p": p, "q": q, "e": e, "c": c}), FLAG)
        d = nt.invert(e, (p - 1) * (q - 1))
        self.assertEqual(self.solve({"n": n, "e": e, "dp": d % (p - 1), "c": c}), FLAG)

    def test_common_modulus(self):
        n = prime(512, self.rng) * prime(512, self.rng)
        self.assertEqual(self.solve({"n1": n, "n2": n, "e1": 65537, "e2": 17, "c1": pow(M, 65537, n), "c2": pow(M, 17, n)}), FLAG)

    def test_broadcast_and_small_e(self):
        ns = [prime(256, self.rng) * prime(256, self.rng) for _ in range(3)]
        params = {"e": 3}
        for i, n in enumerate(ns, 1):
            params["n%d" % i], params["c%d" % i] = n, pow(M, 3, n)
        self.assertEqual(self.solve(params), FLAG)
        n = prime(512, self.rng) * prime(512, self.rng)
        self.assertEqual(self.solve({"n": n, "e": 3, "c": pow(M, 3, n)}), FLAG)

    def test_common_factor(self):
        p = prime(512, self.rng)
        n1, n2 = p * prime(512, self.rng), p * prime(512, self.rng)
        self.assertEqual(self.solve({"n1": n1, "n2": n2, "e": 65537, "c1": pow(M, 65537, n1), "c2": pow(M, 65537, n2)}), FLAG)

    def test_wiener_and_fermat(self):
        while True:
            p, q = prime(512, self.rng), prime(512, self.rng)
            if q < p < 2 * q:
                break
        n, phi = p * q, (p - 1) * (q - 1)
        while True:
            d = self.rng.getrandbits(200) | 1
            if math.gcd(d, phi) == 1:
                break
        e = nt.invert(d, phi)
        self.assertEqual(self.solve({"n": n, "e": e, "c": pow(M, e, n)}), FLAG)
        p = prime(512, self.rng)
        q = p + 2
        while not nt.is_prime(q):
            q += 2
        self.assertEqual(self.solve({"n": p * q, "e": 65537, "c": pow(M, 65537, p * q)}), FLAG)

    def test_parse(self):
        self.assertEqual(parse_params("n = 0x10\ne=3\nc = 5L\nn = 7"), {"e": 3, "c": 5, "n1": 16, "n2": 7})
        kind, v = parse_key("-----BEGIN RSA PUBLIC KEY-----\nMAwCBQDVyTbVAgMBAAE=\n-----END RSA PUBLIC KEY-----")
        self.assertEqual((v["n"], v["e"]), (0xd5c936d5, 65537))


class TestDlog(unittest.TestCase):
    def test_dlog_and_ecc(self):
        p = 9288760545485721301
        r = run("modern.dlog", {"text": str(pow(3, 0x666c6167, p)), "g": "3", "p": str(p)})["output"]
        self.assertEqual(dict(r["items"])["x 转成字节"], "flag")
        from ctfkit.crypto.ecc import Curve
        E = Curve(2, 3, 65537)
        Q = E.mul(31337, (2, 23365))
        r = run("modern.ecc", {"text": "2, 23365", "op": "离散对数：求 k 使 k·P = Q", "Q": "%d, %d" % Q, "p": "65537"})["output"]
        self.assertEqual(dict(r["items"])["k"], 31337)


if __name__ == "__main__":
    unittest.main()
