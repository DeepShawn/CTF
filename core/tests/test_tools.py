"""ctfkit 单元测试：标准测试向量 + 每个工具的示例 + 编码类工具的往返测试。

运行：在 core 目录下执行 python -m unittest discover -s tests -v
"""

import json
import random
import unittest

from ctfkit.registry import all_tools, manifest, run, run_json, source


def out(tid, **params):
    r = run(tid, params)
    if not r["ok"]:
        raise AssertionError("%s 出错：%s" % (tid, r["error"]))
    o = r["output"]
    return o["value"] if o["type"] == "text" else o


class TestVectors(unittest.TestCase):
    def test_rfc4648_base64(self):
        vec = {"": "", "f": "Zg==", "fo": "Zm8=", "foo": "Zm9v", "foob": "Zm9vYg==", "fooba": "Zm9vYmE=", "foobar": "Zm9vYmFy"}
        for p, c in vec.items():
            self.assertEqual(out("encoding.base64", text=p, mode="编码"), c)
            if p:
                self.assertEqual(out("encoding.base64", text=c, mode="解码"), p)
        self.assertEqual(out("encoding.base64", text="Zm9vYg", mode="解码"), "foob")   # 缺少 = 时自动补齐

    def test_rfc4648_base32_base16(self):
        vec = {"f": "MY======", "fo": "MZXQ====", "foo": "MZXW6===", "foob": "MZXW6YQ=", "fooba": "MZXW6YTB", "foobar": "MZXW6YTBOI======"}
        for p, c in vec.items():
            self.assertEqual(out("encoding.base32", text=p, mode="编码"), c)
            self.assertEqual(out("encoding.base32", text=c, mode="解码"), p)
        self.assertEqual(out("encoding.base16", text="foobar", mode="编码"), "666F6F626172")

    def test_custom_base64_table(self):
        table = "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA9876543210+/"
        enc = out("encoding.base64", text="flag{custom}", mode="编码", table="自定义", custom=table)
        self.assertEqual(out("encoding.base64", text=enc, mode="解码", table="自定义", custom=table), "flag{custom}")
        self.assertIn("码表", run("encoding.base64", {"text": "x", "table": "自定义", "custom": "abc"})["error"])

    def test_base58_base91_base92(self):
        self.assertEqual(out("encoding.base58", text="hello world", mode="编码"), "StV1DL6CwTryKyV")
        self.assertEqual(out("encoding.base91", text="test", mode="编码"), "fPNKd")
        self.assertEqual(out("encoding.base92", text="hello world", mode="编码"), "Fc_$aOTdKnsM*k")

    def test_hash_vectors(self):
        rows = {r[0]: r[2] for r in out("hash.digest", text="abc")["rows"]}
        self.assertEqual(rows["MD5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(rows["SHA1"], "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(rows["SHA256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(rows["SHA3-256"], "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        self.assertEqual(rows["CRC32"], "352441c2")
        self.assertEqual(out("hash.hmac", text="The quick brown fox jumps over the lazy dog", key="key", algorithm="sha256"),
                         "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")

    def test_crack(self):
        r = out("hash.crack", text="81dc9bdb52d04dc20036dbd8313ed055", max_len=4)
        self.assertEqual(r["rows"][0][1], "1234")
        import hashlib
        h = hashlib.md5(b"flag{42}").hexdigest()
        r = out("hash.crack", text=h, template="flag{*}", max_len=2)
        self.assertEqual(r["rows"][0][1], "flag{42}")
        r = out("hash.crack", text=hashlib.md5(b"777").hexdigest()[:6], prefix=True, max_len=3)
        self.assertEqual(r["rows"][0][1], "777")


class TestClassical(unittest.TestCase):
    def test_known(self):
        self.assertEqual(out("classical.affine", text="AFFINE CIPHER", mode="加密", a=5, b=8), "IHHWVC SWFRCP")
        self.assertEqual(out("classical.hill", text="help", mode="加密", key="3 3 2 5"), "hiat")
        self.assertEqual(out("classical.playfair", text="hide the gold in the tree stump", mode="加密", key="playfair example"),
                         "bmodzbxdnabekudmuixmmouvif")
        self.assertEqual(out("classical.vigenere", text="attackatdawn", mode="加密", key="lemon"), "lxfopvefrnhr")
        self.assertEqual(out("classical.rot", text="flag", variant="ROT47"), "7=28")
        self.assertEqual(out("classical.atbash", text="abcxyz"), "zyxcba")

    def test_caesar_bruteforce_ranks_answer_first(self):
        r = out("classical.caesar", text="synt{pnrfne_vf_rnfl}")
        self.assertEqual(r["rows"][0][2], "flag{caesar_is_easy}")

    def test_railfence_roundtrip(self):
        for variant in ("普通型", "W 型"):
            for k in range(2, 8):
                c = out("classical.railfence", text="flag{rail_fence_cipher}", mode="加密", variant=variant, key=k)
                self.assertEqual(out("classical.railfence", text=c, mode="解密", variant=variant, key=k), "flag{rail_fence_cipher}")
        self.assertEqual(out("classical.railfence", text="WECRLTEERDSOEEFEAOCAIVDEN", mode="解密", variant="W 型", key=3),
                         "WEAREDISCOVEREDFLEEATONCE")

    def test_vigenere_crack(self):
        plain = ("It was the best of times, it was the worst of times, it was the age of wisdom, "
                 "it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity.")
        c = out("classical.vigenere", text=plain, mode="加密", key="crypto")
        r = out("classical.vigenere", text=c, mode="无密钥破解")
        self.assertEqual(r["rows"][0][3], "crypto")

    def test_bacon_both_alphabets(self):
        for v in ("26 字母", "24 字母"):
            c = out("classical.bacon", text="flag", mode="编码", variant=v)
            self.assertEqual(out("classical.bacon", text=c, mode="解码", variant=v), "flag")

    def test_keyboard(self):
        self.assertEqual(out("classical.keyboard", text="王夫 井工 夫田", variant="当铺密码").splitlines()[0], "CTF")
        self.assertEqual(out("classical.keyboard", text="333 555 2 4", variant="九宫格（重复次数）"), "flag")


ROUNDTRIP = [
    ("encoding.base64", {}), ("encoding.base32", {}), ("encoding.base58", {}), ("encoding.base62", {}),
    ("encoding.base85", {"variant": "ASCII85"}), ("encoding.base85", {"variant": "RFC 1924"}),
    ("encoding.base91", {}), ("encoding.base92", {}), ("encoding.quoted_printable", {}),
    ("encoding.uuencode", {}), ("encoding.xxencode", {}), ("encoding.url", {}), ("encoding.url", {"all": True}),
    ("encoding.unicode", {}), ("encoding.html", {"all": True}), ("encoding.corevalues", {}), ("encoding.shellcode", {}),
    ("encoding.base16", {}),
]


class TestRoundTrip(unittest.TestCase):
    def test_encode_then_decode(self):
        rng = random.Random(2026)
        samples = ["flag{round_trip}", "a", "你好，CTF！", "".join(chr(rng.randint(32, 126)) for _ in range(200)),
                   "line1\nline2"]
        for tid, opts in ROUNDTRIP:
            for s in samples:
                if tid == "encoding.morse":
                    continue
                enc = out(tid, text=s, mode="编码", **opts)
                dec = out(tid, text=enc, mode="解码", **{k: v for k, v in opts.items() if k == "variant"})
                self.assertEqual(dec, s, "%s %r -> %r -> %r" % (tid, s, enc, dec))

    def test_morse(self):
        enc = out("encoding.morse", text="FLAG IS MORSE 123", mode="编码")
        self.assertEqual(out("encoding.morse", text=enc, mode="解码"), "FLAG IS MORSE 123")
        enc = out("encoding.morse", text="SOS", mode="编码", dot="0", dash="1")
        self.assertEqual(enc, "000 111 000")
        self.assertEqual(out("encoding.morse", text=enc, mode="解码", dot="0", dash="1"), "SOS")

    def test_brainfuck(self):
        bf = out("encoding.brainfuck", text="flag{brainfuck}", action="文本 → Brainfuck")
        self.assertEqual(out("encoding.brainfuck", text=bf), "flag{brainfuck}")


class TestMagicAndMisc(unittest.TestCase):
    def test_magic_multilayer(self):
        import base64
        s = base64.b32encode(base64.b64encode(b"flag{three_layers}").hex().encode()).decode()
        r = out("encoding.magic", text=s)
        self.assertEqual(r["rows"][0][2], "flag{three_layers}")
        self.assertEqual(r["rows"][0][1], "Base32 → 十六进制 → Base64")

    def test_py2check(self):
        r = out("misc.py2check", text="print 'hi'\nexcept Exception, e:\nx = raw_input()\ns.encode('hex')")
        names = {row[1] for row in r["rows"]}
        self.assertTrue({"print 语句", "except X, e 写法", "raw_input()", ".encode('hex' / 'base64')"} <= names)

    def test_flagsearch(self):
        r = out("misc.flagsearch", text="aaa\nZmxhZ3tiNjR9\n}desrever{galf")
        kinds = {row[1] for row in r["rows"]}
        self.assertIn("Base64（偏移 0）", kinds)
        self.assertIn("反转", kinds)


class TestRegistry(unittest.TestCase):
    def test_every_example_runs(self):
        for t in all_tools():
            for ex in t["examples"]:
                r = run(t["id"], ex)
                self.assertTrue(r["ok"], "%s 示例 %r 出错：%s" % (t["id"], ex, r.get("error")))

    def test_manifest_is_json(self):
        m = json.loads(json.dumps(manifest(), ensure_ascii=False))
        self.assertGreaterEqual(len(m["tools"]), 40)
        for t in m["tools"]:
            self.assertTrue(t["principle"], t["id"] + " 缺少原理讲解")
            self.assertTrue(t["summary"], t["id"] + " 缺少简介")
            for f in t["inputs"] + t["options"]:
                self.assertIn(f["type"], {"text", "string", "number", "select", "segmented", "switch"})
            self.assertTrue(source(t["id"]))

    def test_errors_are_readable(self):
        r = json.loads(run_json("encoding.base64", json.dumps({"text": "@@@@", "mode": "解码"})))
        self.assertFalse(r["ok"])
        self.assertIn("码表以外", r["error"])
        self.assertFalse(run("no.such.tool")["ok"])


if __name__ == "__main__":
    unittest.main()
