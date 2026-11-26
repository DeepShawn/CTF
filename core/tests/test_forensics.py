"""杂项、取证、隐写工具测试。"""

import io
import struct
import unittest
import zipfile
import zlib

from ctfkit import imagelib
from ctfkit.registry import run


def b64(data):
    import base64
    return {"$b64": base64.b64encode(data).decode()}


def out(tid, **kw):
    r = run(tid, kw)
    if not r["ok"]:
        raise AssertionError("%s: %s" % (tid, r["error"]))
    return r["output"]


def flat(o):
    if o["type"] == "group":
        return sum((flat(x) for x in o["items"]), [])
    return [o]


def make_png(w, h, pixels, mode="RGB"):
    return imagelib.encode_png(w, h, pixels, mode)


class TestImageStego(unittest.TestCase):
    def test_png_fix_height(self):
        png = bytearray(make_png(30, 50, [(i % 256, 0, 0) for i in range(1500)]))
        png[20:24] = struct.pack(">I", 25)                 # 改小高度，CRC 不变
        r = flat(out("stego.png", file=b64(bytes(png))))
        info = dict(r[0]["items"])
        self.assertEqual(info["原始宽高（按 CRC 爆破）"], "30 × 50")

    def test_lsb_roundtrip(self):
        px = [(100, 150, 200)] * 1600
        msg = b"flag{lsb}"
        bits = "".join("{:08b}".format(x) for x in msg)
        for i, bit in enumerate(bits):
            p = list(px[i // 3])
            p[i % 3] = (p[i % 3] & 0xFE) | int(bit)
            px[i // 3] = tuple(p)
        png = make_png(40, 40, px)
        r = out("stego.lsb", file=b64(png), mode="自动尝试")
        self.assertEqual(r["rows"][0][5], "flag{lsb}")

    def test_combine_xor(self):
        a = make_png(10, 10, [(i, i, i) for i in range(100)])
        b = make_png(10, 10, [(i ^ 0x55, i, i) for i in range(100)])
        r = flat(out("stego.combine", file=b64(a), file2=b64(b), op="异或"))
        self.assertTrue(any(it["type"] == "image" for it in r))

    def test_pixels_to_image(self):
        r = flat(out("stego.pixels", text="1" * 16 + "0" * 16 + "1" * 16, width=0))
        self.assertTrue(any(it["type"] == "image" for it in r))


class TestFiles(unittest.TestCase):
    def test_identify_and_carve(self):
        png = make_png(5, 5, [(0, 0, 0)] * 25)
        blob = png + b"PK\x03\x04" + b"X" * 20
        r = flat(out("forensics.filetype", file=b64(blob)))
        self.assertEqual(dict(r[0]["items"])["识别结果"], "PNG 图片")
        self.assertTrue(any("ZIP" in str(row) for row in r[1]["rows"]))

    def test_strings_hexview(self):
        data = b"\x00\x01flag{strings_here}\xff\xfe"
        r = flat(out("forensics.strings", file=b64(data), min_len=4))
        self.assertIn("flag{strings_here}", dict(r[0]["items"])["疑似 flag"])
        r = flat(out("forensics.hexview", file=b64(data), search="flag"))

    def test_zip_fake_encrypt(self):
        zb = io.BytesIO()
        with zipfile.ZipFile(zb, "w") as z:
            z.writestr("f.txt", "flag{fake}")
        raw = bytearray(zb.getvalue())
        raw[raw.find(b"PK\x03\x04") + 6] |= 1
        raw[raw.find(b"PK\x01\x02") + 8] |= 1
        r = flat(out("forensics.zip", file=b64(bytes(raw))))
        self.assertIn("伪加密", dict(r[0]["items"])["判断"])

    def test_zip_crack(self):
        import os
        import subprocess
        import tempfile
        d = tempfile.mkdtemp()
        with open(d + "/f.txt", "w") as fp:
            fp.write("flag{pw}")
        try:
            subprocess.run(["zip", "-q", "-P", "321", "-j", d + "/a.zip", d + "/f.txt"], check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            self.skipTest("没有 zip 命令")
        enc = open(d + "/a.zip", "rb").read()
        r = flat(out("forensics.zip_crack", file=b64(enc), charset="数字", max_len=3))
        self.assertEqual(dict(r[0]["items"])["密码"], "321")

    def test_crc32(self):
        r = flat(out("forensics.crc32", text="0x%08x,4" % (zlib.crc32(b"flag") & 0xFFFFFFFF)))
        self.assertEqual(dict(r[-1]["items"])["按顺序拼接"], "flag")


class TestPcapUsb(unittest.TestCase):
    def _pcap(self, frames):
        out_ = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for f in frames:
            out_ += struct.pack("<IIII", 0, 0, len(f), len(f)) + f
        return bytes(out_)

    def _eth_ip(self, proto, payload):
        h = bytearray(20)
        h[0] = 0x45
        h[9] = proto
        h[12:16] = b"\x0a\0\0\1"
        h[16:20] = b"\x0a\0\0\2"
        struct.pack_into(">H", h, 2, 20 + len(payload))
        return b"\xff" * 6 + b"\x11" * 6 + b"\x08\x00" + bytes(h) + payload

    def test_icmp(self):
        pkts = [self._eth_ip(1, b"\x08\x00\x00\x00\x00\x00\x00\x00" + bytes([c])) for c in b"flag"]
        r = flat(out("forensics.pcap", file=b64(self._pcap(pkts)), view="ICMP 载荷"))
        self.assertTrue(any("flag" in str(it) for it in r))

    def test_usb_keyboard(self):
        reports = [bytes([0, 0, k, 0, 0, 0, 0, 0]) for k in (0x09, 0x0F, 0x04, 0x0A)]
        r = out("forensics.usb", text="\n".join(x.hex() for x in reports), device="键盘")
        self.assertEqual(dict(r["items"])["还原的输入"], "flag")


class TestTextStego(unittest.TestCase):
    def test_zero_width(self):
        bits = "".join("{:08b}".format(x) for x in b"hi")
        zw = "a" + "".join("​" if b == "0" else "‌" for b in bits) + "b"
        r = flat(out("stego.zerowidth", text=zw))
        self.assertTrue(any("hi" in str(row) for row in r[1]["rows"]))

    def test_homoglyph(self):
        r = flat(out("stego.homoglyph", text="flаg"))
        self.assertEqual(r[0]["rows"][0][2], "U+0430")


if __name__ == "__main__":
    unittest.main()
