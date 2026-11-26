"""Web / 逆向 / PWN / 工控工具测试。"""

import base64
import re
import struct
import subprocess
import unittest

from ctfkit.registry import run


def out(tid, **kw):
    r = run(tid, kw)
    if not r["ok"]:
        raise AssertionError("%s: %s" % (tid, r["error"]))
    return r["output"]


def b64f(data):
    return {"$b64": base64.b64encode(data).decode()}


def fields_dict(o):
    if o["type"] == "group":
        d = {}
        for it in o["items"]:
            if it["type"] == "fields":
                d.update(dict(it["items"]))
        return d
    return dict(o["items"])


class TestWeb(unittest.TestCase):
    def test_jwt(self):
        import hashlib
        import hmac
        import json

        def enc(d):
            return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("=")
        h, p = enc({"alg": "HS256", "typ": "JWT"}), enc({"user": "guest", "admin": False})
        sig = base64.urlsafe_b64encode(hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest()).decode().rstrip("=")
        jwt = f"{h}.{p}.{sig}"
        r = out("web.jwt", text=jwt, action="弱密钥爆破（HS256）")
        self.assertEqual(dict(r["items"])["找到密钥"], "secret")
        r = out("web.jwt", text=jwt, action="伪造 none 算法", payload='{"admin": true}')
        self.assertTrue(dict(r["items"])["伪造的 JWT（none 算法）"].endswith("."))

    def test_php_serialize(self):
        r = out("web.php_serialize", text='{"name": "admin", "admin": true}', action="JSON → 序列化")
        self.assertEqual(r["value"], 'a:2:{s:4:"name";s:5:"admin";s:5:"admin";b:1;}')

    def test_ssrf_ip(self):
        r = dict(out("web.ssrf", text="127.0.0.1", action="IP 写法转换")["items"])
        self.assertEqual(r["十进制整数"], "2130706433")

    def test_http_curl(self):
        r = out("web.http", text="GET /?a=1 HTTP/1.1\nHost: x.com\n", output="curl")
        self.assertIn("curl -X GET", r["value"])


class TestPwn(unittest.TestCase):
    def test_cyclic(self):
        seq = out("pwn.cyclic", text="100", action="生成")["value"]
        self.assertEqual(len(seq), 100)
        off = dict(out("pwn.cyclic", text="kaaa", action="查找偏移", n="4")["items"])["偏移"]
        self.assertEqual(off, 40)

    def test_pack(self):
        r = dict(out("pwn.pack", text="0x400586", action="打包（整数→字节）", bits="64")["items"])
        self.assertEqual(r["字节（十六进制）"], "8605400000000000")

    def test_fmtstr_simulate(self):
        for val in (0x12345678, 0xDEADBEEF, 0):
            for write in ("hhn（1字节×4）", "hn（2字节×2）"):
                p = eval(dict(out("pwn.fmtstr", text="0x601028", value=hex(val), offset=6, bits="64", write=write)["items"])["payload（Python 字节串）"])
                mem = self._sim(p, 6, 8)
                sz = 1 if "hh" in write else 2
                got = sum(mem.get(0x601028 + sz * i, 0) << (8 * sz * i) for i in range(8 // sz))
                self.assertEqual(got, val & 0xFFFFFFFF)

    def _sim(self, payload, start, nb):
        stack = [payload[i:i + nb] for i in range(0, len(payload), nb)]
        count, mem, i = 0, {}, 0
        while i < len(payload):
            m = re.match(rb"%(\d+)\$(hh?)?n", payload[i:])
            mc = re.match(rb"%(\d+)c", payload[i:])
            if m:
                w = {b"hh": 1, b"h": 2, None: nb}[m.group(2)]
                mem[int.from_bytes(stack[int(m.group(1)) - start], "little")] = count & ((1 << (8 * w)) - 1)
                i += m.end()
            elif mc:
                count += int(mc.group(1))
                i += mc.end()
            else:
                count += 1
                i += 1
        return mem

    def test_ret2libc(self):
        r = dict(out("pwn.ret2libc", text="0x7f1234567890", leak_off="0x80e50", system_off="0x4f550", binsh_off="0x1b3e1a")["items"])
        self.assertEqual(r["libc 基址"], hex(0x7F1234567890 - 0x80E50))

    def test_safelinking(self):
        pos, ptr = 0x5555555592A0, 0x555555559290
        enc = (pos >> 12) ^ ptr
        r = dict(out("pwn.safelinking", text=hex(enc), action="解密", pos=hex(pos))["items"])
        self.assertEqual(int(r["解密结果"], 16), ptr)

    def test_checksec(self):
        try:
            subprocess.run(["gcc", "-m64", "-no-pie", "-fno-stack-protector", "-o", "/tmp/_cs", "-xc", "-"],
                           input=b"int main(){return 0;}", check=True)
        except Exception:
            self.skipTest("no gcc")
        data = open("/tmp/_cs", "rb").read()
        r = dict(out("pwn.checksec", file=b64f(data))["items"])
        self.assertEqual(r["PIE（地址随机化）"], "关闭")
        self.assertEqual(r["Canary（栈保护）"], "关闭")
        r = fields_dict(out("reverse.fileinfo", file=b64f(data)))
        self.assertEqual(r["架构"], "x86-64")


class TestReverseIcs(unittest.TestCase):
    def test_algo_detect(self):
        from ctfkit.crypto.ciphers import SBOX
        blob = b"junk" + bytes(SBOX[:16]) + b"more"
        r = out("reverse.algo", file=b64f(blob))
        self.assertTrue(any("AES" in str(row) for row in r["rows"]))

    def test_modbus_flag(self):
        text = "\n".join(struct.pack(">HHHBBHH", 0, 0, 6, 1, 6, i, ord(c)).hex() for i, c in enumerate("flag{m}"))
        o = run("ics.modbus", {"text": text})["output"]
        joined = next(dict(it["items"])["按寄存器地址顺序，写入值的低字节拼成 ASCII"] for it in o["items"] if it["type"] == "fields")
        self.assertEqual(joined, "flag{m}")

    def test_s7(self):
        pkt = "320100000400000e00000401120a10020001000084000000"
        o = run("ics.s7", {"text": pkt})["output"]
        self.assertEqual(o["rows"][0][0], "作业请求")


if __name__ == "__main__":
    unittest.main()
