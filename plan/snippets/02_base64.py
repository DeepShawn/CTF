# -*- coding: utf-8 -*-
from __future__ import print_function
import base64

TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def b64encode(data):
    bits = "".join("{:08b}".format(b) for b in bytearray(data))
    bits += "0" * (-len(bits) % 6)
    out = "".join(TABLE[int(bits[i:i + 6], 2)] for i in range(0, len(bits), 6))
    return out + "=" * (-len(out) % 4)

msg = u"flag{你好}".encode("utf-8")
print(b64encode(msg))
assert b64encode(msg) == base64.b64encode(msg).decode("ascii")
