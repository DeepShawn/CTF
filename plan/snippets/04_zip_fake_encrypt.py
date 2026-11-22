# -*- coding: utf-8 -*-
from __future__ import print_function
import struct, sys, io, zipfile

def scan(data):
    """列出 ZIP 中每个文件的通用位标记（General purpose bit flag）"""
    data = bytearray(data)
    i = 0
    while True:
        i = data.find(b"PK\x01\x02", i)      # 中央目录记录
        if i < 0:
            break
        flag, = struct.unpack("<H", bytes(data[i + 8:i + 10]))
        n, = struct.unpack("<H", bytes(data[i + 28:i + 30]))
        name = bytes(data[i + 46:i + 46 + n]).decode("utf-8", "replace")
        print(name, "加密位 =", flag & 1)
        i += 4

def unfake(data):
    """把所有记录的加密位清零，返回修复后的字节"""
    data = bytearray(data)
    for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        i = 0
        while True:
            i = data.find(sig, i)
            if i < 0:
                break
            data[i + off] &= 0xFE
            i += 4
    return bytes(data)

# 自测：造一个“伪加密”压缩包
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("flag.txt", "flag{fake_encrypt}")
raw = bytearray(buf.getvalue())
for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
    raw[raw.find(sig) + off] |= 1
scan(raw)
fixed = unfake(raw)
scan(fixed)
print(zipfile.ZipFile(io.BytesIO(fixed)).read("flag.txt"))
