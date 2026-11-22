# -*- coding: utf-8 -*-
from __future__ import print_function
import struct, zlib

def fix_height(png):
    """IHDR 的 CRC 对不上时，枚举高度找回真实值"""
    ihdr = png[12:29]                     # 'IHDR' + 13 字节数据
    crc, = struct.unpack(">I", png[29:33])
    w, = struct.unpack(">I", ihdr[4:8])
    for h in range(1, 4096):
        data = ihdr[:8] + struct.pack(">I", h) + ihdr[12:]
        if zlib.crc32(data) & 0xFFFFFFFF == crc:
            return w, h
    return None

# 自测：宽 100、高 300 的 IHDR，再把高度改成 100
body = b"IHDR" + struct.pack(">IIBBBBB", 100, 300, 8, 2, 0, 0, 0)
png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
png = png[:20] + struct.pack(">I", 100) + png[24:]
print(fix_height(png))
