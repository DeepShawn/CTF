# -*- coding: utf-8 -*-
from __future__ import print_function

def hide(pixels, secret):
    """把 secret 的每一位依次写进 pixels 每个字节的最低位"""
    out = bytearray(pixels)
    bits = "".join("{:08b}".format(b) for b in bytearray(secret))
    assert len(bits) <= len(out), "图片太小，装不下"
    for i, bit in enumerate(bits):
        out[i] = (out[i] & 0xFE) | int(bit)
    return out

def extract(pixels, length):
    """读出前 length 个字节的隐藏内容"""
    bits = "".join(str(b & 1) for b in bytearray(pixels)[:length * 8])
    return bytearray(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))

pixels = bytearray((i * 37) % 256 for i in range(300))   # 假装是 100 个 RGB 像素
stego = hide(pixels, b"flag{lsb}")
changed = sum(1 for a, b in zip(pixels, stego) if a != b)
print("改动的字节数:", changed, "最大差值:", max(abs(a - b) for a, b in zip(pixels, stego)))
print(extract(stego, 9).decode())
