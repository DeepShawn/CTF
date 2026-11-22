# -*- coding: utf-8 -*-
from __future__ import print_function, division
import sys

s = b"flag"
print("Python", sys.version_info[0])
print("b'flag' 的类型:", type(s).__name__)
print("s[0] =", repr(s[0]))                    # Python 2 得到 'f'，Python 3 得到 102
print("bytearray(s)[0] =", bytearray(s)[0])   # 两个版本都是 102
print("7 / 2 =", 7 / 2, " 7 // 2 =", 7 // 2)  # 加了 from __future__ import division 后两个版本一致
print("十六进制:", bytearray(b"flag").hex() if hasattr(bytearray, "hex") else b"flag".encode("hex"))
