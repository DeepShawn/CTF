# -*- coding: utf-8 -*-
from __future__ import print_function

def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y

def inverse(e, phi):
    g, x, _ = egcd(e, phi)
    assert g == 1
    return x % phi

p, q, e = 61, 53, 17
n, phi = p * q, (p - 1) * (q - 1)
d = inverse(e, phi)
m = 65
c = pow(m, e, n)
print("n =", n, "d =", d, "c =", c, "m =", pow(c, d, n))

def iroot(x, k):
    """整数 k 次方根（二分）"""
    lo, hi = 0, 1 << (x.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo

# 小 e 攻击：m^3 < n 时，c 就是 m^3 本身
m = int.from_bytes(b"flag{small_e}", "big") if hasattr(int, "from_bytes") else int(b"flag{small_e}".encode("hex"), 16)
n = (1 << 2048) + 981
c = pow(m, 3, n)
r = iroot(c, 3)
print(r == m, bytearray.fromhex("%x" % r).decode())
