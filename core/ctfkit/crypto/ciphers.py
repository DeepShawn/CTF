"""纯 Python 实现的 AES、DES / 3DES、RC4 与分组模式（教材 3.2）。

为什么自己实现：浏览器和手机上不一定有 pycryptodome（iOS 没有现成的包），而且写成纯 Python 便于对照原理阅读。
代码按标准（FIPS-197、FIPS 46-3）逐步实现，用标准测试向量验证；速度比 C 实现慢得多，只适合处理题目中的小数据。
"""

# ================================================================ AES（FIPS-197）

SBOX = [0] * 256
INV_SBOX = [0] * 256


def _init_sbox():
    # 由 GF(2^8) 上的求逆加仿射变换生成 S 盒，而不是抄一张表
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)          # p × 3
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09                                                     # q ÷ 3
        x = q ^ ((q << 1 | q >> 7) & 0xFF) ^ ((q << 2 | q >> 6) & 0xFF) ^ ((q << 3 | q >> 5) & 0xFF) ^ ((q << 4 | q >> 4) & 0xFF)
        SBOX[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    SBOX[0] = 0x63
    for i, v in enumerate(SBOX):
        INV_SBOX[v] = i


_init_sbox()


def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = xtime(a)
        b >>= 1
    return r


MUL = {k: [gmul(i, k) for i in range(256)] for k in (2, 3, 9, 11, 13, 14)}


def aes_expand_key(key):
    nk = len(key) // 4
    if len(key) not in (16, 24, 32):
        raise ValueError("AES 密钥必须是 16、24 或 32 字节，当前为 %d 字节" % len(key))
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def _shift_rows(s, inv=False):
    # 状态按列存放：s[r + 4c]
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            src = (c + r) % 4 if not inv else (c - r) % 4
            out[r + 4 * c] = s[r + 4 * src]
    return out


def _mix_columns(s, inv=False):
    out = []
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        if not inv:
            m2, m3 = MUL[2], MUL[3]
            out += [m2[a[0]] ^ m3[a[1]] ^ a[2] ^ a[3], a[0] ^ m2[a[1]] ^ m3[a[2]] ^ a[3],
                    a[0] ^ a[1] ^ m2[a[2]] ^ m3[a[3]], m3[a[0]] ^ a[1] ^ a[2] ^ m2[a[3]]]
        else:
            m9, m11, m13, m14 = MUL[9], MUL[11], MUL[13], MUL[14]
            out += [m14[a[0]] ^ m11[a[1]] ^ m13[a[2]] ^ m9[a[3]], m9[a[0]] ^ m14[a[1]] ^ m11[a[2]] ^ m13[a[3]],
                    m13[a[0]] ^ m9[a[1]] ^ m14[a[2]] ^ m11[a[3]], m11[a[0]] ^ m13[a[1]] ^ m9[a[2]] ^ m14[a[3]]]
    return out


class AES:
    block_size = 16

    def __init__(self, key):
        self.rk = aes_expand_key(bytes(key))
        self.nr = len(self.rk) - 1

    def encrypt_block(self, block):
        s = [a ^ b for a, b in zip(block, self.rk[0])]
        for r in range(1, self.nr + 1):
            s = _shift_rows([SBOX[b] for b in s])          # 字节代换 + 行移位
            if r != self.nr:
                s = _mix_columns(s)                         # 列混合（最后一轮没有）
            s = [a ^ b for a, b in zip(s, self.rk[r])]      # 轮密钥加
        return bytes(s)

    def decrypt_block(self, block):
        s = [a ^ b for a, b in zip(block, self.rk[self.nr])]
        for r in range(self.nr - 1, -1, -1):
            s = [INV_SBOX[b] for b in _shift_rows(s, inv=True)]
            s = [a ^ b for a, b in zip(s, self.rk[r])]
            if r:
                s = _mix_columns(s, inv=True)
        return bytes(s)


# ================================================================ DES（FIPS 46-3）

IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
FP = [IP.index(i) + 1 for i in range(1, 65)]
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
SBOXES = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _permute(v, table, nbits):
    out = 0
    for t in table:
        out = (out << 1) | ((v >> (nbits - t)) & 1)
    return out


def des_subkeys(key):
    if len(key) != 8:
        raise ValueError("DES 密钥必须是 8 字节，当前为 %d 字节" % len(key))
    k = _permute(int.from_bytes(key, "big"), PC1, 64)
    c, d = k >> 28, k & 0xFFFFFFF
    out = []
    for s in SHIFTS:
        c = ((c << s) | (c >> (28 - s))) & 0xFFFFFFF
        d = ((d << s) | (d >> (28 - s))) & 0xFFFFFFF
        out.append(_permute((c << 28) | d, PC2, 56))
    return out


def _feistel(r, k):
    x = _permute(r, E, 32) ^ k
    out = 0
    for i in range(8):
        b = (x >> (42 - 6 * i)) & 0x3F
        row = ((b >> 4) & 2) | (b & 1)
        col = (b >> 1) & 0xF
        out = (out << 4) | SBOXES[i][row * 16 + col]
    return _permute(out, P, 32)


def des_block(block, subkeys):
    v = _permute(int.from_bytes(block, "big"), IP, 64)
    l, r = v >> 32, v & 0xFFFFFFFF
    for k in subkeys:
        l, r = r, l ^ _feistel(r, k)          # Feistel 结构：左右交换，右半经过轮函数
    return _permute((r << 32) | l, FP, 64).to_bytes(8, "big")


class DES:
    block_size = 8

    def __init__(self, key):
        self.k = des_subkeys(bytes(key))

    def encrypt_block(self, b):
        return des_block(b, self.k)

    def decrypt_block(self, b):
        return des_block(b, self.k[::-1])


class TripleDES:
    """3DES（EDE）：密钥 16 字节（K1 K2 K1）或 24 字节（K1 K2 K3）。"""
    block_size = 8

    def __init__(self, key):
        key = bytes(key)
        if len(key) == 16:
            key += key[:8]
        if len(key) != 24:
            raise ValueError("3DES 密钥必须是 16 或 24 字节，当前为 %d 字节" % len(key))
        self.a, self.b, self.c = DES(key[:8]), DES(key[8:16]), DES(key[16:])

    def encrypt_block(self, x):
        return self.c.encrypt_block(self.b.decrypt_block(self.a.encrypt_block(x)))

    def decrypt_block(self, x):
        return self.a.decrypt_block(self.b.encrypt_block(self.c.decrypt_block(x)))


# ================================================================ 填充

def pad(data, bs, scheme="PKCS#7"):
    n = bs - len(data) % bs
    if scheme == "PKCS#7":
        return data + bytes([n]) * n
    if scheme == "ANSI X9.23":
        return data + b"\0" * (n - 1) + bytes([n])
    if scheme == "ISO/IEC 7816-4":
        return data + b"\x80" + b"\0" * (n - 1)
    if scheme == "零填充":
        return data + b"\0" * (n % bs)
    return data


def unpad(data, bs, scheme="PKCS#7"):
    if not data:
        return data
    if scheme in ("PKCS#7", "ANSI X9.23"):
        n = data[-1]
        if not 1 <= n <= bs or (scheme == "PKCS#7" and data[-n:] != bytes([n]) * n):
            raise ValueError("填充不正确（最后一个字节为 0x%02x）：密钥、IV 或模式可能不对" % n)
        return data[:-n]
    if scheme == "ISO/IEC 7816-4":
        i = data.rstrip(b"\0")
        if not i.endswith(b"\x80"):
            raise ValueError("填充不正确：没有找到 0x80 标记")
        return i[:-1]
    if scheme == "零填充":
        return data.rstrip(b"\0")
    return data


# ================================================================ 分组模式

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _ctr_inc(counter):
    return ((int.from_bytes(counter, "big") + 1) % (1 << (8 * len(counter)))).to_bytes(len(counter), "big")


def mode_encrypt(cipher, mode, data, iv=b""):
    bs = cipher.block_size
    out = bytearray()
    if mode == "ECB":
        if len(data) % bs:
            raise ValueError("ECB 模式的数据长度必须是 %d 的倍数，请选择填充方式" % bs)
        for i in range(0, len(data), bs):
            out += cipher.encrypt_block(data[i:i + bs])
    elif mode == "CBC":
        if len(data) % bs:
            raise ValueError("CBC 模式的数据长度必须是 %d 的倍数，请选择填充方式" % bs)
        prev = iv
        for i in range(0, len(data), bs):
            prev = cipher.encrypt_block(xor_bytes(data[i:i + bs], prev))
            out += prev
    elif mode == "CFB":
        prev = iv
        for i in range(0, len(data), bs):
            ct = xor_bytes(data[i:i + bs], cipher.encrypt_block(prev))
            out += ct
            prev = ct if len(ct) == bs else prev
    elif mode == "OFB":
        s = iv
        for i in range(0, len(data), bs):
            s = cipher.encrypt_block(s)
            out += xor_bytes(data[i:i + bs], s)
    elif mode == "CTR":
        ctr = iv
        for i in range(0, len(data), bs):
            out += xor_bytes(data[i:i + bs], cipher.encrypt_block(ctr))
            ctr = _ctr_inc(ctr)
    else:
        raise ValueError("未知模式 %s" % mode)
    return bytes(out)


def mode_decrypt(cipher, mode, data, iv=b""):
    bs = cipher.block_size
    out = bytearray()
    if mode in ("ECB", "CBC") and len(data) % bs:
        raise ValueError("%s 模式的密文长度必须是 %d 的倍数，当前为 %d 字节：检查输入格式（十六进制 / Base64）是否选对" % (mode, bs, len(data)))
    if mode == "ECB":
        for i in range(0, len(data), bs):
            out += cipher.decrypt_block(data[i:i + bs])
    elif mode == "CBC":
        prev = iv
        for i in range(0, len(data), bs):
            blk = data[i:i + bs]
            out += xor_bytes(cipher.decrypt_block(blk), prev)
            prev = blk
    elif mode == "CFB":
        prev = iv
        for i in range(0, len(data), bs):
            blk = data[i:i + bs]
            out += xor_bytes(blk, cipher.encrypt_block(prev))
            prev = blk if len(blk) == bs else prev
    else:                                                     # OFB、CTR 加解密相同
        return mode_encrypt(cipher, mode, data, iv)
    return bytes(out)


# ================================================================ RC4

def rc4(key, data, drop=0):
    s = list(range(256))
    j = 0
    for i in range(256):                                      # KSA：用密钥打乱 S 盒
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for n in range(drop + len(data)):                         # PRGA：生成密钥流并与数据异或
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        if n >= drop:
            out.append(data[n - drop] ^ k)
    return bytes(out)
