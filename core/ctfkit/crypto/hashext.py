"""哈希长度扩展攻击（教材 3.4.2）。

MD5、SHA-1、SHA-256 都是 Merkle–Damgård 结构：消息补齐后分块，逐块更新内部状态，最后的状态就是哈希值。
所以知道 hash(secret ‖ data) 就等于知道“处理完 secret ‖ data ‖ padding 之后的状态”，
可以从这个状态继续处理追加的内容，得到 hash(secret ‖ data ‖ padding ‖ append)，而不需要知道 secret。
为此需要能从任意状态开始计算的哈希实现，下面按标准（RFC 1321、FIPS 180-4）用纯 Python 实现了三种算法。
"""

import hashlib
import math
import struct

from ..registry import ToolError, field, text_input, tool
from ..util import DATA_FORMATS, fields, to_bytes

M32 = 0xFFFFFFFF


def rol(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def ror(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


# ---------------------------------------------------------------- MD5

MD5_K = [int(abs(math.sin(i + 1)) * 2 ** 32) & M32 for i in range(64)]
MD5_S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4


def md5_compress(state, block):
    a, b, c, d = state
    x = struct.unpack("<16I", block)
    for i in range(64):
        if i < 16:
            f, g = (b & c) | (~b & d), i
        elif i < 32:
            f, g = (d & b) | (~d & c), (5 * i + 1) % 16
        elif i < 48:
            f, g = b ^ c ^ d, (3 * i + 5) % 16
        else:
            f, g = c ^ (b | (~d & M32)), (7 * i) % 16
        f = (f + a + MD5_K[i] + x[g]) & M32
        a, d, c, b = d, c, b, (b + rol(f, MD5_S[i])) & M32
    return [(s + v) & M32 for s, v in zip(state, (a, b, c, d))]


# ---------------------------------------------------------------- SHA-1

def sha1_compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = state
    for i in range(80):
        if i < 20:
            f, k = (b & c) | (~b & d), 0x5A827999
        elif i < 40:
            f, k = b ^ c ^ d, 0x6ED9EBA1
        elif i < 60:
            f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            f, k = b ^ c ^ d, 0xCA62C1D6
        a, b, c, d, e = (rol(a, 5) + (f & M32) + e + k + w[i]) & M32, a, rol(b, 30), c, d
    return [(s + v) & M32 for s, v in zip(state, (a, b, c, d, e))]


# ---------------------------------------------------------------- SHA-256

def _primes(n):
    out, x = [], 2
    while len(out) < n:
        if all(x % p for p in out if p * p <= x):
            out.append(x)
        x += 1
    return out


def _frac_bits(v):
    return int((v - int(v)) * 2 ** 32) & M32


def _icbrt_frac(p):
    # 素数立方根小数部分的前 32 位，用整数运算避免浮点误差
    r = round(p ** (1 / 3) * 2 ** 32)
    while r ** 3 > p << 96:
        r -= 1
    while (r + 1) ** 3 <= p << 96:
        r += 1
    return r & M32


def _isqrt_frac(p):
    return math.isqrt(p << 64) & M32


SHA256_K = [_icbrt_frac(p) for p in _primes(64)]
SHA256_IV = [_isqrt_frac(p) for p in _primes(8)]


def sha256_compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        t1 = (h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + SHA256_K[i] + w[i]) & M32
        t2 = ((ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & M32
        a, b, c, d, e, f, g, h = (t1 + t2) & M32, a, b, c, (d + t1) & M32, e, f, g
    return [(s + v) & M32 for s, v in zip(state, (a, b, c, d, e, f, g, h))]


ALGOS = {
    "md5": {"iv": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476], "f": md5_compress, "end": "<", "words": 4},
    "sha1": {"iv": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0], "f": sha1_compress, "end": ">", "words": 5},
    "sha256": {"iv": SHA256_IV, "f": sha256_compress, "end": ">", "words": 8},
}


def md_padding(length, endian):
    """长度为 length 字节的消息需要补的填充：0x80、若干 0、64 位长度（比特数）。"""
    return b"\x80" + b"\0" * ((55 - length) % 64) + struct.pack(endian + "Q", length * 8)


def digest(algo, data, state=None, prefix_len=0):
    a = ALGOS[algo]
    st = list(state or a["iv"])
    msg = data + md_padding(prefix_len + len(data), a["end"])
    for i in range(0, len(msg), 64):
        st = a["f"](st, msg[i:i + 64])
    return b"".join(struct.pack(a["end"] + "I", v) for v in st).hex()


def extend(algo, known_hash, data, append, secret_len):
    a = ALGOS[algo]
    h = bytes.fromhex(known_hash)
    if len(h) != 4 * a["words"]:
        raise ToolError("%s 的哈希应为 %d 个十六进制字符" % (algo, 8 * a["words"]))
    state = list(struct.unpack(a["end"] + "%dI" % a["words"], h))
    glue = md_padding(secret_len + len(data), a["end"])
    new_data = data + glue + append
    processed = secret_len + len(data) + len(glue)        # 已经处理过的字节数（必然是 64 的倍数）
    return new_data, digest(algo, append, state, processed)


@tool(
    "hash.length_extension", "哈希长度扩展攻击", "hash", "3.4.2",
    summary="已知 hash(secret + data) 与 secret 长度，构造追加内容后的合法哈希",
    principle="""
    很多网站用 `hash(secret + data)` 给数据签名。MD5、SHA-1、SHA-256 对消息分块逐块处理，
    **最后的内部状态就是哈希值本身**。所以攻击者拿到哈希值，就能从这个状态“接着算”：

    1. 原消息 `secret + data` 处理时被补上了填充 `padding`（`0x80`、若干 `0x00`、消息长度）；
    2. 把已知哈希作为初始状态，继续处理 `append`，得到的就是 `hash(secret + data + padding + append)`；
    3. 把 `data + padding + append` 作为新数据提交，服务器算出的签名与我们构造的一致。

    需要知道 secret 的**长度**（不知道时可以从 1 开始逐个尝试）。新数据中的填充含有不可打印字节，
    放进 URL 时要做 URL 编码（结果中已给出）。防御方法是改用 HMAC。
    """,
    inputs=[field("text", "string", "已知哈希", default="", placeholder="hash(secret + data) 的十六进制"),
            field("data", "string", "原始数据 data", default="")],
    options=[field("append", "string", "要追加的内容", default=""),
             field("secret_len", "number", "secret 的长度（字节）", default=8, min=0, max=4096),
             field("algorithm", "segmented", "算法", default="md5", choices=list(ALGOS)),
             field("data_format", "segmented", "数据格式", default="文本", choices=DATA_FORMATS)],
    examples=[{"text": hashlib.md5(b"secret!!user=guest").hexdigest(), "data": "user=guest", "append": "&admin=1",
               "secret_len": 8, "algorithm": "md5"}],
    keywords=["长度扩展", "length extension", "hashpump", "签名"],
)
def length_extension_tool(text, data="", append="", secret_len=8, algorithm="md5", data_format="文本"):
    from urllib.parse import quote_from_bytes
    if not text.strip():
        raise ToolError("请输入已知哈希")
    d = to_bytes(data, data_format)
    new_data, new_hash = extend(algorithm, text.strip().lower(), d, to_bytes(append, data_format), int(secret_len))
    return fields([["新的哈希", new_hash], ["新数据（URL 编码）", quote_from_bytes(new_data)],
                   ["新数据（十六进制）", new_data.hex()], ["新数据（Python）", repr(new_data)]])


def self_check():
    """与 hashlib 对比，确保三个手写实现正确。"""
    for algo in ALGOS:
        for msg in (b"", b"abc", b"a" * 200):
            assert digest(algo, msg) == hashlib.new(algo, msg).hexdigest(), algo
