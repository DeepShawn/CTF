"""Base 系列编码（教材 1.1.1～1.1.4）：Base64、Base32、Base16、Base58、Base62、Base85、Base91、Base92。

这些编码的共同思路：把字节看成一串二进制位（或一个大整数），
再按固定的“码表”换成可打印字符。码表大小决定了名字：Base64 用 64 个字符。
"""

import base64
import binascii
import re

from ..registry import ToolError, field, mode, text_input, tool
from ..util import INPUT_FORMATS, show_both, to_bytes

B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
B32_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B58_BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _check_table(table, size):
    if len(table) != size:
        raise ToolError("码表应为 %d 个字符，当前为 %d 个" % (size, len(table)))
    if len(set(table)) != size:
        raise ToolError("码表中有重复字符")


def _translate(s, src, dst):
    return s.translate(str.maketrans(src, dst))


# ---------------------------------------------------------------- Base64

def b64encode(data, table=B64_STD):
    return _translate(base64.b64encode(data).decode("ascii"), B64_STD, table)


def b64decode(text, table=B64_STD):
    s = re.sub(r"\s", "", text)
    s = _translate(s, table, B64_STD).rstrip("=")
    bad = set(s) - set(B64_STD)
    if bad:
        raise ToolError("包含码表以外的字符：%s" % " ".join(sorted(bad)[:10]))
    if len(s) % 4 == 1:
        raise ToolError("长度不对：去掉 = 后有 %d 个字符，Base64 不会出现除以 4 余 1 的长度" % len(s))
    return base64.b64decode(s + "=" * (-len(s) % 4))   # 缺少的 = 自动补齐


@tool(
    "encoding.base64", "Base64 编码 / 解码", "encoding", "1.1.1",
    summary="最常见的编码；支持 URL 安全码表与自定义码表（换表 Base64）",
    principle="""
    Base64 把每 3 个字节（24 位）分成 4 组、每组 6 位，每组的值 0～63 去码表里查一个字符。
    最后不足 3 个字节时补 0，并用 `=` 把结果补到 4 的倍数。

    **怎么认出来**：只含 `A-Z a-z 0-9 + /`，末尾可能有 1～2 个 `=`，长度是 4 的倍数。
    `flag{` 编码后以 `ZmxhZ` 开头。

    **换表 Base64**：出题人把 64 个字符打乱顺序。知道新码表后，选择“自定义”并填入即可。
    逆向题里看到一段 64 个不重复字符的字符串，通常就是新码表。
    """,
    inputs=[text_input(placeholder="ZmxhZ3toZWxsb30=")],
    options=[
        mode(default="解码"),
        field("table", "select", "码表", default="标准", choices=["标准", "URL 安全", "自定义"]),
        field("custom", "string", "自定义码表", default="", placeholder="64 个不重复的字符",
              visible_when={"table": "自定义"}),
        field("input_format", "segmented", "输入格式", default="文本", choices=INPUT_FORMATS,
              visible_when={"mode": "编码"}),
    ],
    examples=[{"text": "ZmxhZ3toZWxsb30=", "mode": "解码"}, {"text": "flag{hello}", "mode": "编码"}],
    keywords=["base64", "b64", "换表"],
)
def base64_tool(text, mode="解码", table="标准", custom="", input_format="文本"):
    t = {"标准": B64_STD, "URL 安全": B64_URL}.get(table, custom)
    _check_table(t, 64)
    if mode == "编码":
        return b64encode(to_bytes(text, input_format), t)
    return show_both(b64decode(text, t))


# ---------------------------------------------------------------- Base32

@tool(
    "encoding.base32", "Base32 编码 / 解码", "encoding", "1.1.2",
    summary="大写字母 A-Z 与数字 2-7，常以多个 = 结尾",
    principle="""
    Base32 每 5 个字节（40 位）分成 8 组、每组 5 位，查 32 个字符的码表。
    结果长度是 8 的倍数，不足时用 `=` 补齐，所以末尾常见 1、3、4、6 个 `=`。

    **怎么认出来**：只含大写字母和数字 `2-7`（没有 0、1、8、9）。
    """,
    inputs=[text_input(placeholder="MZWGCZ33NBSWY3DPPU======")],
    options=[
        mode(default="解码"),
        field("custom", "string", "自定义码表", default="", placeholder="留空使用标准码表（32 个字符）"),
        field("input_format", "segmented", "输入格式", default="文本", choices=INPUT_FORMATS,
              visible_when={"mode": "编码"}),
    ],
    examples=[{"text": "MZWGCZ33NBSWY3DPPU======", "mode": "解码"}],
    keywords=["base32", "b32"],
)
def base32_tool(text, mode="解码", custom="", input_format="文本"):
    t = custom or B32_STD
    _check_table(t, 32)
    if mode == "编码":
        return _translate(base64.b32encode(to_bytes(text, input_format)).decode("ascii"), B32_STD, t)
    s = re.sub(r"\s", "", text)
    if not custom:
        s = s.upper()
    s = _translate(s, t, B32_STD).rstrip("=")
    bad = set(s) - set(B32_STD)
    if bad:
        raise ToolError("包含码表以外的字符：%s" % " ".join(sorted(bad)[:10]))
    try:
        return show_both(base64.b32decode(s + "=" * (-len(s) % 8)))
    except binascii.Error:
        raise ToolError("长度不对：去掉 = 后的字符数不可能由 Base32 产生")


# ---------------------------------------------------------------- Base16

@tool(
    "encoding.base16", "Base16（十六进制）", "encoding", "1.1.3",
    summary="每个字节写成两位十六进制",
    principle="""
    Base16 就是十六进制：每个字节（8 位）分成两个 4 位，每 4 位用 `0-9 A-F` 中的一个字符表示。
    结果长度是原来的 2 倍。解码时会忽略空格、`0x`、`\\x` 等分隔写法。
    """,
    inputs=[text_input(placeholder="666C61677B6865787D")],
    options=[mode(default="解码"),
             field("upper", "switch", "大写字母", default=True, visible_when={"mode": "编码"}),
             field("sep", "string", "分隔符", default="", placeholder="如空格", visible_when={"mode": "编码"})],
    examples=[{"text": "666C61677B6865787D", "mode": "解码"}],
    keywords=["hex", "base16", "十六进制"],
)
def base16_tool(text, mode="解码", upper=True, sep=""):
    from ..util import parse_hex
    if mode == "编码":
        h = text.encode("utf-8").hex()
        if upper:
            h = h.upper()
        return sep.join(h[i:i + 2] for i in range(0, len(h), 2))
    return show_both(parse_hex(text))


# ---------------------------------------------------------------- 大整数类：Base58、Base62

def int_encode(data, table):
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, len(table))
        out = table[r] + out
    pad = len(data) - len(data.lstrip(b"\0"))        # 开头的 0 字节各记作一个码表首字符
    return table[0] * pad + out


def int_decode(text, table):
    s = re.sub(r"\s", "", text)
    n = 0
    for c in s:
        i = table.find(c)
        if i < 0:
            raise ToolError("包含码表以外的字符：%s" % c)
        n = n * len(table) + i
    pad = len(s) - len(s.lstrip(table[0]))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * pad + body


@tool(
    "encoding.base58", "Base58 编码 / 解码", "encoding", "1.1.4",
    summary="比特币地址使用的编码，去掉了容易看错的 0 O I l",
    principle="""
    Base58 把整段数据看成一个大整数，不断除以 58，余数去码表里查字符（与进制转换完全相同）。
    码表去掉了 `0`、`O`、`I`、`l` 四个容易混淆的字符，也没有 `+` `/`。

    **怎么认出来**：只含字母和数字，但其中没有 `0 O I l`。
    开头的 0 字节各编码成一个 `1`。
    """,
    inputs=[text_input(placeholder="StV1DL6CwTryKyV")],
    options=[mode(default="解码"),
             field("custom", "string", "自定义码表", default="", placeholder="留空使用比特币码表"),
             field("input_format", "segmented", "输入格式", default="文本", choices=INPUT_FORMATS,
                   visible_when={"mode": "编码"})],
    examples=[{"text": "StV1DL6CwTryKyV", "mode": "解码"}],
    keywords=["base58", "bitcoin"],
)
def base58_tool(text, mode="解码", custom="", input_format="文本"):
    t = custom or B58_BTC
    _check_table(t, 58)
    if mode == "编码":
        return int_encode(to_bytes(text, input_format), t)
    return show_both(int_decode(text, t))


@tool(
    "encoding.base62", "Base62 编码 / 解码", "encoding", "1.1.4",
    summary="只用数字与大小写字母，常见于短链接",
    principle="""
    与 Base58 相同的大整数做法，码表为 `0-9 A-Z a-z` 共 62 个字符，没有任何符号。
    不同网站的码表顺序可能不同（如小写在前），解不出来时试试自定义码表。
    """,
    inputs=[text_input()],
    options=[mode(default="解码"),
             field("custom", "string", "自定义码表", default="", placeholder="留空使用 0-9A-Za-z"),
             field("input_format", "segmented", "输入格式", default="文本", choices=INPUT_FORMATS,
                   visible_when={"mode": "编码"})],
    examples=[{"text": "flag{62}", "mode": "编码"}],
    keywords=["base62"],
)
def base62_tool(text, mode="解码", custom="", input_format="文本"):
    t = custom or B62
    _check_table(t, 62)
    if mode == "编码":
        return int_encode(to_bytes(text, input_format), t)
    return show_both(int_decode(text, t))


# ---------------------------------------------------------------- Base85

@tool(
    "encoding.base85", "Base85 / ASCII85", "encoding", "1.1.4",
    summary="每 4 字节编码成 5 个字符；有 ASCII85 与 RFC 1924 两种码表",
    principle="""
    Base85 把每 4 个字节看成一个 32 位整数，用 85 进制写成 5 位，所以只膨胀 25%（Base64 是 33%）。

    - **ASCII85**（Adobe，PDF 中常见）：码表是 ASCII 33 `!` 到 117 `u`，全 0 的 4 字节缩写为 `z`，
      常用 `<~` 和 `~>` 包起来；
    - **RFC 1924**（Python `base64.b85encode`）：码表是 `0-9 A-Z a-z` 加 23 个符号。

    **怎么认出来**：字符种类非常多，包含各种标点符号。
    """,
    inputs=[text_input(placeholder="<~Ao(mgHXSlkI/~>")],
    options=[mode(default="解码"),
             field("variant", "segmented", "码表", default="ASCII85", choices=["ASCII85", "RFC 1924"]),
             field("input_format", "segmented", "输入格式", default="文本", choices=INPUT_FORMATS,
                   visible_when={"mode": "编码"})],
    examples=[{"text": "<~Ao(mgHXSlkI/~>", "mode": "解码"}],
    keywords=["base85", "ascii85", "a85", "b85"],
)
def base85_tool(text, mode="解码", variant="ASCII85", input_format="文本"):
    if mode == "编码":
        data = to_bytes(text, input_format)
        if variant == "ASCII85":
            return base64.a85encode(data, adobe=True).decode("ascii")
        return base64.b85encode(data).decode("ascii")
    s = text.strip()
    try:
        if variant == "ASCII85":
            s = re.sub(r"\s", "", s)
            if s.startswith("<~"):
                s = s[2:]
            if s.endswith("~>"):
                s = s[:-2]
            return show_both(base64.a85decode(s))
        return show_both(base64.b85decode(re.sub(r"\s", "", s)))
    except ValueError as e:
        raise ToolError("无法按 %s 解码：%s" % (variant, e))


# ---------------------------------------------------------------- Base91

B91 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
       "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")


def b91encode(data):
    b = n = 0
    out = []
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(B91[v % 91] + B91[v // 91])
    if n:
        out.append(B91[b % 91])
        if n > 7 or b > 90:
            out.append(B91[b // 91])
    return "".join(out)


def b91decode(text):
    v = -1
    b = n = 0
    out = bytearray()
    for c in text:
        if c not in B91:
            if c.isspace():
                continue
            raise ToolError("包含码表以外的字符：%s" % c)
        d = B91.index(c)
        if v < 0:
            v = d
        else:
            v += d * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v + 1:
        out.append((b | v << n) & 255)
    return bytes(out)


@tool(
    "encoding.base91", "Base91 编码 / 解码", "encoding", "1.1.4",
    summary="basE91：用 91 个可打印字符，比 Base64 更紧凑",
    principle="""
    basE91 每次取 13 或 14 位，用两个 91 进制字符表示（91² = 8281 > 2¹³ = 8192）。
    码表包含除 `-`、`'`、`\\`、空格以外的几乎所有可打印 ASCII 字符。
    """,
    inputs=[text_input()],
    options=[mode(default="解码"),
             field("input_format", "segmented", "输入格式", default="文本", choices=INPUT_FORMATS,
                   visible_when={"mode": "编码"})],
    examples=[{"text": "fPNKd", "mode": "解码"}],
    keywords=["base91"],
)
def base91_tool(text, mode="解码", input_format="文本"):
    if mode == "编码":
        return b91encode(to_bytes(text, input_format))
    return show_both(b91decode(text))


# ---------------------------------------------------------------- Base92

def _b92chr(v):
    if v == 0:
        return "!"
    if v <= 61:
        return chr(ord("#") + v - 1)
    return chr(ord("a") + v - 62)


def _b92ord(c):
    if c == "!":
        return 0
    if "#" <= c <= "_":
        return ord(c) - ord("#") + 1
    if "a" <= c <= "}":
        return ord(c) - ord("a") + 62
    raise ToolError("包含码表以外的字符：%s" % c)


def b92encode(data):
    if not data:
        return "~"
    bits = "".join("{:08b}".format(b) for b in data)
    out = []
    while len(bits) >= 13:
        v = int(bits[:13], 2)
        out.append(_b92chr(v // 91) + _b92chr(v % 91))
        bits = bits[13:]
    if bits:
        if len(bits) < 7:
            v = int(bits.ljust(6, "0"), 2)
            out.append(_b92chr(v))
        else:
            v = int(bits.ljust(13, "0"), 2)
            out.append(_b92chr(v // 91) + _b92chr(v % 91))
    return "".join(out)


def b92decode(text):
    s = re.sub(r"\s", "", text)
    if s == "~":
        return b""
    bits = ""
    out = bytearray()
    for i in range(len(s) // 2):
        bits += "{:013b}".format(_b92ord(s[2 * i]) * 91 + _b92ord(s[2 * i + 1]))
        while len(bits) >= 8:
            out.append(int(bits[:8], 2))
            bits = bits[8:]
    if len(s) % 2:
        bits += "{:06b}".format(_b92ord(s[-1]))
        while len(bits) >= 8:
            out.append(int(bits[:8], 2))
            bits = bits[8:]
    return bytes(out)


@tool(
    "encoding.base92", "Base92 编码 / 解码", "encoding", "1.1.4",
    summary="每 13 位编码成两个字符；空数据编码为 ~",
    principle="""
    Base92 每次取 13 位，写成两个 91 进制字符；最后剩下不足 7 位时只用一个字符表示 6 位。
    码表是 `!` 与 `#` 到 `_`、`a` 到 `}`（不含双引号与反引号）。
    """,
    inputs=[text_input()],
    options=[mode(default="解码"),
             field("input_format", "segmented", "输入格式", default="文本", choices=INPUT_FORMATS,
                   visible_when={"mode": "编码"})],
    examples=[{"text": "Fc_$aOTdKnsM*k", "mode": "解码"}],
    keywords=["base92"],
)
def base92_tool(text, mode="解码", input_format="文本"):
    if mode == "编码":
        return b92encode(to_bytes(text, input_format))
    return show_both(b92decode(text))
