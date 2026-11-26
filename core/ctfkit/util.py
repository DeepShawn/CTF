"""各工具共用的小函数：文本与字节的转换、可读性打分、flag 匹配。"""

import re
import string

from .registry import ToolError

PRINTABLE = set(string.printable.encode("ascii"))
FLAG_RE = re.compile(r"(?:flag|ctf|key)\{[^{}\s]{1,200}\}", re.I)

INPUT_FORMATS = ("文本", "十六进制")
DATA_FORMATS = ("文本", "十六进制", "Base64")
OUTPUT_FORMATS = ("十六进制", "Base64", "文本")


def to_bytes(text, fmt="文本"):
    """把界面上输入的内容转成字节。``fmt`` 为“文本”（按 UTF-8）、“十六进制”或“Base64”。"""
    if isinstance(text, (bytes, bytearray)):
        return bytes(text)
    if fmt == "十六进制":
        return parse_hex(text)
    if fmt == "Base64":
        import base64
        import binascii
        s = re.sub(r"\s", "", text)
        try:
            return base64.b64decode(s + "=" * (-len(s) % 4))
        except (binascii.Error, ValueError):
            raise ToolError("不是有效的 Base64")
    return text.encode("utf-8")


def from_bytes(data, fmt="十六进制"):
    """把字节按指定格式写出：十六进制、Base64 或文本（不可读时自动改为十六进制）。"""
    if fmt == "Base64":
        import base64
        return base64.b64encode(data).decode("ascii")
    if fmt == "文本":
        return show(data)
    return data.hex()


def parse_int(s, name="数字"):
    """解析整数：支持十进制、0x 十六进制、0b 二进制、0o 八进制，忽略空白与下划线。"""
    t = re.sub(r"[\s_]", "", str(s))
    if not t:
        raise ToolError("%s不能为空" % name)
    try:
        return int(t, 0) if re.match(r"^-?0[xXbBoO]", t) else int(t)
    except ValueError:
        raise ToolError("%s不是整数：%s" % (name, t[:40]))


def i2b(n):
    """整数转字节（大端序），相当于 Crypto.Util.number.long_to_bytes。"""
    return n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")


def b2i(b):
    return int.from_bytes(b, "big")


def image(data, mime="image/png", caption=""):
    """图片输出，界面用 ImageViewer 显示。"""
    import base64
    return {"type": "image", "mime": mime, "data": base64.b64encode(data).decode("ascii"), "caption": caption}


def file_out(data, name, mime="application/octet-stream", caption=""):
    """文件输出，界面提供下载。"""
    import base64
    return {"type": "file", "name": name, "mime": mime, "size": len(data),
            "data": base64.b64encode(data).decode("ascii"), "caption": caption}


def parse_hex(text):
    """宽松地解析十六进制：忽略空白、``0x``、``\\x``、冒号和逗号。"""
    s = re.sub(r"0x|\\x|[\s:,;-]", "", text, flags=re.I)
    if len(s) % 2:
        raise ToolError("十六进制的位数应为偶数，当前为 %d 位" % len(s))
    try:
        return bytes.fromhex(s)
    except ValueError:
        bad = sorted(set(c for c in s if c not in string.hexdigits))
        raise ToolError("包含非十六进制字符：%s" % " ".join(bad[:10]))


def show(data):
    """把字节显示成文本：能按 UTF-8 解码且基本可读时显示文本，否则显示十六进制。"""
    if isinstance(data, str):
        return data
    try:
        s = data.decode("utf-8")
        if all(c.isprintable() or c in "\r\n\t" for c in s):
            return s
    except UnicodeDecodeError:
        pass
    return "（不是可读文本，以十六进制显示）\n" + data.hex()


def show_both(data):
    """同时给出文本与十六进制两种形式，供解码类工具使用。"""
    s = show(data)
    if s.startswith("（不是可读文本"):
        return {"type": "fields", "items": [["十六进制", data.hex()], ["按 Latin-1 显示", data.decode("latin-1")]]}
    return s


def printable_ratio(data):
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    if not data:
        return 0.0
    return sum(1 for b in data if b in PRINTABLE) / len(data)


# 英文字母频率（%），用于给古典密码的候选结果打分
ENGLISH_FREQ = {
    "a": 8.17, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.23, "g": 2.02, "h": 6.09,
    "i": 6.97, "j": 0.15, "k": 0.77, "l": 4.03, "m": 2.41, "n": 6.75, "o": 7.51, "p": 1.93,
    "q": 0.10, "r": 5.99, "s": 6.33, "t": 9.06, "u": 2.76, "v": 0.98, "w": 2.36, "x": 0.15,
    "y": 1.97, "z": 0.07,
}

COMMON_WORDS = ("the", "and", "flag", "ctf", "is", "of", "to", "you", "that", "this", "key", "for")


def english_score(text):
    """越像英文分数越高（0～100 左右）。用卡方距离衡量字母频率，再给常见单词与 flag 加分。"""
    letters = [c for c in text.lower() if "a" <= c <= "z"]
    if not letters:
        return 0.0
    n = len(letters)
    counts = {}
    for c in letters:
        counts[c] = counts.get(c, 0) + 1
    chi = 0.0
    for c, p in ENGLISH_FREQ.items():
        expected = n * p / 100
        chi += (counts.get(c, 0) - expected) ** 2 / expected
    score = 100.0 / (1.0 + chi / n)
    low = text.lower()
    score += sum(3 for w in COMMON_WORDS if w in low)
    if FLAG_RE.search(text):
        score += 50
    return round(score, 2)


def find_flags(text):
    return FLAG_RE.findall(text)


def table(columns, rows):
    return {"type": "table", "columns": list(columns), "rows": [list(r) for r in rows]}


def fields(items):
    return {"type": "fields", "items": [list(i) for i in items]}
