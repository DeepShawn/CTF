"""各工具共用的小函数：文本与字节的转换、可读性打分、flag 匹配。"""

import re
import string

from .registry import ToolError

PRINTABLE = set(string.printable.encode("ascii"))
FLAG_RE = re.compile(r"(?:flag|ctf|key)\{[^{}\s]{1,200}\}", re.I)

INPUT_FORMATS = ("文本", "十六进制")


def to_bytes(text, fmt="文本"):
    """把界面上输入的内容转成字节。``fmt`` 为“文本”（按 UTF-8）或“十六进制”。"""
    if isinstance(text, bytes):
        return text
    if fmt == "十六进制":
        return parse_hex(text)
    return text.encode("utf-8")


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
