"""文本隐写（教材 2.4）：零宽字符、空白（SNOW）、Unicode 同形字检测。"""

import re
import unicodedata

from ..registry import field, text_input, tool
from ..util import fields, show, table

# 常用零宽字符
ZWSP = "​"   # 零宽空格
ZWNJ = "‌"   # 零宽不连字
ZWJ = "‍"    # 零宽连字
ZWNBSP = "﻿"  # 零宽不换行空格
ZW_ALL = [ZWSP, ZWNJ, ZWJ, ZWNBSP, "⁠", "᠎"]


def extract_zero_width(text):
    """取出文本中的零宽字符。"""
    return "".join(c for c in text if c in ZW_ALL or (0x200b <= ord(c) <= 0x200f) or ord(c) in (0x2060, 0xfeff, 0x180e))


def zw_to_bits(zw, zero=ZWSP, one=ZWNJ):
    bits = "".join("0" if c == zero else "1" if c == one else "" for c in zw)
    return bits


def bits_to_text(bits):
    data = bytearray()
    for i in range(0, len(bits) - 7, 8):
        data.append(int(bits[i:i + 8], 2))
    return bytes(data)


@tool(
    "stego.zerowidth", "零宽字符隐写", "stego", "2.4.0",
    summary="检测并解码藏在文字之间的零宽字符；也可把文本编码成零宽字符",
    principle="""
    零宽字符（零宽空格 U+200B、零宽不连字 U+200C 等）在屏幕上不显示，但确实存在于文本里。
    把它们夹在正常文字之间，就能隐藏信息——复制粘贴一段“普通”文字时，秘密也跟着过去了。

    **解码**：先把零宽字符单独取出来，常见的编码方式有两种：
    - **二进制**：用两种零宽字符表示 0 和 1，每 8 位一个字节；
    - **多进制**：用三四种零宽字符表示更多状态。

    本工具自动统计用到了哪几种零宽字符并尝试解码。如果页面上看不出异常但怀疑有隐写，直接把文本粘进来即可。
    """,
    inputs=[text_input("含零宽字符的文本")],
    options=[field("action", "segmented", "操作", default="解码", choices=["解码", "编码"])],
    examples=[{"text": "H​​​‌‌​​‌i" + "​‌‌​​‌‌​", "action": "解码"}],
    keywords=["零宽", "zero width", "zwsp", "unicode", "隐写"],
    live=False,
)
def zerowidth_tool(text, action="解码"):
    if action == "编码":
        bits = "".join("{:08b}".format(b) for b in text.encode("utf-8"))
        return "（下面是零宽字符，看不见是正常的；可粘贴到任意文字中间）\n正常文字" + \
               "".join(ZWSP if b == "0" else ZWNJ for b in bits) + "也是正常文字"
    zw = extract_zero_width(text)
    if not zw:
        return "没有找到零宽字符。可以试试“空白隐写”或“同形字检测”。"
    kinds = {}
    for c in zw:
        kinds[c] = kinds.get(c, 0) + 1
    name = {ZWSP: "U+200B 零宽空格", ZWNJ: "U+200C 零宽不连字", ZWJ: "U+200D 零宽连字", ZWNBSP: "U+FEFF 零宽不换行空格"}
    info = [["零宽字符总数", len(zw)]] + [[name.get(c, "U+%04X" % ord(c)), n] for c, n in kinds.items()]
    out = [fields(info)]
    uniq = list(kinds)
    results = []
    if len(uniq) == 2:
        for zero, one in [(uniq[0], uniq[1]), (uniq[1], uniq[0])]:
            bits = zw_to_bits(zw, zero, one)
            data = bits_to_text(bits)
            results.append(["%s=0, %s=1" % (name.get(zero, "?")[:6], name.get(one, "?")[:6]), show(data)])
    elif len(uniq) >= 3:
        order = {c: i for i, c in enumerate(uniq)}
        base = len(uniq)
        val = 0
        for c in zw:
            val = val * base + order[c]
        results.append(["按 %d 进制" % base, "（多进制编码，需结合题目判断，原始序列如下）"])
    if results:
        out.append(table(["解码方式", "结果"], results))
    return out


@tool(
    "stego.whitespace", "空白字符隐写", "stego", "2.4.0",
    summary="解码行尾用空格 / 制表符（SNOW 风格）隐藏的信息",
    principle="""
    SNOW 工具把信息藏在**每行末尾的空格和制表符**里：空格代表 0、制表符代表 1（或反过来），
    每 8 位拼成一个字节。文本正常显示，只是行尾多了些看不见的空白。

    本工具提取每行的行尾空白，按“空格=0、Tab=1”尝试解码。
    """,
    inputs=[text_input("含行尾空白的文本")],
    options=[field("space", "segmented", "空格代表", default="0", choices=["0", "1"])],
    keywords=["snow", "空白", "空格", "tab", "whitespace"],
    live=False,
)
def whitespace_tool(text, space="0"):
    tail = ""
    for line in text.split("\n"):
        m = re.search(r"[ \t]+$", line)
        if m:
            tail += m.group(0)
    if not tail.strip("\t "):
        tail = re.sub(r"[^ \t]", "", text)              # 退而求其次：取全部空白
    if not tail:
        return "没有找到行尾空白。"
    zero = " " if space == "0" else "\t"
    bits = "".join("0" if c == zero else "1" for c in tail if c in " \t")
    data = bits_to_text(bits)
    return fields([["空白字符数", len(bits)], ["二进制", bits[:200]], ["解码结果", show(data)]])


HOMOGLYPHS = {
    "а": "a (西里尔)", "е": "e (西里尔)", "о": "o (西里尔)", "р": "p (西里尔)", "с": "c (西里尔)",
    "х": "x (西里尔)", "у": "y (西里尔)", "ѕ": "s (西里尔)", "і": "i (西里尔)", "ј": "j (西里尔)",
    "Ａ": "A (全角)", "ｌ": "l (全角)", "０": "0 (全角)", "α": "a (希腊)", "ο": "o (希腊)", "ρ": "p (希腊)",
}


@tool(
    "stego.homoglyph", "Unicode 同形字检测", "stego", "2.4.0",
    summary="找出混在文本中、长得像 ASCII 的西里尔 / 希腊 / 全角字符",
    principle="""
    很多 Unicode 字符长得和英文字母一模一样，比如西里尔字母 `а`（U+0430）和拉丁 `a`（U+0061）。
    把域名、flag 里的某个字母换成同形字，看起来没变，实际内容不同（同形字攻击 / IDN 欺骗）。

    本工具列出文本中所有非 ASCII 但“看起来像”ASCII 的字符及其码点，帮助发现被替换的位置。
    """,
    inputs=[text_input("文本")],
    examples=[{"text": "flаg{h0mોglyph}"}],
    keywords=["同形字", "homoglyph", "unicode", "西里尔", "idn"],
)
def homoglyph_tool(text):
    rows = []
    for i, c in enumerate(text):
        if ord(c) < 128:
            continue
        try:
            name = unicodedata.name(c)
        except ValueError:
            name = "?"
        like = HOMOGLYPHS.get(c)
        if like or any(k in name for k in ("CYRILLIC", "GREEK", "FULLWIDTH", "MATHEMATICAL")):
            rows.append([i, c, "U+%04X" % ord(c), name, like or "可疑"])
    if not rows:
        return "没有发现可疑的同形字。文本中的非 ASCII 字符可能是正常的中文或符号。"
    ascii_version = "".join(c if ord(c) < 128 else "?" for c in text)
    return [table(["位置", "字符", "码点", "Unicode 名称", "疑似替换"], rows),
            fields([["把可疑字符标成 ?", ascii_version]])]
