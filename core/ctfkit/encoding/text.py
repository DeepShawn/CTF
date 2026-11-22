"""其他常用编码：Unicode 转义、HTML 实体、进制转换、文本处理、核心价值观编码。"""

import html
import random
import re

from ..registry import ToolError, field, mode, text_input, tool
from ..util import fields

# ---------------------------------------------------------------- Unicode 转义


@tool(
    "encoding.unicode", "Unicode 转义", "encoding", "1.1",
    summary="\\u5e93、&#x5e93;、U+5E93 等写法与文字互转",
    principle="""
    Unicode 给世界上每个字符分配一个编号（码点），如“库”是 U+5E93。不同场合写法不同：

    | 写法 | 场合 |
    |---|---|
    | `\\u5e93` | JavaScript、JSON、Java、Python 字符串 |
    | `&#x5e93;` / `&#24211;` | HTML（十六进制 / 十进制） |
    | `U+5E93` | 文档中的标准写法 |

    超过 U+FFFF 的字符（如表情符号）在 `\\u` 写法中会拆成两个“代理对”，如 `\\ud83d\\ude00`。
    """,
    inputs=[text_input(placeholder="\\u0066\\u006c\\u0061\\u0067")],
    options=[mode(default="解码"),
             field("style", "select", "编码格式", default="\\uXXXX",
                   choices=["\\uXXXX", "&#xXXXX;", "&#DDDD;", "U+XXXX"], visible_when={"mode": "编码"}),
             field("ascii_too", "switch", "ASCII 字符也编码", default=True, visible_when={"mode": "编码"})],
    examples=[{"text": "\\u0066\\u006c\\u0061\\u0067\\u007b\\u4f60\\u597d\\u007d", "mode": "解码"}],
    keywords=["unicode", "\\u", "码点"],
)
def unicode_tool(text, mode="解码", style="\\uXXXX", ascii_too=True):
    if mode == "编码":
        out = []
        for c in text:
            if not ascii_too and ord(c) < 128:
                out.append(c)
            elif style == "\\uXXXX":
                b = c.encode("utf-16-be")
                out.append("".join("\\u%04x" % int.from_bytes(b[i:i + 2], "big") for i in range(0, len(b), 2)))
            elif style == "&#xXXXX;":
                out.append("&#x%x;" % ord(c))
            elif style == "&#DDDD;":
                out.append("&#%d;" % ord(c))
            else:
                out.append("U+%04X " % ord(c))
        return "".join(out).strip()

    def u_esc(m):
        return m.group(0).encode("ascii").decode("unicode_escape")

    s = re.sub(r"(?:\\u[0-9a-fA-F]{4})+", lambda m: m.group(0).encode("ascii").decode("unicode_escape")
               .encode("utf-16", "surrogatepass").decode("utf-16"), text)
    s = re.sub(r"\\U[0-9a-fA-F]{8}|\\x[0-9a-fA-F]{2}", u_esc, s)
    s = re.sub(r"[Uu]\+([0-9a-fA-F]{4,6})\s?", lambda m: chr(int(m.group(1), 16)), s)
    return html.unescape(s)


# ---------------------------------------------------------------- HTML 实体

@tool(
    "encoding.html", "HTML 实体", "encoding", "1.1",
    summary="&lt; &amp; &#39; 等 HTML 实体编码 / 解码",
    principle="""
    HTML 中 `<`、`>`、`&`、`"` 有特殊含义，要显示它们本身需写成实体：`&lt;` `&gt;` `&amp;` `&quot;`。
    任何字符也可以写成 `&#十进制;` 或 `&#x十六进制;`。XSS 题中常用实体编码绕过过滤。
    """,
    inputs=[text_input(placeholder="&lt;script&gt;alert(1)&lt;/script&gt;")],
    options=[mode(default="解码"),
             field("all", "switch", "编码全部字符", default=False, visible_when={"mode": "编码"})],
    examples=[{"text": "&lt;script&gt;alert(&#39;flag&#39;)&lt;/script&gt;", "mode": "解码"}],
    keywords=["html", "实体", "entity", "xss"],
)
def html_tool(text, mode="解码", all=False):
    if mode == "编码":
        return "".join("&#%d;" % ord(c) for c in text) if all else html.escape(text)
    return html.unescape(text)


# ---------------------------------------------------------------- 进制转换

DIGITS = "0123456789abcdefghijklmnopqrstuvwxyz"


def to_base(n, base):
    if n == 0:
        return "0"
    sign = "-" if n < 0 else ""
    n = abs(n)
    out = ""
    while n:
        n, r = divmod(n, base)
        out = DIGITS[r] + out
    return sign + out


@tool(
    "encoding.radix", "进制转换", "encoding", "1.1",
    summary="2～36 进制之间转换整数（可以很大）；一行一个数",
    principle="""
    同一个数可以用不同进制书写：十进制 255 = 十六进制 `ff` = 八进制 `377` = 二进制 `11111111`。
    转换方法是不断除以目标进制、倒序写出余数。Python 中 `int("ff", 16)` 可把任意进制转成整数，
    整数大小没有上限，适合 RSA 等大数题。

    Base36 就是 36 进制（0-9 加 a-z），也可以用这个工具转换。
    """,
    inputs=[text_input("数字（一行一个）", placeholder="255")],
    options=[field("src", "number", "原进制", default=10, min=2, max=36),
             field("dst", "number", "目标进制", default=16, min=2, max=36)],
    examples=[{"text": "255\n65535", "src": 10, "dst": 2}],
    keywords=["进制", "radix", "base36", "二进制", "十六进制"],
)
def radix_tool(text, src=10, dst=16):
    src, dst = int(src), int(dst)
    if not (2 <= src <= 36 and 2 <= dst <= 36):
        raise ToolError("进制必须在 2～36 之间")
    out = []
    for line in text.split():
        s = re.sub(r"^(0x|0o|0b)", "", line.strip().replace("_", ""), flags=re.I)
        try:
            out.append(to_base(int(s, src), dst))
        except ValueError:
            raise ToolError("“%s”不是 %d 进制数" % (line, src))
    return "\n".join(out)


# ---------------------------------------------------------------- 文本处理

@tool(
    "encoding.text_ops", "文本处理", "encoding", "1.1",
    summary="反转、大小写互换、去空白、按长度分组、统计字符",
    principle="""
    很多题目的最后一步是简单的文本变换：整体反转、每组反转、大小写互换、去掉干扰字符。
    “统计”会列出字符数、字节数以及出现的字符种类，帮助判断是哪种编码。
    """,
    inputs=[text_input()],
    options=[field("op", "select", "操作", default="反转",
                   choices=["反转", "每组反转", "大小写互换", "全部大写", "全部小写", "去掉空白", "按长度分组", "统计"]),
             field("size", "number", "每组长度", default=8, min=1, max=1024,
                   visible_when={"op": ["每组反转", "按长度分组"]})],
    examples=[{"text": "}desrever{galf", "op": "反转"}],
    keywords=["反转", "reverse", "大小写", "统计"],
)
def text_ops(text, op="反转", size=8):
    size = max(1, int(size))
    if op == "反转":
        return text[::-1]
    if op == "每组反转":
        return "".join(text[i:i + size][::-1] for i in range(0, len(text), size))
    if op == "大小写互换":
        return text.swapcase()
    if op == "全部大写":
        return text.upper()
    if op == "全部小写":
        return text.lower()
    if op == "去掉空白":
        return re.sub(r"\s", "", text)
    if op == "按长度分组":
        return " ".join(text[i:i + size] for i in range(0, len(text), size))
    kinds = []
    for name, pat in (("大写字母", r"[A-Z]"), ("小写字母", r"[a-z]"), ("数字", r"[0-9]"),
                      ("空白", r"\s"), ("中文", r"[一-鿿]")):
        n = len(re.findall(pat, text))
        if n:
            kinds.append("%s %d" % (name, n))
    others = sorted(set(re.sub(r"[A-Za-z0-9\s一-鿿]", "", text)))
    return fields([["字符数", len(text)], ["UTF-8 字节数", len(text.encode("utf-8"))],
                   ["不同字符数", len(set(text))], ["组成", "，".join(kinds) or "无"],
                   ["其他符号", " ".join(others) or "无"]])


# ---------------------------------------------------------------- 核心价值观编码

VALUES = "富强民主文明和谐自由平等公正法治爱国敬业诚信友善"
WORDS = [VALUES[i:i + 2] for i in range(0, len(VALUES), 2)]


def corevalues_encode(text, rng=None):
    rng = rng or random.Random(0)          # 固定种子：同样的输入得到同样的输出，便于核对
    out = []
    for h in text.encode("utf-8").hex().upper():
        d = int(h, 16)
        if d < 10:
            out.append(WORDS[d])
        elif rng.random() < 0.5:
            out.append(WORDS[10] + WORDS[d - 10])     # 10～15 写成“诚信”+ 第 0～5 个词
        else:
            out.append(WORDS[11] + WORDS[d - 6])      # 10～15 写成“友善”+ 第 4～9 个词
    return "".join(out)


def corevalues_decode(text):
    s = re.sub(r"\s", "", text)
    if len(s) % 2:
        raise ToolError("长度应为偶数（每个词两个字）")
    idx = []
    for i in range(0, len(s), 2):
        w = s[i:i + 2]
        if w not in WORDS:
            raise ToolError("“%s”不是十二个词之一" % w)
        idx.append(WORDS.index(w))
    digits, i = [], 0
    while i < len(idx):
        v = idx[i]
        if v == 10:
            digits.append(10 + idx[i + 1])
            i += 2
        elif v == 11:
            digits.append(idx[i + 1] + 6)
            i += 2
        else:
            digits.append(v)
            i += 1
    hexs = "".join("%X" % d for d in digits)
    if len(hexs) % 2:
        raise ToolError("解出的十六进制位数为奇数，内容可能不完整")
    return bytes.fromhex(hexs).decode("utf-8", "replace")


@tool(
    "encoding.corevalues", "核心价值观编码", "encoding", "1.1",
    summary="由“富强民主文明和谐……”十二个词组成的趣味编码",
    principle="""
    这种编码先把文字按 UTF-8 写成十六进制，再把每个十六进制数字换成一个词：
    0～9 依次对应前十个词（富强、民主、文明……敬业），10～15 写成两个词：
    “诚信”加第 0～5 个词，或“友善”加第 4～9 个词。所以同一段文字可以有多种编码结果，但解码结果唯一。
    """,
    inputs=[text_input(placeholder="公正公正公正诚信文明公正民主公正法治法治诚信民主")],
    options=[mode(default="解码")],
    examples=[{"text": "flag", "mode": "编码"}],
    keywords=["核心价值观", "趣味编码"],
)
def corevalues_tool(text, mode="解码"):
    if mode == "编码":
        return corevalues_encode(text)
    return corevalues_decode(text)
