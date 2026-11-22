"""ASCII、Shellcode、Quoted-printable、UUencode、XXencode、URL 编码（教材 1.1.0、1.1.5～1.1.9）。"""

import quopri
import re
from urllib.parse import quote, unquote_to_bytes

from ..registry import ToolError, field, mode, text_input, tool
from ..util import INPUT_FORMATS, parse_hex, show_both, to_bytes, table

# ---------------------------------------------------------------- ASCII

BASES = {"十进制": 10, "十六进制": 16, "八进制": 8, "二进制": 2}


def _parse_numbers(text, base):
    s = text.strip()
    if base == 2 and re.fullmatch(r"[01\s]+", s) and " " not in s.strip() and len(s) % 8 == 0:
        parts = [s[i:i + 8] for i in range(0, len(s), 8)]          # 连在一起的 01 串按 8 位切开
    elif base == 16 and re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        parts = [s[i:i + 2] for i in range(0, len(s), 2)]
    else:
        parts = [p for p in re.split(r"[\s,;]+", s) if p]
    out = bytearray()
    for p in parts:
        p2 = re.sub(r"^(0x|0o|0b|\\x)", "", p, flags=re.I)
        try:
            v = int(p2, base)
        except ValueError:
            raise ToolError("“%s”不是%s数字" % (p, [k for k, b in BASES.items() if b == base][0]))
        if v > 255:
            raise ToolError("%s 超过了一个字节的范围（0～255）" % p)
        out.append(v)
    return bytes(out)


@tool(
    "encoding.ascii", "ASCII 码转换", "encoding", "1.1.0",
    summary="字符与十进制、十六进制、八进制、二进制数字互转",
    principle="""
    ASCII 用 0～127 的数字表示英文字母、数字和符号：`0` 是 48，`A` 是 65，`a` 是 97。
    在计算机中每个字符存成一个字节，所以“字符 → 数字”就是看这个字节的值，再换个进制写出来。

    **常见题型**：一串 `102 108 97 103`（十进制）、`01100110 01101100`（二进制）或
    `146 154 141 147`（八进制），按对应进制转回字符即可。
    中文等非 ASCII 字符会按 UTF-8 拆成多个字节。
    """,
    inputs=[text_input(placeholder="102 108 97 103 123 97 115 99 105 105 125")],
    options=[field("direction", "segmented", "方向", default="数字 → 字符", choices=["字符 → 数字", "数字 → 字符"]),
             field("base", "select", "进制", default="十进制", choices=list(BASES))],
    examples=[{"text": "102 108 97 103 123 97 115 99 105 105 125", "direction": "数字 → 字符"},
              {"text": "flag", "direction": "字符 → 数字", "base": "二进制"}],
    keywords=["ascii", "ord", "chr", "二进制", "八进制", "十进制"],
)
def ascii_tool(text, direction="数字 → 字符", base="十进制"):
    b = BASES[base]
    if direction == "字符 → 数字":
        fmt = {10: "{:d}", 16: "{:02x}", 8: "{:03o}", 2: "{:08b}"}[b]
        return " ".join(fmt.format(x) for x in text.encode("utf-8"))
    return show_both(_parse_numbers(text, b))


@tool(
    "encoding.ascii_table", "ASCII 码表", "encoding", "1.1.0",
    summary="32～126 可打印字符的十进制、十六进制、八进制、二进制对照",
    principle="ASCII 码表中 0～31 与 127 是控制字符（如换行 10、回车 13），32 是空格，33～126 是可打印字符。",
    inputs=[field("filter", "string", "筛选", default="", placeholder="输入字符，只显示这些字符")],
    keywords=["ascii", "码表"],
)
def ascii_table(filter=""):
    rows = []
    for i in range(32, 127):
        c = chr(i)
        if filter and c not in filter:
            continue
        rows.append([c if c != " " else "空格", i, "%02X" % i, "%03o" % i, "{:08b}".format(i)])
    return table(["字符", "十进制", "十六进制", "八进制", "二进制"], rows)


# ---------------------------------------------------------------- Shellcode

@tool(
    "encoding.shellcode", "Shellcode 编码", "encoding", "1.1.5",
    summary="\\x 形式与原始文本 / 十六进制互转",
    principle="""
    Shellcode 编码就是把每个字节写成 `\\x` 加两位十六进制，如 `\\x66\\x6c\\x61\\x67` 是 `flag`。
    这是 C 语言和 Python 字符串中表示任意字节的写法，PWN 题中注入的机器码常以这种形式给出。
    """,
    inputs=[text_input(placeholder="\\x66\\x6c\\x61\\x67")],
    options=[mode(default="解码"),
             field("input_format", "segmented", "输入格式", default="文本", choices=INPUT_FORMATS,
                   visible_when={"mode": "编码"})],
    examples=[{"text": "\\x66\\x6c\\x61\\x67\\x7b\\x73\\x63\\x7d", "mode": "解码"}],
    keywords=["shellcode", "\\x"],
)
def shellcode_tool(text, mode="解码", input_format="文本"):
    if mode == "编码":
        return "".join("\\x%02x" % b for b in to_bytes(text, input_format))
    return show_both(parse_hex(text))


# ---------------------------------------------------------------- Quoted-printable

@tool(
    "encoding.quoted_printable", "Quoted-printable 编码", "encoding", "1.1.6",
    summary="邮件中常见：非 ASCII 字节写成 =E4=BD=A0",
    principle="""
    Quoted-printable 让可打印 ASCII 字符保持原样，其他字节写成 `=` 加两位大写十六进制，
    行尾的 `=` 表示软换行（该处换行不属于原文）。邮件原文中的 `Content-Transfer-Encoding: quoted-printable` 即指这种编码。
    """,
    inputs=[text_input(placeholder="flag{=E4=BD=A0=E5=A5=BD}")],
    options=[mode(default="解码")],
    examples=[{"text": "flag{=E4=BD=A0=E5=A5=BD}", "mode": "解码"}],
    keywords=["quoted-printable", "qp", "邮件"],
)
def qp_tool(text, mode="解码"):
    if mode == "编码":
        return quopri.encodestring(text.encode("utf-8")).decode("ascii")
    return show_both(quopri.decodestring(text.encode("utf-8")))


# ---------------------------------------------------------------- UUencode / XXencode

UU_TABLE = "`" + "".join(chr(i) for i in range(33, 96))
XX_TABLE = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def uu_like_encode(data, tbl, name="flag.txt", header=True):
    lines = []
    for i in range(0, len(data), 45):                       # 每行最多 45 字节
        chunk = data[i:i + 45]
        line = tbl[len(chunk)]                              # 行首字符表示本行字节数
        padded = chunk + b"\0" * (-len(chunk) % 3)
        for j in range(0, len(padded), 3):
            n = int.from_bytes(padded[j:j + 3], "big")
            line += "".join(tbl[(n >> s) & 63] for s in (18, 12, 6, 0))
        lines.append(line)
    lines.append(tbl[0])
    body = "\n".join(lines)
    return "begin 644 %s\n%s\nend" % (name, body) if header else body


def uu_like_decode(text, tbl):
    lookup = {c: i for i, c in enumerate(tbl)}
    if tbl is UU_TABLE:
        lookup[" "] = 0                                     # 旧式 uuencode 用空格表示 0
    out = bytearray()
    for raw in text.splitlines():
        line = raw.rstrip("\r\n")
        if not line or line.startswith("begin ") or line.strip() == "end":
            continue
        if line[0] not in lookup:
            raise ToolError("无法识别的行：%s" % line[:20])
        count = lookup[line[0]]
        if count == 0:
            continue
        chars = line[1:]
        buf = bytearray()
        for j in range(0, len(chars) - 3, 4):
            try:
                n = 0
                for c in chars[j:j + 4]:
                    n = (n << 6) | lookup[c]
            except KeyError as e:
                raise ToolError("包含码表以外的字符：%s" % e.args[0])
            buf += n.to_bytes(3, "big")
        out += buf[:count]
    return bytes(out)


_UU_PRINCIPLE = """
{name} 是早期在邮件、新闻组中传输文件的编码，与 Base64 一样每 3 字节变成 4 个字符，区别在于码表和格式：

- 以 `begin 644 文件名` 开始、`end` 结束；
- 每行开头的第一个字符表示这一行有多少个字节（最多 45 个，对应字符 `{full}`）；
- 码表：{table}

**怎么认出来**：{hint}
"""


@tool(
    "encoding.uuencode", "UUencode 编码 / 解码", "encoding", "1.1.7",
    summary="begin 644 开头、每行以 M 开头的老式编码",
    principle=_UU_PRINCIPLE.format(name="UUencode", full="M", table="ASCII 32～95（0 用反引号表示）",
                                   hint="满行以 `M` 开头，字符多为大写字母、数字与标点，几乎没有小写字母。"),
    inputs=[text_input()],
    options=[mode(default="解码"),
             field("header", "switch", "包含 begin / end", default=True, visible_when={"mode": "编码"})],
    examples=[{"text": "flag{uuencode}", "mode": "编码"}],
    keywords=["uuencode", "uu"],
)
def uu_tool(text, mode="解码", header=True):
    if mode == "编码":
        return uu_like_encode(text.encode("utf-8"), UU_TABLE, header=header)
    return show_both(uu_like_decode(text, UU_TABLE))


@tool(
    "encoding.xxencode", "XXencode 编码 / 解码", "encoding", "1.1.8",
    summary="与 UUencode 格式相同，码表换成 +-0-9A-Za-z",
    principle=_UU_PRINCIPLE.format(name="XXencode", full="h", table="`+-0-9A-Za-z`",
                                   hint="满行以 `h` 开头，只含字母、数字、`+` 和 `-`。"),
    inputs=[text_input()],
    options=[mode(default="解码"),
             field("header", "switch", "包含 begin / end", default=True, visible_when={"mode": "编码"})],
    examples=[{"text": "flag{xxencode}", "mode": "编码"}],
    keywords=["xxencode", "xx"],
)
def xx_tool(text, mode="解码", header=True):
    if mode == "编码":
        return uu_like_encode(text.encode("utf-8"), XX_TABLE, header=header)
    return show_both(uu_like_decode(text, XX_TABLE))


# ---------------------------------------------------------------- URL

@tool(
    "encoding.url", "URL 编码 / 解码", "encoding", "1.1.9",
    summary="%66%6C%61%67 形式；Web 题中最常见",
    principle="""
    URL 中只能出现部分 ASCII 字符，其他字节写成 `%` 加两位十六进制（百分号编码），
    中文按 UTF-8 编码后每个字节一个 `%XX`。表单中的空格常写成 `+`。

    Web 题中常用“全部编码”绕过对关键字的过滤，或进行二次编码（`%25` 是 `%` 本身）。
    """,
    inputs=[text_input(placeholder="flag%7B%E4%BD%A0%E5%A5%BD%7D")],
    options=[mode(default="解码"),
             field("all", "switch", "编码全部字符", default=False, visible_when={"mode": "编码"}),
             field("plus", "switch", "把 + 当作空格", default=True, visible_when={"mode": "解码"})],
    examples=[{"text": "flag%7B%E4%BD%A0%E5%A5%BD%7D", "mode": "解码"}],
    keywords=["url", "urlencode", "百分号"],
)
def url_tool(text, mode="解码", all=False, plus=True):
    if mode == "编码":
        if all:
            return "".join("%%%02X" % b for b in text.encode("utf-8"))
        return quote(text, safe="")
    s = text.replace("+", " ") if plus else text
    return show_both(unquote_to_bytes(s))
