"""智能识别（教材 1.1.13 编码类题目的通用解题方法）。

做编码题的通用方法是：观察字符集和长度，猜一种编码，解开后看结果像不像有意义的内容，
不像就换一种，像但还不是 flag 就继续解下一层。本工具把这个过程自动化：
对输入尝试全部解码方法，给每个结果打分，分高的继续往下解，最后按分数排序列出“解码路径”。
"""

import base64
import codecs
import html
import quopri
import re
from urllib.parse import unquote_to_bytes

from ..registry import ToolError, field, text_input, tool
from ..util import FLAG_RE, english_score, printable_ratio, table
from . import base as B
from .esolang import ook_to_bf, run_bf
from .legacy import UU_TABLE, XX_TABLE, uu_like_decode
from .morse import REVERSE as MORSE_REVERSE
from .text import corevalues_decode


def _s(data):
    return data.decode("utf-8") if isinstance(data, bytes) else data


def _need(pattern, s, min_len=4):
    if len(s) < min_len or not re.fullmatch(pattern, s):
        raise ValueError


def d_base64(s):
    t = re.sub(r"\s", "", s)
    _need(r"[A-Za-z0-9+/]+={0,2}", t)
    if len(t.rstrip("=")) % 4 == 1:
        raise ValueError
    return base64.b64decode(t.rstrip("=") + "=" * (-len(t.rstrip("=")) % 4))


def d_base64url(s):
    t = re.sub(r"\s", "", s)
    _need(r"[A-Za-z0-9_-]*[_-][A-Za-z0-9_-]*={0,2}", t)
    return base64.urlsafe_b64decode(t.rstrip("=") + "=" * (-len(t.rstrip("=")) % 4))


def d_base32(s):
    t = re.sub(r"\s", "", s).upper()
    _need(r"[A-Z2-7]+=*", t, 8)
    return base64.b32decode(t.rstrip("=") + "=" * (-len(t.rstrip("=")) % 8))


def d_hex(s):
    t = re.sub(r"0x|\\x|[\s:,]", "", s, flags=re.I)
    _need(r"(?:[0-9a-fA-F]{2})+", t)
    return bytes.fromhex(t)


def d_base58(s):
    _need(r"[1-9A-HJ-NP-Za-km-z]+", s.strip(), 4)
    return B.int_decode(s, B.B58_BTC)


def d_base85(s):
    t = re.sub(r"\s", "", s)
    if t.startswith("<~") and t.endswith("~>"):
        return base64.a85decode(t[2:-2])
    _need(r"[!-u]+", t, 5)
    return base64.a85decode(t)


def d_base91(s):
    t = s.strip()
    _need(r"[A-Za-z0-9!#$%&()*+,./:;<=>?@\[\]^_`{|}~\"]+", t, 4)
    if not re.search(r"[^A-Za-z0-9+/=]", t):          # 看起来像 Base64 的不再当作 Base91
        raise ValueError
    return B.b91decode(t)


def d_binary(s):
    t = re.sub(r"\s", "", s)
    _need(r"[01]+", t, 8)
    if len(t) % 8:
        raise ValueError
    return bytes(int(t[i:i + 8], 2) for i in range(0, len(t), 8))


def d_decimal(s):
    parts = re.split(r"[\s,]+", s.strip())
    if len(parts) < 3 or not all(p.isdigit() and int(p) < 256 for p in parts):
        raise ValueError
    return bytes(int(p) for p in parts)


def d_octal(s):
    parts = re.split(r"[\s,]+", s.strip())
    if len(parts) < 3 or not all(re.fullmatch(r"[0-7]{3}", p) for p in parts):
        raise ValueError
    return bytes(int(p, 8) for p in parts)


def d_url(s):
    if not re.search(r"%[0-9a-fA-F]{2}", s):
        raise ValueError
    return unquote_to_bytes(s)


def d_unicode(s):
    if not re.search(r"\\u[0-9a-fA-F]{4}|&#x?[0-9a-fA-F]+;|&[a-z]+;", s):
        raise ValueError
    from .text import unicode_tool
    return unicode_tool(s, "解码").encode("utf-8")


def d_html(s):
    if not re.search(r"&[a-z]+;|&#\d+;", s):
        raise ValueError
    return html.unescape(s).encode("utf-8")


def d_qp(s):
    if not re.search(r"=[0-9A-F]{2}", s):
        raise ValueError
    return quopri.decodestring(s.encode("utf-8"))


def d_uu(s):
    if "begin " not in s:
        raise ValueError
    try:
        return uu_like_decode(s, UU_TABLE)
    except ToolError:
        return uu_like_decode(s, XX_TABLE)


def d_morse(s):
    t = s.strip()
    _need(r"[.\-/\s|]+", t, 3)
    words = re.split(r"\s*[/|]\s*", t)
    out = []
    for w in words:
        letters = [MORSE_REVERSE.get(p) for p in w.split()]
        if None in letters:
            raise ValueError
        out.append("".join(letters))
    return " ".join(out).encode("ascii")


def d_rot13(s):
    if not re.search(r"[A-Za-z]", s):
        raise ValueError
    return codecs.encode(s, "rot13").encode("utf-8")


def d_reverse(s):
    if not FLAG_RE.search(s[::-1]) and not re.search(r"=+$|^=+", s.strip()[::-1]):
        raise ValueError                              # 只有反转后出现 flag 或 Base64 填充时才尝试
    return s.strip()[::-1].encode("utf-8")


def d_brainfuck(s):
    if "Ook" in s:
        return run_bf(ook_to_bf(s), max_steps=500000)
    t = re.sub(r"\s", "", s)
    _need(r"[+\-<>\[\].,]+", t, 8)
    return run_bf(t, max_steps=500000)


def d_corevalues(s):
    if not re.fullmatch(r"(?:%s)+" % "|".join(re.findall("..", "富强民主文明和谐自由平等公正法治爱国敬业诚信友善")),
                        re.sub(r"\s", "", s)):
        raise ValueError
    return corevalues_decode(s).encode("utf-8")


DECODERS = [
    ("Base64", d_base64), ("Base64（URL 安全）", d_base64url), ("Base32", d_base32), ("十六进制", d_hex),
    ("Base58", d_base58), ("Base85", d_base85), ("Base91", d_base91), ("二进制", d_binary),
    ("十进制 ASCII", d_decimal), ("八进制 ASCII", d_octal), ("URL", d_url), ("Unicode 转义", d_unicode),
    ("HTML 实体", d_html), ("Quoted-printable", d_qp), ("UU / XXencode", d_uu), ("摩斯密码", d_morse),
    ("ROT13", d_rot13), ("反转", d_reverse), ("Brainfuck / Ook!", d_brainfuck), ("核心价值观", d_corevalues),
]


def score(data, flag_re=FLAG_RE):
    """结果打分：可打印字符比例为主，像英文、出现 flag 加分。"""
    try:
        text = data.decode("utf-8")
        ratio = 1.0 if all(c.isprintable() or c in "\r\n\t" for c in text) else printable_ratio(data)
    except UnicodeDecodeError:
        text = data.decode("latin-1")
        ratio = printable_ratio(data) * 0.8
    s = ratio * 60
    if ratio > 0.95:
        s += min(english_score(text), 40) * 0.5
    if flag_re.search(text):
        s += 100
    return round(s, 1), text


def magic(text, depth=4, flag_re=FLAG_RE, beam=6):
    """逐层尝试全部解码方法，返回 [(分数, 路径, 结果文本)]，按分数从高到低排序。"""
    start = text.strip()
    frontier = [(0.0, [], start)]
    seen = {start}
    found = []
    for _ in range(depth):
        nxt = []
        for _, path, cur in frontier:
            for name, fn in DECODERS:
                if path and path[-1] == name and name in ("ROT13", "反转"):
                    continue                            # ROT13、反转做两次等于没做
                try:
                    out = fn(cur)
                except Exception:
                    continue
                if not out:
                    continue
                sc, s = score(out, flag_re)
                if sc < 30 or s in seen or s.strip() == cur.strip():
                    continue
                seen.add(s)
                item = (sc, path + [name], s)
                found.append(item)
                if sc >= 45:
                    nxt.append(item)
        nxt.sort(key=lambda x: -x[0])
        frontier = nxt[:beam]
        if not frontier:
            break
    # 同分时路径短的排前面
    found.sort(key=lambda x: (-x[0], len(x[1])))
    return found


@tool(
    "encoding.magic", "智能识别", "encoding", "1.1.13",
    summary="粘贴任意文本，自动尝试全部编码并逐层解开，按可能性排序",
    principle="""
    编码题的通用解法是“观察 → 猜测 → 验证”：

    1. **看字符集**：只有 `0-9a-f` 可能是十六进制；有 `=` 结尾、大小写混合可能是 Base64；
       只有大写和 `2-7` 可能是 Base32；只有 `.-` 可能是摩斯；
    2. **看长度**：Base64 是 4 的倍数，Base32 是 8 的倍数，十六进制是 2 的倍数；
    3. **验证**：解出来是可读文本就对了；还是一串编码就继续解下一层。

    本工具对每一层尝试全部 20 种解码，用“可打印字符比例、像不像英文、有没有 flag”打分，
    保留分数高的继续往下解，最多 4 层。可以在“flag 格式”中填写题目要求的格式（正则表达式）。
    分数只是参考，最终要自己判断结果是否合理。
    """,
    inputs=[text_input(placeholder="粘贴需要识别的内容")],
    options=[field("depth", "number", "最多解几层", default=4, min=1, max=8),
             field("flag", "string", "flag 格式（正则）", default="", placeholder=r"如 flag\{.*?\}，留空使用默认")],
    examples=[{"text": "Wm14aFozdHRZV2RwWTE5bGJtTnZaR2x1WjMwPQ=="}],
    keywords=["magic", "识别", "自动", "cyberchef"],
)
def magic_tool(text, depth=4, flag=""):
    if not text.strip():
        raise ToolError("请输入要识别的内容")
    try:
        flag_re = re.compile(flag, re.I) if flag else FLAG_RE
    except re.error as e:
        raise ToolError("flag 格式不是有效的正则表达式：%s" % e)
    results = magic(text, int(depth), flag_re)
    if not results:
        raise ToolError("没有找到能解开的编码。可以试试古典密码类工具，或检查是否复制完整")
    rows = [[sc, " → ".join(path), s if len(s) <= 300 else s[:300] + "…"] for sc, path, s in results[:30]]
    return table(["分数", "解码路径", "结果"], rows)
