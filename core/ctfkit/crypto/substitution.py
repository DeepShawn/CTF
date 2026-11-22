"""代换类古典密码：简单替换、词频分析、培根、波利比奥斯方阵、键盘、当铺、手机九宫格
（教材 3.1.4～3.1.6、3.1.8）。"""

import re
import string

from ..registry import ToolError, field, mode, text_input, tool
from ..util import ENGLISH_FREQ, table

LOWER, UPPER = string.ascii_lowercase, string.ascii_uppercase

# ---------------------------------------------------------------- 简单替换


def _key_alphabet(key):
    k = "".join(dict.fromkeys(c for c in key.lower() if c in LOWER))
    if len(k) == 26:
        return k
    if len(k) < 26 and not re.search(r"[^a-z\s]", key.lower()):
        # 关键词形式：关键词去重后放前面，剩下的字母按顺序补在后面
        return k + "".join(c for c in LOWER if c not in k)
    raise ToolError("替换表应为 26 个不重复的字母，或一个关键词")


@tool(
    "classical.substitution", "简单替换密码", "classical", "3.1.6",
    summary="按 26 个字母的替换表（或关键词）加密 / 解密",
    principle="""
    简单替换密码把每个字母换成替换表中对应位置的字母：替换表 `qwertyuiop…` 表示 `a → q`、`b → w`……
    密钥空间有 26! ≈ 4 × 10²⁶ 种，无法枚举，但可以用**词频分析**破解（见“词频分析”工具）。

    **关键词形式**：只给一个单词如 `KEYWORD`，替换表是 `keyword` 去重后接上其余字母：
    `keywordabcfghijlmnpqstuvxz`。
    """,
    inputs=[text_input(placeholder="ysqu{lxwlzozxzogf}")],
    options=[mode(("加密", "解密"), default="解密"),
             field("key", "string", "替换表 / 关键词", default="qwertyuiopasdfghjklzxcvbnm",
                   help="第 1 个字母代替 a，第 2 个代替 b，依此类推")],
    examples=[{"text": "ysqu{lxwlzozxzogf}", "mode": "解密", "key": "qwertyuiopasdfghjklzxcvbnm"}],
    keywords=["替换", "substitution", "单表代换"],
)
def substitution_tool(text, mode="解密", key="qwertyuiopasdfghjklzxcvbnm"):
    k = _key_alphabet(key)
    src, dst = (LOWER, k) if mode == "加密" else (k, LOWER)
    return text.translate(str.maketrans(src + src.upper(), dst + dst.upper()))


# ---------------------------------------------------------------- 词频分析

ENGLISH_ORDER = "".join(sorted(ENGLISH_FREQ, key=lambda c: -ENGLISH_FREQ[c]))


@tool(
    "classical.frequency", "词频分析", "classical", "3.1.6",
    summary="统计字母频率，与英文频率对照，给出初步替换猜测",
    principle="""
    英文中各字母出现的频率相对固定：`e` 最多（约 12.7%），其次是 `t a o i n s h r`。
    单表代换（凯撒、替换、仿射……）只改变字母的样子，不改变出现次数，
    所以统计密文中最常见的字母，大概率对应 `e`、`t`、`a`。

    **步骤**：
    1. 统计密文字母频率，最常见的先猜成 `e`；
    2. 找常见单词：三个字母且最常见的多半是 `the`，单独一个字母是 `a` 或 `i`；
    3. 把猜测填进“简单替换”的替换表，看结果，逐步修正。

    密文太短（少于 100 个字母）时频率不准，要更多依靠单词形状猜测。
    “初步猜测”只是把频率顺序直接对应过去，通常只有几个字母是对的，需要手动调整。
    """,
    inputs=[text_input(placeholder="粘贴较长的密文")],
    examples=[{"text": "Oz vql zit wtlz gy zodtl, oz vql zit vgklz gy zodtl, oz vql zit qut gy volrgd, oz vql zit qut gy yggsoliftll, oz vql zit thgei gy wtsoty, oz vql zit thgei gy ofektrxsozn, oz vql zit ltqlgf gy souiz, oz vql zit ltqlgf gy rqkaftll. Zit ysqu ol yktjxtfen qfqsnlol vgkal."}],
    keywords=["词频", "频率", "frequency"],
)
def frequency_tool(text):
    letters = [c for c in text.lower() if c in LOWER]
    if not letters:
        raise ToolError("没有找到英文字母")
    n = len(letters)
    counts = {c: letters.count(c) for c in LOWER}
    order = sorted(LOWER, key=lambda c: (-counts[c], c))
    rows = [[c, counts[c], "%.2f%%" % (100.0 * counts[c] / n), ENGLISH_ORDER[i], "%.2f%%" % ENGLISH_FREQ[ENGLISH_ORDER[i]]]
            for i, c in enumerate(order) if counts[c]]
    guess = {order[i]: ENGLISH_ORDER[i] for i in range(26)}
    words = re.findall(r"[a-z]+", text.lower())
    common = {}
    for w in words:
        if 1 <= len(w) <= 3:
            common[w] = common.get(w, 0) + 1
    tops = sorted(common.items(), key=lambda x: -x[1])[:8]
    key = "".join(next(c for c in LOWER if guess[c] == p) for p in LOWER)
    return [
        table(["密文字母", "次数", "频率", "按频率对应的英文字母", "英文频率"], rows),
        table(["项目", "内容"], [
            ["字母总数", n],
            ["初步猜测的明文", text.lower().translate(str.maketrans(LOWER, "".join(guess[c] for c in LOWER)))[:500]],
            ["对应替换表（可填入“简单替换”加密模式的替换表）", key],
            ["常见短单词", "，".join("%s × %d" % t for t in tops) or "无"],
        ]),
    ]


# ---------------------------------------------------------------- 培根密码

BACON26 = {c: "{:05b}".format(i).replace("0", "A").replace("1", "B") for i, c in enumerate(LOWER)}
BACON24 = {}
_i = 0
for _c in LOWER:
    if _c in "jv":                               # 24 字母版：i/j、u/v 共用
        BACON24[_c] = BACON24["i" if _c == "j" else "u"]
        continue
    BACON24[_c] = "{:05b}".format(_i).replace("0", "A").replace("1", "B")
    _i += 1


@tool(
    "classical.bacon", "培根密码", "classical", "3.1.5",
    summary="每个字母写成 5 位 A/B；也可藏在大小写或两种字体里",
    principle="""
    培根密码把每个字母写成 5 位的 A、B 组合（本质是 5 位二进制）：`a = AAAAA`、`b = AAAAB`……

    有两个版本：
    - **26 字母版**：a～z 依次对应 0～25；
    - **24 字母版**（培根原版）：i 与 j、u 与 v 共用一个编码。

    **藏法**：A/B 不一定直接写出来，可能是大小写（小写 = A，大写 = B）、两种字体、
    两种符号（如 `.` 和 `-`）。只要内容只有两种“状态”、且总数是 5 的倍数，就可以试培根密码。
    """,
    inputs=[text_input(placeholder="AABAB ABABB AAAAA AABBA")],
    options=[mode(default="解码"),
             field("variant", "segmented", "版本", default="26 字母", choices=["26 字母", "24 字母"]),
             field("symbols", "select", "A / B 的表示", default="A 和 B",
                   choices=["A 和 B", "0 和 1", "小写和大写字母"], visible_when={"mode": "解码"})],
    examples=[{"text": "AABAB ABABB AAAAA AABBA", "mode": "解码"}],
    keywords=["培根", "bacon"],
)
def bacon_tool(text, mode="解码", variant="26 字母", symbols="A 和 B"):
    table_ = BACON26 if variant == "26 字母" else BACON24
    if mode == "编码":
        return " ".join(table_[c] for c in text.lower() if c in LOWER)
    if symbols == "0 和 1":
        s = re.sub(r"[^01]", "", text).replace("0", "A").replace("1", "B")
    elif symbols == "小写和大写字母":
        s = "".join("B" if c.isupper() else "A" for c in text if c.isalpha())
    else:
        s = re.sub(r"[^AB]", "", text.upper())
    if not s:
        raise ToolError("没有找到 A / B 符号，检查“A / B 的表示”设置")
    rev = {}
    for c, code in table_.items():
        rev.setdefault(code, c)
    out = "".join(rev.get(s[i:i + 5], "?") for i in range(0, len(s) - 4, 5))
    note = "" if len(s) % 5 == 0 else "\n（共 %d 个符号，不是 5 的倍数，末尾 %d 个被忽略）" % (len(s), len(s) % 5)
    return out + note


# ---------------------------------------------------------------- 波利比奥斯方阵

def _square(key, size=5):
    alphabet = "abcdefghiklmnopqrstuvwxyz" if size == 5 else LOWER + "0123456789"
    k = "".join(dict.fromkeys(c for c in key.lower().replace("j", "i" if size == 5 else "j") if c in alphabet))
    return k + "".join(c for c in alphabet if c not in k)


@tool(
    "classical.polybius", "波利比奥斯方阵", "classical", "3.1.8",
    summary="字母写成方阵中的“行列”两位数字，如 a = 11",
    principle="""
    把 25 个字母（i 与 j 合并）排成 5 × 5 的方阵，每个字母用它所在的**行号和列号**表示：
    `a = 11`、`b = 12`、`f = 21`……密文是一串由 1～5 组成的两位数。
    给出关键词时，方阵先填关键词（去重），再按顺序填剩下的字母。

    ADFGX 密码、敲击码（Tap Code）都是在这个方阵的基础上变形的。
    """,
    inputs=[text_input(placeholder="21 31 11 22")],
    options=[mode(default="解码"),
             field("key", "string", "关键词", default="", placeholder="留空使用 abcde…")],
    examples=[{"text": "21 31 11 22", "mode": "解码"}],
    keywords=["polybius", "棋盘", "方阵", "敲击码"],
)
def polybius_tool(text, mode="解码", key=""):
    sq = _square(key)
    if mode == "编码":
        out = []
        for c in text.lower().replace("j", "i"):
            if c in sq:
                i = sq.index(c)
                out.append("%d%d" % (i // 5 + 1, i % 5 + 1))
        return " ".join(out)
    digits = re.sub(r"[^1-5]", "", text)
    if len(digits) % 2:
        raise ToolError("数字个数应为偶数（每个字母两位）")
    return "".join(sq[(int(digits[i]) - 1) * 5 + int(digits[i + 1]) - 1] for i in range(0, len(digits), 2))


# ---------------------------------------------------------------- 键盘密码

QWERTY = "qwertyuiopasdfghjklzxcvbnm"


@tool(
    "classical.keyboard", "键盘密码", "classical", "3.1.8",
    summary="QWERTY 键盘顺序与字母表互转；手机九宫格；当铺密码",
    principle="""
    CTF 中常见的几种“键盘”类密码：

    - **QWERTY 替换**：把键盘上从左到右、从上到下的字母 `qwertyuiop asdfghjkl zxcvbnm`
      依次对应 `a～z`。本质是一种固定替换表的简单替换密码；
    - **手机九宫格**：数字表示按键，重复次数表示第几个字母，如 `2` = a、`22` = b、`222` = c、`7777` = s；
      也有写成“按键 + 次数”的两位数形式，如 `21` = a、`74` = s；
    - **当铺密码**：一个汉字代表它出头的笔画数：田 0、由 1、中 2、人 3、工 4、大 5、王 6、夫 7、井 8、羊 9。
    """,
    inputs=[text_input(placeholder="ysqu")],
    options=[field("variant", "select", "类型", default="QWERTY → 字母表",
                   choices=["QWERTY → 字母表", "字母表 → QWERTY", "九宫格（重复次数）", "九宫格（两位数）", "当铺密码"])],
    examples=[{"text": "ysqu", "variant": "QWERTY → 字母表"}, {"text": "333 555 2 4", "variant": "九宫格（重复次数）"},
              {"text": "王夫 井工 夫田", "variant": "当铺密码"}],
    keywords=["键盘", "qwerty", "九宫格", "当铺", "手机"],
)
def keyboard_tool(text, variant="QWERTY → 字母表"):
    if variant == "QWERTY → 字母表":
        return text.translate(str.maketrans(QWERTY + QWERTY.upper(), LOWER + UPPER))
    if variant == "字母表 → QWERTY":
        return text.translate(str.maketrans(LOWER + UPPER, QWERTY + QWERTY.upper()))
    keys = {"2": "abc", "3": "def", "4": "ghi", "5": "jkl", "6": "mno", "7": "pqrs", "8": "tuv", "9": "wxyz", "0": " "}
    if variant == "九宫格（重复次数）":
        out = []
        for g in re.finditer(r"(\d)\1*", text):
            s = g.group(0)
            letters = keys.get(s[0])
            if not letters:
                raise ToolError("按键 %s 上没有字母" % s[0])
            out.append(letters[(len(s) - 1) % len(letters)])
        return "".join(out)
    if variant == "九宫格（两位数）":
        out = []
        for a, b in re.findall(r"(\d)(\d)", re.sub(r"\D", "", text)):
            letters = keys.get(a)
            if not letters or not 1 <= int(b) <= len(letters):
                raise ToolError("“%s%s”不是有效的按键 + 次数" % (a, b))
            out.append(letters[int(b) - 1])
        return "".join(out)
    pawn = "田由中人工大王夫井羊"
    out = []
    for group in text.split():
        digits = "".join(str(pawn.index(c)) for c in group if c in pawn)
        if digits:
            n = int(digits)
            out.append(chr(n) if 32 <= n < 127 else digits)
    return "".join(out) + "\n（每组按数字转成 ASCII；不在可打印范围的保留数字）"
