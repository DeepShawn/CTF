"""移位类古典密码：凯撒、ROT 系列、Atbash、仿射（教材 3.1.1～3.1.3、3.1.7）。

这几种密码都是“单表代换”：每个字母固定替换成另一个字母，区别只在替换规则。
"""

import string
from math import gcd

from ..registry import ToolError, field, text_input, tool
from ..util import english_score, table

LOWER, UPPER = string.ascii_lowercase, string.ascii_uppercase


def shift(text, k):
    """凯撒移位：字母向后移 k 位，保留大小写，非字母不变。"""
    k %= 26
    t = str.maketrans(LOWER + UPPER, LOWER[k:] + LOWER[:k] + UPPER[k:] + UPPER[:k])
    return text.translate(t)


@tool(
    "classical.caesar", "凯撒密码", "classical", "3.1.1",
    summary="字母移位；可一次列出全部 26 种位移并按“像不像英文”排序",
    principle="""
    凯撒密码把每个字母在字母表中向后移动固定的位数 k：k = 3 时 `a → d`、`z → c`。
    解密就是向前移 k 位（或向后移 26 − k 位）。

    **为什么容易破解**：密钥只有 26 种可能，全部试一遍即可（枚举）。
    本工具按英文字母频率和常见单词给 26 个结果打分，最像英文的排在最前面。

    **变形**：数字和符号也移动了，可能是 ROT47；每个字母位移不同，可能是维吉尼亚密码。
    """,
    inputs=[text_input(placeholder="synt{pnrfne}")],
    options=[field("mode", "segmented", "模式", default="枚举全部", choices=["枚举全部", "加密", "解密"]),
             field("key", "number", "位移 k", default=3, min=0, max=25, visible_when={"mode": ["加密", "解密"]})],
    examples=[{"text": "synt{pnrfne}", "mode": "枚举全部"}, {"text": "flag{caesar}", "mode": "加密", "key": 3}],
    keywords=["caesar", "凯撒", "移位"],
)
def caesar_tool(text, mode="枚举全部", key=3):
    key = int(key)
    if mode == "加密":
        return shift(text, key)
    if mode == "解密":
        return shift(text, -key)
    rows = [[k, english_score(shift(text, -k)), shift(text, -k)] for k in range(26)]
    rows.sort(key=lambda r: -r[1])
    return table(["密钥 k（解密时左移）", "得分", "结果"], rows)


def rot47(text):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)


def rot5(text):
    return text.translate(str.maketrans("0123456789", "5678901234"))


@tool(
    "classical.rot", "ROT5 / ROT13 / ROT18 / ROT47", "classical", "3.1.2",
    summary="固定位移的特例；加密与解密是同一个操作",
    principle="""
    | 名称 | 作用范围 | 位移 |
    |---|---|---|
    | ROT5 | 数字 0～9 | 5 |
    | ROT13 | 字母 | 13 |
    | ROT18 | 字母 + 数字（ROT13 加 ROT5） | 13 / 5 |
    | ROT47 | ASCII 33～126 的全部可打印字符 | 47 |

    因为位移正好是范围的一半，做两次等于没做，所以加密和解密是同一个操作。
    `flag` 经 ROT13 是 `synt`；经 ROT47 是 `7=28`。
    """,
    inputs=[text_input(placeholder="synt{ebg13}")],
    options=[field("variant", "segmented", "类型", default="ROT13", choices=["ROT5", "ROT13", "ROT18", "ROT47"])],
    examples=[{"text": "synt{ebg13}", "variant": "ROT13"}, {"text": "7=28L#~%cfN", "variant": "ROT47"}],
    keywords=["rot13", "rot47", "rot5", "rot18"],
)
def rot_tool(text, variant="ROT13"):
    if variant == "ROT5":
        return rot5(text)
    if variant == "ROT13":
        return shift(text, 13)
    if variant == "ROT18":
        return rot5(shift(text, 13))
    return rot47(text)


@tool(
    "classical.atbash", "Atbash 埃特巴什码", "classical", "3.1.3",
    summary="字母表倒过来：a↔z、b↔y",
    principle="""
    Atbash 把字母表首尾对调：`a ↔ z`、`b ↔ y`、`c ↔ x`……第 i 个字母换成第 25 − i 个。
    没有密钥，加密和解密相同。`flag` 经 Atbash 是 `uozt`。
    """,
    inputs=[text_input(placeholder="uozt{zgyzhs}")],
    examples=[{"text": "uozt{zgyzhs}"}],
    keywords=["atbash", "埃特巴什"],
)
def atbash_tool(text):
    return text.translate(str.maketrans(LOWER + UPPER, LOWER[::-1] + UPPER[::-1]))


# ---------------------------------------------------------------- 仿射密码

def affine(text, a, b, decrypt=False):
    if gcd(a, 26) != 1:
        raise ToolError("a = %d 与 26 不互素，无法解密。a 只能取 1 3 5 7 9 11 15 17 19 21 23 25" % a)
    inv = pow(a, -1, 26)
    out = []
    for c in text:
        for base in (LOWER, UPPER):
            if c in base:
                x = base.index(c)
                y = inv * (x - b) % 26 if decrypt else (a * x + b) % 26
                out.append(base[y])
                break
        else:
            out.append(c)
    return "".join(out)


@tool(
    "classical.affine", "仿射密码", "classical", "3.1.7",
    summary="E(x) = (a·x + b) mod 26；可枚举全部 312 组密钥",
    principle="""
    把字母 `a～z` 记作 0～25，加密公式为 `E(x) = (a·x + b) mod 26`，解密为
    `D(y) = a⁻¹·(y − b) mod 26`，其中 a⁻¹ 是 a 模 26 的逆元。

    a 必须与 26 互素（否则有两个字母会加密成同一个，无法解密），所以 a 只有 12 种取值，
    b 有 26 种，密钥一共 12 × 26 = 312 种，可以全部枚举。

    a = 1 时就是凯撒密码。已知两组明文和密文字母时，也可以解方程直接求出 a 和 b。
    """,
    inputs=[text_input(placeholder="ihhwvc swfrcp")],
    options=[field("mode", "segmented", "模式", default="解密", choices=["加密", "解密", "枚举全部"]),
             field("a", "number", "a", default=5, min=1, max=25, visible_when={"mode": ["加密", "解密"]}),
             field("b", "number", "b", default=8, min=0, max=25, visible_when={"mode": ["加密", "解密"]})],
    examples=[{"text": "ihhwvc swfrcp", "mode": "解密", "a": 5, "b": 8}],
    keywords=["affine", "仿射"],
)
def affine_tool(text, mode="解密", a=5, b=8):
    a, b = int(a), int(b)
    if mode == "加密":
        return affine(text, a, b)
    if mode == "解密":
        return affine(text, a, b, decrypt=True)
    rows = []
    for aa in range(1, 26, 2):
        if aa == 13:
            continue
        for bb in range(26):
            p = affine(text, aa, bb, decrypt=True)
            rows.append([aa, bb, english_score(p), p])
    rows.sort(key=lambda r: -r[2])
    return table(["a", "b", "得分", "结果"], rows[:50])
