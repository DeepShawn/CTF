"""栅栏密码（教材 3.1.0）。

栅栏密码是“换位密码”：字母本身不变，只打乱位置。所以密文的字母频率与明文完全相同，
如果密文里能看到 f、l、a、g、{、} 但顺序是乱的，多半是换位密码。
"""

from ..registry import ToolError, field, text_input, tool
from ..util import english_score, table


def classic_encrypt(text, k):
    """普通型：按 k 个一组分组，依次取每组的第 1 个、第 2 个……字母。"""
    return "".join(text[i::k] for i in range(k))


def classic_decrypt(text, k):
    n = len(text)
    rows = [n // k + (1 if i < n % k else 0) for i in range(k)]   # 每一“栏”有多少个字母
    parts, pos = [], 0
    for r in rows:
        parts.append(text[pos:pos + r])
        pos += r
    return "".join(parts[i][j] for j in range(rows[0]) for i in range(k) if j < len(parts[i]))


def _zigzag(n, k):
    """W 型：字母沿 k 行上下折返书写，返回每个位置所在的行号。"""
    if k == 1:
        return [0] * n
    cycle = 2 * (k - 1)
    return [i % cycle if i % cycle < k else cycle - i % cycle for i in range(n)]


def w_encrypt(text, k):
    rows = _zigzag(len(text), k)
    return "".join(c for r in range(k) for c, rr in zip(text, rows) if rr == r)


def w_decrypt(text, k):
    rows = _zigzag(len(text), k)
    order = sorted(range(len(text)), key=lambda i: (rows[i], i))   # 密文第 j 个字母原来在 order[j]
    out = [""] * len(text)
    for j, i in enumerate(order):
        out[i] = text[j]
    return "".join(out)


@tool(
    "classical.railfence", "栅栏密码", "classical", "3.1.0",
    summary="普通型与 W 型；可枚举全部栏数",
    principle="""
    栅栏密码只打乱字母顺序，不替换字母。有两种常见写法：

    **普通型**（国内 CTF 最常见）：把明文按 k 个一组分组，先取每组的第 1 个字母，再取每组的第 2 个……
    例如 `flag{rail}`、k = 2：分组 `fl ag {r ai l}` → 取第 1 个 `fa{al`，取第 2 个 `lgri}` → `fa{allgri}`。

    **W 型**（国外资料中的 Rail Fence）：把明文沿 k 行上下折返书写，再逐行读出。

    **破解**：栏数一般不超过密文长度，全部枚举即可。看到 `{` `}` 在中间而不在两端，就是换位的信号。
    """,
    inputs=[text_input(placeholder="fa{allgri}")],
    options=[field("mode", "segmented", "模式", default="枚举全部", choices=["枚举全部", "加密", "解密"]),
             field("variant", "segmented", "类型", default="普通型", choices=["普通型", "W 型"]),
             field("key", "number", "栏数 k", default=2, min=2, max=100, visible_when={"mode": ["加密", "解密"]})],
    examples=[{"text": "fa{allgri}", "mode": "枚举全部"}, {"text": "flag{rail}", "mode": "加密", "key": 2}],
    keywords=["栅栏", "rail fence", "换位"],
)
def railfence_tool(text, mode="枚举全部", variant="普通型", key=2):
    enc, dec = (classic_encrypt, classic_decrypt) if variant == "普通型" else (w_encrypt, w_decrypt)
    k = int(key)
    if mode != "枚举全部" and not 2 <= k:
        raise ToolError("栏数至少为 2")
    if mode == "加密":
        return enc(text, k)
    if mode == "解密":
        return dec(text, k)
    rows = []
    for k in range(2, max(3, len(text))):
        p = dec(text, k)
        rows.append([k, english_score(p), p])
    rows.sort(key=lambda r: -r[1])
    return table(["栏数", "得分", "结果"], rows)
