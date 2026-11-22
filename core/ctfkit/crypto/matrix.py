"""希尔密码与 Playfair 密码（教材 3.1.11 及其他古典密码）。"""

import re
import string

from ..registry import ToolError, field, mode, text_input, tool

LOWER = string.ascii_lowercase

# ---------------------------------------------------------------- 希尔密码


def parse_matrix(text):
    nums = [int(x) for x in re.findall(r"-?\d+", text)]
    if not nums:                                     # 也接受字母形式的密钥，如 "hill"
        nums = [LOWER.index(c) for c in text.lower() if c in LOWER]
    n = int(round(len(nums) ** 0.5))
    if n < 2 or n * n != len(nums):
        raise ToolError("密钥矩阵应为 n × n 个数（n ≥ 2），当前有 %d 个" % len(nums))
    return [nums[i * n:(i + 1) * n] for i in range(n)]


def det(m):
    if len(m) == 1:
        return m[0][0]
    return sum((-1) ** j * m[0][j] * det([r[:j] + r[j + 1:] for r in m[1:]]) for j in range(len(m)))


def inverse_mod(m, mod=26):
    """矩阵模逆：伴随矩阵 × 行列式的模逆。"""
    d = det(m) % mod
    try:
        d_inv = pow(d, -1, mod)
    except ValueError:
        raise ToolError("密钥矩阵的行列式为 %d，与 26 不互素，矩阵不可逆，无法解密" % d)
    n = len(m)
    cof = [[(-1) ** (i + j) * det([r[:j] + r[j + 1:] for k, r in enumerate(m) if k != i]) for j in range(n)]
           for i in range(n)]
    return [[cof[j][i] * d_inv % mod for j in range(n)] for i in range(n)]   # 转置


def hill(text, key, decrypt=False, pad="x"):
    m = parse_matrix(key)
    if decrypt:
        m = inverse_mod(m)
    else:
        inverse_mod(m)                               # 加密前先检查可逆，避免得到无法解密的密文
    n = len(m)
    letters = [LOWER.index(c) for c in text.lower() if c in LOWER]
    if not letters:
        raise ToolError("没有找到英文字母")
    while len(letters) % n:
        letters.append(LOWER.index(pad))
    out = []
    for i in range(0, len(letters), n):
        v = letters[i:i + n]
        out.extend(sum(m[r][c] * v[c] for c in range(n)) % 26 for r in range(n))
    return "".join(LOWER[x] for x in out)


@tool(
    "classical.hill", "希尔密码", "classical", "3.1.11",
    summary="用 n × n 矩阵乘法加密每 n 个字母",
    principle="""
    希尔密码把明文每 n 个字母看成一个向量（`a = 0`……`z = 25`），乘以 n × n 的密钥矩阵 K，再模 26：
    `C = K · P mod 26`。解密时乘以 K 的**模 26 逆矩阵**：`P = K⁻¹ · C mod 26`。

    K 可逆的条件是行列式与 26 互素（不能是偶数，也不能是 13 的倍数）。

    **已知明文攻击**：如果知道 n 组明文和对应的密文（如 flag 开头的 `flag`），
    可以列方程 `C = K · P` 直接解出 K——这是希尔密码的主要弱点。
    密钥可以写成数字（`3 3 2 5`，按行排列），也可以写成字母（`hill` 表示 7 8 11 11）。
    """,
    inputs=[text_input(placeholder="密文")],
    options=[mode(("加密", "解密"), default="解密"),
             field("key", "string", "密钥矩阵", default="3 3 2 5", help="按行排列的 n² 个数，或 n² 个字母")],
    examples=[{"text": "hiat", "mode": "解密", "key": "3 3 2 5"}],
    keywords=["hill", "希尔", "矩阵"],
)
def hill_tool(text, mode="解密", key="3 3 2 5"):
    return hill(text, key, decrypt=(mode == "解密"))


# ---------------------------------------------------------------- Playfair


def playfair_square(key):
    alphabet = "abcdefghiklmnopqrstuvwxyz"
    k = "".join(dict.fromkeys(c for c in key.lower().replace("j", "i") if c in alphabet))
    return k + "".join(c for c in alphabet if c not in k)


def playfair_pairs(text):
    s = [c for c in text.lower().replace("j", "i") if c in LOWER]
    pairs, i = [], 0
    while i < len(s):
        a = s[i]
        b = s[i + 1] if i + 1 < len(s) else "x"
        if a == b:                                   # 同一组两个相同字母，中间插入 x
            pairs.append((a, "x" if a != "x" else "q"))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs


def playfair(text, key, decrypt=False):
    sq = playfair_square(key)
    pos = {c: divmod(i, 5) for i, c in enumerate(sq)}
    d = -1 if decrypt else 1
    if decrypt:
        s = [c for c in text.lower().replace("j", "i") if c in LOWER]
        if len(s) % 2:
            raise ToolError("Playfair 密文的字母数应为偶数")
        pairs = [(s[i], s[i + 1]) for i in range(0, len(s), 2)]
    else:
        pairs = playfair_pairs(text)
    out = []
    for a, b in pairs:
        (ra, ca), (rb, cb) = pos[a], pos[b]
        if ra == rb:                                 # 同一行：各取右边一个（解密取左边）
            out += [sq[ra * 5 + (ca + d) % 5], sq[rb * 5 + (cb + d) % 5]]
        elif ca == cb:                               # 同一列：各取下边一个（解密取上边）
            out += [sq[((ra + d) % 5) * 5 + ca], sq[((rb + d) % 5) * 5 + cb]]
        else:                                        # 矩形：交换列
            out += [sq[ra * 5 + cb], sq[rb * 5 + ca]]
    return "".join(out)


@tool(
    "classical.playfair", "Playfair 密码", "classical", "3.1",
    summary="5 × 5 方阵，每两个字母一组加密",
    principle="""
    Playfair 用关键词生成 5 × 5 的字母方阵（i 与 j 合并），明文两个字母一组，按位置关系替换：

    1. **同一行**：各取右边的字母（行尾回到行首）；
    2. **同一列**：各取下面的字母（列尾回到列首）；
    3. **不同行列**：两个字母构成矩形的两个对角，换成另外两个对角（行不变，列互换）。

    分组时如果两个字母相同，在中间插入 `x`；字母数为奇数时末尾补 `x`。
    所以解密结果中多余的 `x` 需要自己去掉。
    """,
    inputs=[text_input(placeholder="密文")],
    options=[mode(("加密", "解密"), default="解密"),
             field("key", "string", "关键词", default="playfair example")],
    examples=[{"text": "bmodzbxdnabekudmuixmmouvif", "mode": "解密", "key": "playfair example"}],
    keywords=["playfair", "普莱费尔"],
)
def playfair_tool(text, mode="解密", key="playfair example"):
    return playfair(text, key, decrypt=(mode == "解密"))
