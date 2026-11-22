"""维吉尼亚密码与无密钥破解（教材 3.1.9～3.1.10）。"""

import string
from collections import Counter

from ..registry import ToolError, field, text_input, tool
from ..util import ENGLISH_FREQ, english_score, table

LOWER = string.ascii_lowercase


def vigenere(text, key, decrypt=False, variant="维吉尼亚"):
    ks = [LOWER.index(c) for c in key.lower() if c in LOWER]
    if not ks:
        raise ToolError("密钥中至少要有一个英文字母")
    out, j = [], 0
    for c in text:
        lower = c.lower()
        if lower not in LOWER:
            out.append(c)                           # 非字母原样保留，且不消耗密钥
            continue
        x, k = LOWER.index(lower), ks[j % len(ks)]
        j += 1
        if variant == "博福特":                      # Beaufort：加密与解密相同，y = k − x
            y = (k - x) % 26
        else:
            y = (x - k) % 26 if decrypt else (x + k) % 26
        out.append(LOWER[y].upper() if c.isupper() else LOWER[y])
    return "".join(out)


def index_of_coincidence(s):
    n = len(s)
    if n < 2:
        return 0.0
    return sum(v * (v - 1) for v in Counter(s).values()) / (n * (n - 1))


def best_shift(column):
    """对一列字母找最可能的凯撒位移：使解出的字母频率与英文最接近（卡方最小）。"""
    best = None
    n = len(column)
    for k in range(26):
        counts = Counter((LOWER.index(c) - k) % 26 for c in column)
        chi = sum((counts.get(i, 0) - n * ENGLISH_FREQ[LOWER[i]] / 100) ** 2 / (n * ENGLISH_FREQ[LOWER[i]] / 100)
                  for i in range(26))
        if best is None or chi < best[0]:
            best = (chi, k)
    return best[1]


def kasiski(letters, min_len=3):
    """Kasiski 测试：重复出现的字母串之间的距离，往往是密钥长度的倍数。"""
    pos = {}
    for i in range(len(letters) - min_len + 1):
        pos.setdefault(letters[i:i + min_len], []).append(i)
    dists = Counter()
    for p in pos.values():
        for a, b in zip(p, p[1:]):
            d = b - a
            for f in range(2, 21):
                if d % f == 0:
                    dists[f] += 1
    return dists


def crack(text, max_len=20):
    letters = "".join(c for c in text.lower() if c in LOWER)
    if len(letters) < 30:
        raise ToolError("密文至少需要 30 个字母才能统计；当前只有 %d 个" % len(letters))
    kas = kasiski(letters)
    results = []
    for L in range(1, min(max_len, len(letters) // 4) + 1):
        cols = [letters[i::L] for i in range(L)]
        ioc = sum(index_of_coincidence(c) for c in cols) / L
        key = "".join(LOWER[best_shift(c)] for c in cols)
        plain = vigenere(text, key, decrypt=True)
        results.append([L, round(ioc, 4), kas.get(L, 0), key, english_score(plain), plain[:200]])
    # 英文的重合指数约 0.066，随机文本约 0.038。重合指数明显偏高（> 0.055）的长度中，
    # 最短的那个最可能正确（它的倍数也会偏高）；其余按重合指数从高到低排在后面
    results.sort(key=lambda r: (0, r[0]) if r[1] > 0.055 else (1, -r[1]))
    return results


@tool(
    "classical.vigenere", "维吉尼亚密码", "classical", "3.1.10",
    summary="多表代换；支持无密钥破解（重合指数 + 频率分析）",
    principle="""
    维吉尼亚密码用一个单词作密钥，密钥的每个字母表示一个凯撒位移（`a = 0`、`b = 1`……），
    明文的第 i 个字母用密钥的第 i 个字母加密，密钥用完了就从头循环。
    例如密钥 `key`：明文第 1、4、7……个字母右移 10（k），第 2、5、8……个右移 4（e）。

    **无密钥破解**分两步：

    1. **求密钥长度 L**：把密文每隔 L 个字母取一个分成 L 列。L 正确时，每一列都是普通凯撒密码，
       字母分布像英文，**重合指数**（随机取两个字母相同的概率）约为 0.066；L 错误时接近随机的 0.038。
       Kasiski 测试也可以辅助：重复出现的片段之间的距离常是 L 的倍数；
    2. **逐列破解**：每一列按凯撒密码做频率分析，找出使字母频率最像英文的位移，拼起来就是密钥。

    密文越长越准，一般需要密钥长度的 20 倍以上。破解出的密钥个别字母可能不对，按结果手动修正即可。
    **博福特密码**是它的变形：`y = k − x`，加密和解密相同。
    """,
    inputs=[text_input(placeholder="密文")],
    options=[field("mode", "segmented", "模式", default="解密", choices=["加密", "解密", "无密钥破解"]),
             field("key", "string", "密钥", default="key", visible_when={"mode": ["加密", "解密"]}),
             field("variant", "segmented", "类型", default="维吉尼亚", choices=["维吉尼亚", "博福特"],
                   visible_when={"mode": ["加密", "解密"]})],
    examples=[{"text": "ppyq{zgqilovc}", "mode": "解密", "key": "key"},
              {"text": "Kk upl hjv ztlh qw rxfsu, zr ltg vyc lhfuk mu mwovq, xm kcj rwx oiv mu pwuumb, bh yrq ias cxc dy tqfjxlvpvqh, bh yrq ias ggmra ch scabsh, zr ltg vyc ticey mu bbeicsnzkkw, xm kcj rwx ggrqdg ch cgvah, kk upl hjv qttgqe mu wotbltlg. Vyc ueoi zq uksslccvm ceyargkj udkyu.", "mode": "无密钥破解"}],
    keywords=["vigenere", "维吉尼亚", "多表", "beaufort", "博福特"],
    live=True,
)
def vigenere_tool(text, mode="解密", key="key", variant="维吉尼亚"):
    if mode == "加密":
        return vigenere(text, key, False, variant)
    if mode == "解密":
        return vigenere(text, key, True, variant)
    rows = crack(text)
    return table(["密钥长度", "重合指数", "Kasiski 计数", "推测密钥", "得分", "解密结果（前 200 字）"], rows[:10])
