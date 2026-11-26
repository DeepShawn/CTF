"""椭圆曲线与离散对数（教材 3.3.5～3.3.7）：点运算、点的阶、BSGS、Pohlig–Hellman。"""

import math
from collections import Counter

from ..registry import ToolError, field, tool
from ..util import fields, parse_int, show, i2b
from .nt import crt, factor, invert, is_prime

# ---------------------------------------------------------------- 曲线运算（无穷远点记为 None）


class Curve:
    def __init__(self, a, b, p):
        if (4 * a ** 3 + 27 * b ** 2) % p == 0:
            raise ToolError("4a³ + 27b² ≡ 0 (mod p)，这不是一条光滑的椭圆曲线")
        self.a, self.b, self.p = a % p, b % p, p

    def on_curve(self, P):
        if P is None:
            return True
        x, y = P
        return (y * y - x ** 3 - self.a * x - self.b) % self.p == 0

    def neg(self, P):
        return None if P is None else (P[0], -P[1] % self.p)

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        p = self.p
        if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
            return None
        if P == Q:
            lam = (3 * P[0] * P[0] + self.a) * invert(2 * P[1], p) % p      # 切线斜率
        else:
            lam = (Q[1] - P[1]) * invert(Q[0] - P[0], p) % p                # 割线斜率
        x = (lam * lam - P[0] - Q[0]) % p
        return x, (lam * (P[0] - x) - P[1]) % p

    def mul(self, k, P):
        if k < 0:
            return self.mul(-k, self.neg(P))
        R = None
        while k:                                                            # 倍加法（double-and-add）
            if k & 1:
                R = self.add(R, P)
            P = self.add(P, P)
            k >>= 1
        return R


def bsgs(step, op, identity, g, h, n, inv_g):
    """大步小步法：在阶为 n 的循环群中求 x，使 g^x = h（op 为群运算，step(a, k) 为 a 的 k 次幂）。"""
    m = math.isqrt(n) + 1
    if m > 4_000_000:
        raise ToolError("群的阶太大（约 2^%d），大步小步法需要的内存太多" % n.bit_length())
    table, cur = {}, identity
    for j in range(m):
        table.setdefault(cur, j)
        cur = op(cur, g)
    factor_ = step(inv_g, m)                                                 # g^(-m)
    gamma = h
    for i in range(m):
        if gamma in table:
            return (i * m + table[gamma]) % n
        gamma = op(gamma, factor_)
    return None


def pohlig_hellman(order, step, op, identity, g, h, inv):
    """Pohlig–Hellman：阶 n 分解成小素数幂时，分别在每个小子群中求离散对数，再用中国剩余定理合并。"""
    fs, complete = factor(order)
    if not complete:
        raise ToolError("群的阶没能完全分解，无法使用 Pohlig–Hellman")
    rems, mods = [], []
    for q, e in Counter(fs).items():
        qe = q ** e
        g_i = step(g, order // qe)
        h_i = step(h, order // qe)
        # 逐位求 x mod q^e
        x = 0
        gamma = step(g_i, q ** (e - 1))
        for k in range(e):
            hk = step(op(step(inv(g_i), x), h_i), q ** (e - 1 - k))
            d = bsgs(step, op, identity, gamma, hk, q, inv(gamma))
            if d is None:
                raise ToolError("在阶为 %d 的子群中没有找到解：h 可能不在 g 生成的群中" % q)
            x += d * q ** k
        rems.append(x)
        mods.append(qe)
    return crt(rems, mods)[0], Counter(fs)


def point_order(curve, P, n_hint=None):
    """点的阶：已知群阶（或其倍数）时，从中除去不必要的素因子。"""
    if n_hint is None:
        if curve.p > 10 ** 7:
            raise ToolError("p 太大，无法直接数出点的阶，请在“群的阶”中填写曲线的阶 #E")
        n = 1
        Q = P
        while Q is not None:
            Q = curve.add(Q, P)
            n += 1
        return n
    n = n_hint
    for q in set(factor(n)[0]):
        while n % q == 0 and curve.mul(n // q, P) is None:
            n //= q
    return n


def parse_point(s, name):
    nums = [x for x in s.replace("(", " ").replace(")", " ").replace(",", " ").split() if x]
    if not nums:
        return None
    if len(nums) != 2:
        raise ToolError("%s 应写成 x, y 两个数" % name)
    return parse_int(nums[0], name + " 的 x"), parse_int(nums[1], name + " 的 y")


ECC_OPS = ["P + Q", "k · P", "检查点是否在曲线上", "点 P 的阶", "离散对数：求 k 使 k·P = Q"]


@tool(
    "modern.ecc", "椭圆曲线计算器", "modern", "3.3.5～3.3.7",
    summary="点加、倍点、点的阶，以及小阶情况下的椭圆曲线离散对数（BSGS + Pohlig–Hellman）",
    principle="""
    椭圆曲线 `y² = x³ + a·x + b (mod p)` 上的点可以“相加”：过 P、Q 作直线交曲线于第三点，再关于 x 轴对称。
    `k·P` 就是 P 自加 k 次，用“倍加法”只需 log k 步。

    ECC 的安全性基于**椭圆曲线离散对数问题**：已知 P 和 Q = k·P，求 k 很难。但在下面的情况下可以求解：

    | 情况 | 方法 |
    |---|---|
    | 点的阶很小（≲ 10¹²） | 大步小步法（BSGS），约 √n 步 |
    | 点的阶是许多小素数的乘积（光滑） | **Pohlig–Hellman**：在每个小素数阶子群中分别求解，再用中国剩余定理合并 |
    | 曲线的阶等于 p（异常曲线） | Smart 攻击（需要 p 进数运算，请在 Docker 中用 SageMath） |

    求离散对数时，如果知道曲线的阶 #E，请填在“群的阶”中；p 较小时会自动计算。
    """,
    inputs=[field("text", "string", "点 P（x, y）", default="", placeholder="3, 6")],
    options=[field("op", "select", "运算", default=ECC_OPS[0], choices=ECC_OPS),
             field("Q", "string", "点 Q（x, y）", default="", visible_when={"op": ["P + Q", "离散对数：求 k 使 k·P = Q"]}),
             field("k", "string", "k", default="2", visible_when={"op": "k · P"}),
             field("a", "string", "a", default="2"),
             field("b", "string", "b", default="3"),
             field("p", "string", "p", default="97"),
             field("order", "string", "群的阶（可选）", default="", visible_when={"op": ["点 P 的阶", "离散对数：求 k 使 k·P = Q"]})],
    examples=[{"text": "3, 6", "op": "k · P", "k": "2", "a": "2", "b": "3", "p": "97"},
              {"text": "2, 23365", "op": "离散对数：求 k 使 k·P = Q", "Q": "3085, 62791", "a": "2", "b": "3", "p": "65537"}],
    keywords=["ecc", "椭圆曲线", "ecdlp", "pohlig", "bsgs", "离散对数"],
    live=False,
)
def ecc_tool(text, op=ECC_OPS[0], Q="", k="2", a="2", b="3", p="97", order=""):
    pp = parse_int(p, "p")
    if not is_prime(pp):
        raise ToolError("p 应为素数")
    E = Curve(parse_int(a, "a"), parse_int(b, "b"), pp)
    P = parse_point(text, "P")
    if P is None:
        raise ToolError("请输入点 P")
    fmt = lambda R: "无穷远点 O" if R is None else "(%d, %d)" % R   # noqa: E731
    if not E.on_curve(P):
        raise ToolError("P%s 不在曲线 y² = x³ + %dx + %d (mod %d) 上" % (fmt(P), E.a, E.b, pp))
    if op == "检查点是否在曲线上":
        return fields([["结果", "P 在曲线上"]])
    if op == "P + Q":
        QQ = parse_point(Q, "Q")
        if not E.on_curve(QQ):
            raise ToolError("Q 不在曲线上")
        return fields([["P + Q", fmt(E.add(P, QQ))]])
    if op == "k · P":
        return fields([["k · P", fmt(E.mul(parse_int(k, "k"), P))]])
    n_hint = parse_int(order, "群的阶") if order.strip() else None
    n = point_order(E, P, n_hint)
    if op == "点 P 的阶":
        fs, _ = factor(n)
        return fields([["P 的阶", n], ["阶的分解", " × ".join(map(str, fs))]])
    QQ = parse_point(Q, "Q")
    if not E.on_curve(QQ):
        raise ToolError("Q 不在曲线上")
    step = lambda X, m: E.mul(m, X)   # noqa: E731
    x, fs = pohlig_hellman(n, step, E.add, None, P, QQ, E.neg)
    if E.mul(x, P) != QQ:
        raise ToolError("求出的 k 不满足 k·P = Q：Q 可能不在 P 生成的子群中")
    return fields([["k", x], ["P 的阶", n], ["阶的分解", " × ".join("%d^%d" % (q, e) if e > 1 else str(q) for q, e in sorted(fs.items()))],
                   ["k 转成字节", show(i2b(x))]])


@tool(
    "modern.dlog", "离散对数（模 p）", "modern", "3.3.7",
    summary="求 x 使 g^x ≡ h (mod p)：p−1 光滑时用 Pohlig–Hellman 很快",
    principle="""
    已知 g、h、p，求 x 使 `g^x ≡ h (mod p)`，这是 Diffie–Hellman、ElGamal 的安全基础。
    一般情况下很难，但当 **p − 1 只有小素因子**（光滑）时，Pohlig–Hellman 方法把问题拆到每个小子群中，
    每个子群用大步小步法求解，最后用中国剩余定理合并，几乎瞬间完成。

    CTF 中常见的考法就是故意选一个 p − 1 光滑的素数。可以先在“数论工具箱”里分解 p − 1 看看。
    """,
    inputs=[field("text", "string", "h", default="", placeholder="g^x mod p 的值")],
    options=[field("g", "string", "底数 g", default="2"), field("p", "string", "模数 p", default="")],
    examples=[{"text": "4744228931762206312", "g": "3", "p": "9288760545485721301"}],
    keywords=["离散对数", "dlog", "pohlig", "bsgs", "diffie-hellman"],
    live=False,
)
def dlog_tool(text, g="2", p=""):
    pp, gg, hh = parse_int(p, "p"), parse_int(g, "g"), parse_int(text, "h")
    if not is_prime(pp):
        raise ToolError("p 应为素数")
    n = pp - 1
    for q in set(factor(n)[0]):                       # 先求 g 的阶，只在 g 生成的子群中求解
        while n % q == 0 and pow(gg, n // q, pp) == 1:
            n //= q
    step = lambda a, m: pow(a, m, pp)   # noqa: E731
    op = lambda a, b: a * b % pp         # noqa: E731
    x, fs = pohlig_hellman(n, step, op, 1, gg, hh, lambda a: invert(a, pp))
    if pow(gg, x, pp) != hh % pp:
        raise ToolError("没有解：h 不在 g 生成的子群中")
    return fields([["x", x], ["g 的阶（p − 1 的因数）的分解", " × ".join("%d^%d" % (q, e) if e > 1 else str(q) for q, e in sorted(fs.items()))],
                   ["x 转成字节", show(i2b(x))]])
