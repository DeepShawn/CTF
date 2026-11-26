"""数论工具箱（教材 3.3 的基础）：扩展欧几里得、模逆、中国剩余定理、整数开方、素性检测、分解、连分数。

这些函数只用 Python 内置的大整数，不依赖 gmpy2，所以在浏览器和手机上也能运行。
RSA 类题目几乎都由这几个函数组合而成。
"""

import math
import random

from ..registry import ToolError, field, text_input, tool
from ..util import fields, i2b, parse_int, show


def egcd(a, b):
    """扩展欧几里得：返回 (g, x, y)，满足 a*x + b*y = g = gcd(a, b)。用循环实现，大数也不会递归过深。"""
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def invert(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ToolError("%s 与 %s 不互素（最大公因数为 %s），没有模逆" % (short(a), short(m), short(g)))
    return x % m


def crt(remainders, moduli):
    """中国剩余定理：求 x ≡ r_i (mod m_i)。模数不必两两互素，但需要相容。返回 (x, M)。"""
    x, m = 0, 1
    for r, mi in zip(remainders, moduli):
        g, p, _ = egcd(m, mi)
        if (r - x) % g:
            raise ToolError("同余方程组无解：模数 %s 与 %s 不互素且余数不相容" % (short(m), short(mi)))
        lcm = m // g * mi
        x = (x + (r - x) // g * p % (mi // g) * m) % lcm
        m = lcm
    return x, m


def iroot(x, k):
    """整数 k 次方根，返回 (根, 是否恰好开尽)。用牛顿迭代，几千位的大数也很快。"""
    if x < 0:
        raise ToolError("不能对负数开方")
    if x < 2:
        return x, True
    r = 1 << ((x.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * r + x // r ** (k - 1)) // k
        if y >= r:
            break
        r = y
    while r ** k > x:
        r -= 1
    while (r + 1) ** k <= x:
        r += 1
    return r, r ** k == x


SMALL_PRIMES = [p for p in range(2, 1000) if all(p % d for d in range(2, int(p ** 0.5) + 1))]


def is_prime(n, rounds=32):
    """Miller-Rabin 素性检测。对 2^64 以下的数用固定底数，结果是确定的。"""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] if n < 3317044064679887385961981 else \
        [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] + [random.randrange(2, n - 1) for _ in range(rounds)]
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def pollard_rho(n, limit=6_000_000):
    """Pollard rho（Brent 改进）：适合分解出较小的因子。找不到时返回 None。"""
    if n % 2 == 0:
        return 2
    rng = random.Random(n)
    for _ in range(8):
        y, c, m = rng.randrange(1, n), rng.randrange(1, n), 128
        g = r = q = 1
        steps = 0
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
            r *= 2
            steps += r
            if steps > limit:
                return None
        if g == n:
            while True:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
                if g > 1:
                    break
        if g != n:
            return g
    return None


def fermat(n, limit=1_000_000):
    """费马分解：p、q 很接近时，n = a² − b²，从 √n 开始找 a。"""
    a, exact = iroot(n, 2)
    if exact:
        return a
    a += 1
    for _ in range(limit):
        b2 = a * a - n
        b, ok = iroot(b2, 2)
        if ok:
            return a - b
        a += 1
    return None


def pollard_pm1(n, bound=50_000):
    """Pollard p−1：p−1 只有小因子（光滑）时很快。"""
    a = 2
    for p in SMALL_PRIMES + list(range(1001, bound, 2)):
        a = pow(a, p ** max(1, int(math.log(bound, p))), n) if p < 1000 else pow(a, p, n)
        if p % 1000 == 1:
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                return g
    g = math.gcd(a - 1, n)
    return g if 1 < g < n else None


def factor(n, budget=6_000_000):
    """尽力分解：试除 → 费马 → Pollard p−1 → Pollard rho。返回 (质因数列表, 是否完全分解)。"""
    if n < 2:
        return [], True
    out, stack, complete = [], [n], True
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if is_prime(m):
            out.append(m)
            continue
        d = None
        for p in SMALL_PRIMES:
            if m % p == 0:
                d = p
                break
        d = d or fermat(m, 200_000) or pollard_pm1(m) or pollard_rho(m, budget)
        if not d or d in (1, m):
            out.append(m)
            complete = False
            continue
        stack += [d, m // d]
    return sorted(out), complete


def continued_fraction(num, den):
    out = []
    while den:
        q = num // den
        out.append(q)
        num, den = den, num - q * den
    return out


def convergents(cf):
    """连分数的各个渐近分数 (分子, 分母)。"""
    h0, h1, k0, k1 = 0, 1, 1, 0
    for a in cf:
        h0, h1 = h1, a * h1 + h0
        k0, k1 = k1, a * k1 + k0
        yield h1, k1


def phi_from_factors(factors):
    from collections import Counter
    r = 1
    for p, e in Counter(factors).items():
        r *= (p - 1) * p ** (e - 1)
    return r


def short(n, width=60):
    s = str(n)
    return s if len(s) <= width else "%s…%s（%d 位）" % (s[:20], s[-20:], len(s))


def int_info(n):
    """把整数同时显示成十进制、十六进制与字节（字节常常就是 flag）。"""
    b = i2b(n) if n >= 0 else b""
    return [["十进制", str(n)], ["十六进制", hex(n)], ["位数", "%d 位二进制" % n.bit_length()],
            ["转成字节", show(b)]]


OPS = ["最大公因数 / 扩展欧几里得", "模逆", "模幂", "中国剩余定理", "整数开 k 次方", "素性检测", "分解质因数",
       "连分数", "整数 ↔ 字节"]


@tool(
    "modern.numtheory", "数论工具箱", "modern", "3.3",
    summary="gcd、模逆、模幂、中国剩余定理、开方、素性检测、分解、连分数、整数与字节互转",
    principle="""
    RSA 等公钥密码题目几乎都由几个数论运算组合而成：

    | 运算 | 用途 |
    |---|---|
    | 扩展欧几里得 | 求 `a·x + b·y = gcd(a, b)` 的 x、y；共模攻击要用 |
    | 模逆 `a⁻¹ mod m` | 由 e 求私钥 d：`d = e⁻¹ mod φ(n)` |
    | 模幂 `aᵇ mod m` | 加密、解密 |
    | 中国剩余定理 | 已知 x 除以多个数的余数，求 x；广播攻击、加速解密要用 |
    | 整数开方 | 小 e 攻击：直接对密文开 e 次方 |
    | 分解质因数 | 小 n 直接分解；p、q 接近时用费马分解 |
    | 连分数 | Wiener 攻击 |

    **注意**：大数运算必须用整数，不能用浮点数。`c ** (1/3)` 会因为精度丢失得到错误结果，要用整数开方。
    **整数 ↔ 字节**：RSA 解出的明文 m 是一个整数，转成字节（大端序）往往就是 flag，
    相当于 pycryptodome 中的 `long_to_bytes(m)`。

    输入方式：每行一个数，支持十进制与 `0x` 开头的十六进制。
    """,
    inputs=[text_input("数（每行一个）", placeholder="a\nb")],
    options=[field("op", "select", "运算", default=OPS[0], choices=OPS),
             field("k", "number", "k（开方次数）", default=2, min=2, max=1000, visible_when={"op": "整数开 k 次方"})],
    examples=[{"text": "240\n46", "op": OPS[0]}, {"text": "17\n3120", "op": "模逆"},
              {"text": "2\n3\n3\n5\n2\n7", "op": "中国剩余定理"},
              {"text": "8051", "op": "分解质因数"}, {"text": "0x666c61677b6e747d", "op": "整数 ↔ 字节"}],
    keywords=["gcd", "模逆", "crt", "中国剩余定理", "开方", "分解", "factor", "long_to_bytes", "bytes_to_long"],
)
def numtheory_tool(text, op=OPS[0], k=2):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if op == "整数 ↔ 字节":
        if not lines:
            raise ToolError("请输入整数或文本")
        s = text.strip()
        try:
            n = parse_int(s)
            return fields(int_info(n))
        except ToolError:
            n = int.from_bytes(s.encode("utf-8"), "big")
            return fields([["输入的文本", s], ["转成整数（十进制）", str(n)], ["十六进制", hex(n)]])
    nums = [parse_int(l, "第 %d 行" % (i + 1)) for i, l in enumerate(lines)]
    need = {"最大公因数 / 扩展欧几里得": 2, "模逆": 2, "模幂": 3, "整数开 k 次方": 1, "素性检测": 1,
            "分解质因数": 1, "连分数": 2}
    if op in need and len(nums) < need[op]:
        raise ToolError("“%s”需要 %d 个数，每行一个" % (op, need[op]))
    if op == "最大公因数 / 扩展欧几里得":
        a, b = nums[:2]
        g, x, y = egcd(a, b)
        return fields([["gcd(a, b)", g], ["x", x], ["y", y], ["验证", "a·x + b·y = %s" % short(a * x + b * y)],
                       ["lcm(a, b)", a // g * b if g else 0]])
    if op == "模逆":
        a, m = nums[:2]
        return fields([["a⁻¹ mod m", invert(a, m)]])
    if op == "模幂":
        a, b, m = nums[:3]
        return fields([["aᵇ mod m", pow(a, b, m)]] + int_info(pow(a, b, m))[1:])
    if op == "中国剩余定理":
        if len(nums) % 2 or not nums:
            raise ToolError("按“余数、模数”成对输入，每行一个数")
        x, m = crt(nums[0::2], nums[1::2])
        return fields([["x", x], ["模数乘积（最小公倍数）", m]] + int_info(x)[1:])
    if op == "整数开 k 次方":
        r, exact = iroot(nums[0], int(k))
        return fields([["根（向下取整）", r], ["是否恰好开尽", "是" if exact else "否（余 %s）" % short(nums[0] - r ** int(k))]]
                      + int_info(r)[1:])
    if op == "素性检测":
        n = nums[0]
        return fields([["n", short(n)], ["是否为素数", "是" if is_prime(n) else "否"], ["位数", n.bit_length()]])
    if op == "分解质因数":
        fs, complete = factor(nums[0])
        from collections import Counter
        desc = " × ".join("%s^%d" % (p, e) if e > 1 else str(p) for p, e in sorted(Counter(fs).items()))
        items = [["分解结果", desc], ["是否完全分解", "是" if complete else "否：最后一个数没能分解，可以试试 factordb.com 或 Docker 中的 yafu"]]
        if complete:
            items.append(["欧拉函数 φ(n)", phi_from_factors(fs)])
        return fields(items)
    if op == "连分数":
        cf = continued_fraction(nums[0], nums[1])
        conv = list(convergents(cf))[:20]
        return fields([["连分数展开", "[" + ", ".join(map(str, cf[:60])) + (", …]" if len(cf) > 60 else "]")],
                       ["前几个渐近分数", "  ".join("%s/%s" % (short(h, 20), short(k_, 20)) for h, k_ in conv[:10])]])
    raise ToolError("未知运算")
