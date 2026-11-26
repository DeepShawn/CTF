"""RSA（教材 3.3.0～3.3.4）：计算、常见攻击自动尝试、PEM / SSH 公私钥解析。"""

import base64
import math
import re

from ..registry import ToolError, field, text_input, tool
from ..util import fields, i2b, parse_int, show
from .nt import convergents, continued_fraction, crt, factor, fermat, invert, iroot, is_prime, phi_from_factors, short

# ---------------------------------------------------------------- 参数解析

PARAM_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*[:=]\s*(.+?)\s*[,;]?\s*$")


def parse_params(text):
    """解析题目中常见的写法：每行“名称 = 值”，值可以是十进制或 0x 十六进制。重复的名称自动编号（n, n → n1, n2）。"""
    params, counts = {}, {}
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        m = PARAM_RE.match(line)
        if not m:
            continue
        name, val = m.group(1).lower(), m.group(2).strip().strip("Ll")
        val = re.sub(r"^mpz\((.*)\)$", r"\1", val)
        try:
            v = parse_int(val, name)
        except ToolError:
            continue
        if name in params or name in counts:
            counts.setdefault(name, 1)
            if name in params:
                params[name + "1"] = params.pop(name)
            counts[name] += 1
            name = "%s%d" % (name, counts[name])
        params[name] = v
    return params


def group(params, key):
    """取出 n / n1 / n2 … 这一组值，按编号排列。"""
    if key in params:
        return [params[key]]
    vals = sorted((int(k[len(key):]), v) for k, v in params.items()
                  if k.startswith(key) and k[len(key):].isdigit())
    return [v for _, v in vals]


# ---------------------------------------------------------------- 攻击

def decrypt_with_factors(c, e, fs):
    phi = phi_from_factors(fs)
    g = math.gcd(e, phi)
    if g == 1:
        d = invert(e, phi)
        return pow(c, d, math.prod(fs)), d, None
    # e 与 φ(n) 不互素：先解出 m^g，再开 g 次方（m^g 小于 n 时成立）
    d = invert(e // g, phi)
    mg = pow(c, d, math.prod(fs))
    r, exact = iroot(mg, g)
    note = "e 与 φ(n) 的公因数为 %d：先求 m^%d，再开 %d 次方%s" % (g, g, g, "" if exact else "（未能开尽，结果可能不对）")
    return r, d, note


def wiener(e, n):
    """Wiener 攻击：d < n^0.25 / 3 时，k/d 是 e/n 的某个渐近分数。"""
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1                     # p + q
        disc = s * s - 4 * n
        if disc >= 0:
            r, exact = iroot(disc, 2)
            if exact and (s + r) % 2 == 0:
                return d, (s + r) // 2, (s - r) // 2
    return None


def attack(params, budget=6_000_000):
    """按顺序尝试各种方法，返回 (明文整数, 步骤说明列表)。"""
    steps = []
    ns, es, cs = group(params, "n"), group(params, "e"), group(params, "c")
    n = ns[0] if ns else None
    e = es[0] if es else 65537
    if not es:
        steps.append("没有给出 e，按最常见的 65537 计算")
    c = cs[0] if cs else None
    p, q, d = params.get("p"), params.get("q"), params.get("d")
    if c is None:
        raise ToolError("没有找到密文 c。参数按“c = 数字”的格式每行写一个")

    # 1. 直接给了私钥或因子
    if d and n:
        steps.append("已知私钥 d，直接计算 m = c^d mod n")
        return pow(c, d, n), steps
    if p and q:
        steps.append("已知 p、q：φ(n) = (p−1)(q−1)，d = e⁻¹ mod φ(n)")
        m, d, note = decrypt_with_factors(c, e, [p, q] if p != q else [p, p])
        if note:
            steps.append(note)
        return m, steps
    if p and n and n % p == 0:
        steps.append("已知 p，q = n / p")
        m, _, note = decrypt_with_factors(c, e, [p, n // p])
        if note:
            steps.append(note)
        return m, steps
    if "phi" in params and n:
        steps.append("已知 φ(n)，直接求 d")
        return pow(c, invert(e, params["phi"]), n), steps
    if n is None:
        raise ToolError("没有找到模数 n")

    # 2. dp 泄露
    if "dp" in params:
        dp = params["dp"]
        for k in range(1, e + 1):
            if (e * dp - 1) % k == 0:
                pp = (e * dp - 1) // k + 1
                if n % pp == 0:
                    steps.append("dp 泄露：e·dp ≡ 1 (mod p−1)，枚举 k 得到 p = (e·dp − 1)/k + 1（k = %d）" % k)
                    return decrypt_with_factors(c, e, [pp, n // pp])[0], steps
        steps.append("给出了 dp，但没能由它求出 p")

    # 3. 共模攻击：同一 n，两个互素的 e
    if len(set(ns)) == 1 and len(es) >= 2 and len(cs) >= 2 and es[0] != es[1]:
        g, a, b = _egcd(es[0], es[1])
        if g == 1:
            steps.append("共模攻击：同一个 n、两个互素的 e。由 a·e1 + b·e2 = 1 得 m = c1^a · c2^b mod n（a = %d, b = %d）" % (a, b))
            m = pow(cs[0], a, n) * pow(cs[1], b, n) % n      # 指数为负时 pow 会自动求模逆（Python 3.8+）
            return m, steps

    # 4. 广播攻击：相同的小 e、多组 n 与 c
    if len(ns) >= 2 and len(cs) == len(ns) and len(set(es)) <= 1 and len(ns) >= e:
        x, _ = crt(cs, ns)
        r, exact = iroot(x, e)
        if exact:
            steps.append("广播攻击：%d 组 (n, c) 用中国剩余定理合并得到 m^%d，再开 %d 次方" % (len(ns), e, e))
            return r, steps
        steps.append("尝试了广播攻击，但合并后不能恰好开方")

    # 5. 多个 n 有公因数
    if len(ns) >= 2:
        for i in range(len(ns)):
            for j in range(i + 1, len(ns)):
                g = math.gcd(ns[i], ns[j])
                if 1 < g < ns[i]:
                    steps.append("n%d 与 n%d 有公因数 p = gcd(n%d, n%d)" % (i + 1, j + 1, i + 1, j + 1))
                    ci = cs[i] if i < len(cs) else c
                    ei = es[i] if i < len(es) else e
                    return decrypt_with_factors(ci, ei, [g, ns[i] // g])[0], steps

    # 6. 小 e：m^e 没有超过 n（或只超过很少）
    if e <= 65537 and e < 100:
        for k in range(0, 20000):
            r, exact = iroot(c + k * n, e)
            if exact:
                steps.append("小 e 攻击：c + %d·n 恰好是 %d 次方数，直接开方" % (k, e) if k else
                             "小 e 攻击：m^%d < n，c 就是 m^%d，直接开 %d 次方" % (e, e, e))
                return r, steps
        steps.append("e = %d 较小，但 c + k·n（k < 20000）都不是 %d 次方数" % (e, e))

    # 7. e 很大：Wiener
    if e.bit_length() > n.bit_length() // 2:
        w = wiener(e, n)
        if w:
            d, pp, qq = w
            steps.append("Wiener 攻击：e 很大说明 d 可能很小，用 e/n 的连分数找到 d = %s" % short(d))
            return pow(c, d, n), steps
        steps.append("e 很大，尝试了 Wiener 攻击但没有成功")

    # 8. 分解 n
    if is_prime(n):
        steps.append("n 本身是素数：φ(n) = n − 1")
        return decrypt_with_factors(c, e, [n])[0], steps
    fp = fermat(n, 100_000)
    if fp and fp not in (1, n):
        steps.append("费马分解成功：p、q 非常接近（|p − q| 很小）")
        m, _, note = decrypt_with_factors(c, e, [fp, n // fp])
        if note:
            steps.append(note)
        return m, steps
    fs, complete = factor(n, budget)
    if complete and len(fs) >= 2:
        steps.append("分解 n 成功：n = %s" % " × ".join(short(x, 30) for x in fs))
        m, _, note = decrypt_with_factors(c, e, fs)
        if note:
            steps.append(note)
        return m, steps
    steps.append("没能分解 n（%d 位）。可以到 factordb.com 查询，或在 Docker 环境中使用 yafu、cado-nfs" % n.bit_length())
    return None, steps


def _egcd(a, b):
    from .nt import egcd
    return egcd(a, b)


@tool(
    "modern.rsa", "RSA 解密与常见攻击", "modern", "3.3",
    summary="粘贴题目给出的 n、e、c 等参数，自动尝试 10 种常见攻击",
    principle="""
    RSA 的计算过程：选两个质数 p、q，`n = p·q`，`φ(n) = (p−1)(q−1)`，`d = e⁻¹ mod φ(n)`；
    加密 `c = mᵉ mod n`，解密 `m = cᵈ mod n`。CTF 中的 RSA 题几乎都是让某一步出现弱点：

    | 弱点 | 条件 | 方法 |
    |---|---|---|
    | 已知 p、q、d 或 φ(n) | 题目直接给出 | 直接计算 |
    | dp 泄露 | 给出 `dp = d mod (p−1)` | 枚举 k，由 `e·dp − 1 = k(p−1)` 求 p |
    | 共模攻击 | 同一 n、两个互素的 e 加密同一明文 | 扩展欧几里得组合两个密文 |
    | 广播攻击 | 同一明文用相同的小 e 发给 e 个人 | 中国剩余定理合并后开 e 次方 |
    | 公因数 | 多个 n 共用一个质数 | 两两求最大公因数 |
    | 小 e | e = 3 等且明文较短 | `c + k·n` 开 e 次方 |
    | Wiener | d 很小（e 往往很大） | e/n 的连分数 |
    | p、q 接近 | `|p − q|` 很小 | 费马分解 |
    | n 太小或有小因子 | — | Pollard rho、p−1 |
    | e 与 φ(n) 不互素 | `gcd(e, φ) > 1` | 先求 `m^g` 再开方 |

    **输入格式**：直接粘贴题目输出，每行“名称 = 数字”，如 `n = 0x...`、`e = 65537`、`c = ...`。
    有多组时写 `n1 = …`、`n2 = …`，或者重复写 `n = …`（自动编号）。
    结果中的“转成字节”就是 `long_to_bytes(m)`，通常就是 flag。
    """,
    inputs=[text_input("参数", placeholder="n = ...\ne = 65537\nc = ...")],
    options=[],
    examples=[
        {"text": "p = 61\nq = 53\ne = 17\nc = 2790"},
        {"text": "n = 0x%x\ne = 3\nc = %d" % ((1 << 1024) + 643, pow(int.from_bytes(b"flag{small_e}", "big"), 3, (1 << 1024) + 643))},
    ],
    keywords=["rsa", "共模", "广播", "wiener", "费马", "小 e", "dp", "long_to_bytes"],
    live=False,
)
def rsa_tool(text):
    params = parse_params(text)
    if not params:
        raise ToolError("没有识别到参数。请按“名称 = 数字”每行写一个，如 n = 123")
    m, steps = attack(params)
    recognized = "，".join("%s" % k for k in params)
    items = [["识别到的参数", recognized]] + [["步骤 %d" % (i + 1), s] for i, s in enumerate(steps)]
    if m is None:
        items.append(["结果", "没有找到可用的攻击方法"])
        return fields(items)
    items += [["明文 m（十进制）", str(m)], ["十六进制", hex(m)], ["转成字节", show(i2b(m))]]
    return fields(items)


# ---------------------------------------------------------------- 密钥解析

def der_read(data, i=0):
    """读一个 DER 元素：返回 (标签, 内容, 下一个元素的位置)。"""
    tag = data[i]
    length = data[i + 1]
    i += 2
    if length & 0x80:
        nb = length & 0x7F
        length = int.from_bytes(data[i:i + nb], "big")
        i += nb
    return tag, data[i:i + length], i + length


def der_seq(data):
    out, i = [], 0
    while i < len(data):
        tag, val, i = der_read(data, i)
        out.append((tag, val))
    return out


def parse_key(text):
    s = text.strip()
    if s.startswith("ssh-rsa "):
        blob = base64.b64decode(s.split()[1])
        parts, i = [], 0
        while i < len(blob):
            ln = int.from_bytes(blob[i:i + 4], "big")
            parts.append(blob[i + 4:i + 4 + ln])
            i += 4 + ln
        return "OpenSSH 公钥", {"e": int.from_bytes(parts[1], "big"), "n": int.from_bytes(parts[2], "big")}
    m = re.search(r"-----BEGIN ([A-Z ]+)-----(.*?)-----END \1-----", s, re.S)
    if not m:
        raise ToolError("没有找到 -----BEGIN ... KEY----- 格式的密钥，也不是 ssh-rsa 公钥")
    kind = m.group(1)
    try:
        der = base64.b64decode(re.sub(r"\s|[A-Za-z-]+:.*\n", "", m.group(2)))
    except Exception:
        raise ToolError("密钥内容不是有效的 Base64")
    if "ENCRYPTED" in kind or "Proc-Type" in m.group(2):
        raise ToolError("这是加密的私钥，需要先用密码解密：openssl rsa -in key.pem -out plain.pem")
    _, body, _ = der_read(der)
    items = der_seq(body)
    ints = lambda seq: [int.from_bytes(v, "big") for t, v in seq if t == 0x02]   # noqa: E731
    if kind == "RSA PUBLIC KEY":
        n, e = ints(items)[:2]
        return "PKCS#1 公钥", {"n": n, "e": e}
    if kind == "PUBLIC KEY":
        bitstr = [v for t, v in items if t == 0x03][0][1:]       # 去掉“未使用位数”字节
        _, inner, _ = der_read(bitstr)
        n, e = ints(der_seq(inner))[:2]
        return "X.509 SubjectPublicKeyInfo 公钥", {"n": n, "e": e}
    if kind == "RSA PRIVATE KEY":
        v = ints(items)
        return "PKCS#1 私钥", dict(zip(["version", "n", "e", "d", "p", "q", "dp", "dq", "qinv"], v))
    if kind == "PRIVATE KEY":
        octet = [v for t, v in items if t == 0x04][0]
        _, inner, _ = der_read(octet)
        v = ints(der_seq(inner))
        return "PKCS#8 私钥", dict(zip(["version", "n", "e", "d", "p", "q", "dp", "dq", "qinv"], v))
    raise ToolError("暂不支持 %s" % kind)


@tool(
    "modern.rsa_key", "RSA 密钥解析", "modern", "3.3.0",
    summary="读出 PEM / OpenSSH 公钥与私钥中的 n、e、d、p、q",
    principle="""
    题目常以文件形式给出公钥（`pubkey.pem`），里面的 n、e 用 ASN.1 DER 编码后再 Base64：

    - `-----BEGIN PUBLIC KEY-----`：X.509 格式，最常见；
    - `-----BEGIN RSA PUBLIC KEY-----`：PKCS#1 格式；
    - `-----BEGIN RSA PRIVATE KEY-----` / `-----BEGIN PRIVATE KEY-----`：私钥，包含 n、e、d、p、q 等全部参数；
    - `ssh-rsa AAAA…`：OpenSSH 公钥。

    读出 n、e 后，可以把结果复制到“RSA 解密与常见攻击”中继续处理。
    同样的事情可以用命令 `openssl rsa -pubin -in pubkey.pem -text -noout` 完成。
    """,
    inputs=[text_input("PEM 或 ssh-rsa 密钥", placeholder="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----")],
    examples=[{"text": "-----BEGIN RSA PUBLIC KEY-----\nMAwCBQDVyTbVAgMBAAE=\n-----END RSA PUBLIC KEY-----"}],
    keywords=["pem", "公钥", "私钥", "openssl", "der", "asn1"],
)
def rsa_key_tool(text):
    kind, vals = parse_key(text)
    rows = [["格式", kind]]
    for k in ("n", "e", "d", "p", "q", "dp", "dq", "qinv"):
        if k in vals:
            rows.append([k, str(vals[k])])
    if "n" in vals:
        rows.append(["n 的位数", vals["n"].bit_length()])
        rows.append(["可复制到 RSA 工具", "n = %d\ne = %d" % (vals["n"], vals.get("e", 65537))])
    return fields(rows)
