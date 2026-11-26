"""对称密码工具（教材 3.2）：XOR、RC4、AES / DES / 3DES、填充。"""

from ..registry import ToolError, field, text_input, tool
from ..util import DATA_FORMATS, ENGLISH_FREQ, OUTPUT_FORMATS, english_score, fields, find_flags, from_bytes, printable_ratio, show, table, to_bytes
from .ciphers import AES, DES, TripleDES, mode_decrypt, mode_encrypt, pad, rc4, unpad

# ---------------------------------------------------------------- XOR


def xor_with(data, key):
    if not key:
        raise ToolError("密钥不能为空")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_key_lengths(data, max_len=40):
    """重复密钥异或：按相邻块的平均汉明距离（按位数归一化）估计密钥长度，越小越可能。"""
    scores = []
    for k in range(1, min(max_len, len(data) // 2) + 1):
        blocks = [data[i:i + k] for i in range(0, len(data) - k + 1, k)][:40]
        if len(blocks) < 2:
            continue
        d = sum(hamming(blocks[i], blocks[i + 1]) for i in range(len(blocks) - 1)) / (len(blocks) - 1) / k
        scores.append((d, k))
    return [k for _, k in sorted(scores)]


def text_score(b):
    s = printable_ratio(b) * 50
    try:
        t = b.decode("ascii")
    except UnicodeDecodeError:
        return s
    return s + english_score(t) * 0.5 + (100 if find_flags(t) else 0)


# 英文文本中各字符的大致频率（空格最多），用于给“按列拆开”的片段打分：片段不连贯，不能用单词判断
CHAR_FREQ = {ord(" "): 13.0}
for _c, _f in ENGLISH_FREQ.items():
    CHAR_FREQ[ord(_c)] = _f
    CHAR_FREQ[ord(_c.upper())] = _f * 0.15
for _c in b".,'\"-_{}0123456789":
    CHAR_FREQ.setdefault(_c, 0.5)


def column_score(b):
    s = 0.0
    for x in b:
        if x in CHAR_FREQ:
            s += CHAR_FREQ[x]
        elif not (32 <= x < 127 or x in (9, 10, 13)):
            s -= 20                                   # 不可打印字符重罚
    return s


def best_single_byte(column):
    return max(range(256), key=lambda k: column_score(bytes(b ^ k for b in column)))


XOR_MODES = ["已知密钥", "单字节密钥爆破", "已知明文求密钥", "重复密钥破解"]


@tool(
    "modern.xor", "XOR 异或", "modern", "3.2.2",
    summary="已知密钥异或；单字节爆破；已知明文求密钥；重复密钥破解",
    principle="""
    异或（XOR，⊕）按位比较：相同为 0，不同为 1。它有两个关键性质：

    - `a ⊕ k ⊕ k = a`：同一个密钥异或两次就还原，所以加密和解密是同一个操作；
    - `明文 ⊕ 密文 = 密钥`：只要知道一段明文（比如 flag 开头的 `flag{`），就能求出对应位置的密钥。

    **常见题型**：

    | 题型 | 方法 |
    |---|---|
    | 单字节密钥 | 只有 256 种可能，全部试一遍，选结果最像文本的 |
    | 已知开头 `flag{` | 密文前几个字节与 `flag{` 异或得到密钥开头，往往能看出整个密钥 |
    | 重复密钥（如 `key` 循环使用） | 先估计密钥长度（汉明距离最小的长度），再把密文按长度分列，每列按单字节密钥破解 |
    """,
    inputs=[text_input("数据")],
    options=[field("mode", "select", "模式", default="已知密钥", choices=XOR_MODES),
             field("input_format", "segmented", "数据格式", default="十六进制", choices=DATA_FORMATS),
             field("key", "string", "密钥", default="", visible_when={"mode": "已知密钥"}),
             field("key_format", "segmented", "密钥格式", default="文本", choices=DATA_FORMATS, visible_when={"mode": "已知密钥"}),
             field("known", "string", "已知明文", default="flag{", visible_when={"mode": "已知明文求密钥"}),
             field("output_format", "segmented", "输出格式", default="文本", choices=OUTPUT_FORMATS, visible_when={"mode": "已知密钥"})],
    examples=[{"text": "0d09180c1e0104172602162619000f0e170a0207150e18", "mode": "已知密钥", "key": "key"},
              {"text": "2c262b2d313923242d262f1528333e2f1532253837", "mode": "单字节密钥爆破"},
              {"text": "0d09180c1e0104172602162619000f0e170a0207150e18", "mode": "已知明文求密钥", "known": "flag{"}],
    keywords=["xor", "异或", "单字节", "重复密钥"],
)
def xor_tool(text, mode="已知密钥", input_format="十六进制", key="", key_format="文本", known="flag{", output_format="文本"):
    data = to_bytes(text, input_format)
    if not data:
        raise ToolError("请输入数据")
    if mode == "已知密钥":
        return from_bytes(xor_with(data, to_bytes(key, key_format)), output_format)
    if mode == "单字节密钥爆破":
        rows = []
        for k in range(256):
            p = bytes(b ^ k for b in data)
            rows.append([k, "0x%02x" % k, round(text_score(p), 1), show(p)[:200]])
        rows.sort(key=lambda r: -r[2])
        return table(["密钥", "十六进制", "得分", "结果"], rows[:20])
    if mode == "已知明文求密钥":
        kp = known.encode("utf-8")
        if not kp:
            raise ToolError("请填写已知明文")
        rows = []
        for off in range(0, max(1, len(data) - len(kp) + 1)):
            k = xor_with(data[off:off + len(kp)], kp)
            rows.append([off, k.hex(), show(k)])
            if off >= 63:
                break
        return [fields([["说明", "已知明文在开头时看第 0 行；密钥若是可读文本或有规律，就是答案"]]),
                table(["已知明文所在偏移", "密钥（十六进制）", "密钥（文本）"], rows)]
    rows, seen = [], set()
    for k in guess_key_lengths(data)[:8]:
        key_ = bytes(best_single_byte(data[i::k]) for i in range(k))
        for period in range(1, k + 1):                     # 密钥本身有周期时（如 secretsecret）缩短为 secret
            if k % period == 0 and key_ == key_[:period] * (k // period):
                key_ = key_[:period]
                break
        if key_ in seen:
            continue
        seen.add(key_)
        p = xor_with(data, key_)
        rows.append([len(key_), show(key_), round(text_score(p), 1), show(p)[:200]])
    if not rows:
        raise ToolError("数据太短，至少需要几十个字节才能估计密钥长度")
    best = max(r[2] for r in rows)
    rows.sort(key=lambda r: (r[2] < best * 0.95, r[0], -r[2]))      # 分数接近时，密钥短的更可能正确
    return table(["密钥长度", "推测密钥", "得分", "结果"], rows)


# ---------------------------------------------------------------- RC4

@tool(
    "modern.rc4", "RC4", "modern", "3.2.3",
    summary="流密码 RC4 加密 / 解密（同一个操作）",
    principle="""
    RC4 是流密码：用密钥生成一串伪随机的“密钥流”，再与数据逐字节异或，所以加密和解密是同一个操作。

    1. **KSA（密钥调度）**：S 盒初始化为 0～255，用密钥把它打乱；
    2. **PRGA（伪随机生成）**：每输出一个字节就交换 S 盒中的两项，取出一个字节作为密钥流。

    逆向题中看到长度为 256 的数组初始化、再用 `i`、`j` 两个下标交换的循环，多半是 RC4。
    RC4 的前几个字节有统计偏差，有的实现会丢弃前 N 个字节（RC4-drop），可在“丢弃字节数”中设置。
    """,
    inputs=[text_input("数据")],
    options=[field("input_format", "segmented", "数据格式", default="十六进制", choices=DATA_FORMATS),
             field("key", "string", "密钥", default="key"),
             field("key_format", "segmented", "密钥格式", default="文本", choices=DATA_FORMATS),
             field("drop", "number", "丢弃字节数", default=0, min=0, max=4096),
             field("output_format", "segmented", "输出格式", default="文本", choices=OUTPUT_FORMATS)],
    examples=[{"text": "bbf316e8d940af0ad3", "key": "Key"}],
    keywords=["rc4", "arc4", "流密码"],
)
def rc4_tool(text, input_format="十六进制", key="key", key_format="文本", drop=0, output_format="文本"):
    k = to_bytes(key, key_format)
    if not k:
        raise ToolError("密钥不能为空")
    return from_bytes(rc4(k, to_bytes(text, input_format), int(drop)), output_format)


# ---------------------------------------------------------------- 分组密码

ALGOS = {"AES": AES, "DES": DES, "3DES": TripleDES}
MODES = ["ECB", "CBC", "CFB", "OFB", "CTR"]
PADS = ["PKCS#7", "零填充", "ANSI X9.23", "ISO/IEC 7816-4", "不填充"]


@tool(
    "modern.block", "AES / DES / 3DES", "modern", "3.2.5～3.2.8",
    summary="分组密码加密 / 解密：ECB、CBC、CFB、OFB、CTR 模式与多种填充",
    principle="""
    分组密码每次加密固定长度的一块（AES 16 字节、DES 8 字节）。数据更长时按“模式”把多块串起来：

    | 模式 | 做法 | 特点 |
    |---|---|---|
    | ECB | 每块单独加密 | 相同明文块得到相同密文块，会泄露图案；可以逐块重排、替换 |
    | CBC | 加密前先与上一块密文异或，第一块与 IV 异或 | 改动上一块密文的某一位，会翻转下一块明文的同一位（**字节翻转攻击**） |
    | CFB / OFB / CTR | 把分组密码当作密钥流发生器 | 变成流密码，不需要填充；同一 IV 重复使用会泄露明文异或 |

    **填充**：ECB、CBC 要求数据长度是块长的倍数，不足时补齐。最常见的 PKCS#7 补 n 个值为 n 的字节；
    解密后填充不正确，通常说明密钥、IV 或模式不对（Padding Oracle 攻击就利用了这一点）。

    **密钥长度**：AES 为 16 / 24 / 32 字节，DES 为 8 字节，3DES 为 16 或 24 字节。
    题目给出的密钥是文本还是十六进制要看清楚。本工具是纯 Python 实现，结果与 pycryptodome 一致，适合处理题目中的小数据。
    """,
    inputs=[text_input("数据")],
    options=[field("action", "segmented", "操作", default="解密", choices=["加密", "解密"]),
             field("algorithm", "segmented", "算法", default="AES", choices=list(ALGOS)),
             field("mode", "segmented", "模式", default="CBC", choices=MODES),
             field("key", "string", "密钥", default=""),
             field("key_format", "segmented", "密钥格式", default="文本", choices=DATA_FORMATS),
             field("iv", "string", "IV / 计数器初值", default="", visible_when={"mode": ["CBC", "CFB", "OFB", "CTR"]},
                   help="留空则为全 0"),
             field("iv_format", "segmented", "IV 格式", default="十六进制", choices=DATA_FORMATS,
                   visible_when={"mode": ["CBC", "CFB", "OFB", "CTR"]}),
             field("padding", "select", "填充", default="PKCS#7", choices=PADS, visible_when={"mode": ["ECB", "CBC"]}),
             field("input_format", "segmented", "数据格式", default="Base64", choices=DATA_FORMATS),
             field("output_format", "segmented", "输出格式", default="文本", choices=OUTPUT_FORMATS)],
    examples=[{"text": "flag{aes_cbc_mode}", "action": "加密", "key": "0123456789abcdef", "iv": "00000000000000000000000000000000",
               "input_format": "文本", "output_format": "Base64"},
              {"text": "stR50eWvkh6pYtF8GtKnzqJbqB+TIDHkcsFU/ZiQ84Y=", "action": "解密", "key": "0123456789abcdef"}],
    keywords=["aes", "des", "3des", "cbc", "ecb", "ctr", "分组", "对称"],
)
def block_tool(text, action="解密", algorithm="AES", mode="CBC", key="", key_format="文本", iv="", iv_format="十六进制",
               padding="PKCS#7", input_format="Base64", output_format="文本"):
    cls = ALGOS[algorithm]
    k = to_bytes(key, key_format)
    try:
        cipher = cls(k)
    except ValueError as e:
        raise ToolError(str(e))
    bs = cls.block_size
    ivb = to_bytes(iv, iv_format) if iv.strip() else b"\0" * bs
    if mode != "ECB" and len(ivb) != bs:
        raise ToolError("%s 的 IV 必须是 %d 字节，当前为 %d 字节" % (algorithm, bs, len(ivb)))
    data = to_bytes(text, input_format)
    try:
        if action == "加密":
            if mode in ("ECB", "CBC") and padding != "不填充":
                data = pad(data, bs, padding)
            return from_bytes(mode_encrypt(cipher, mode, data, ivb), output_format)
        out = mode_decrypt(cipher, mode, data, ivb)
        if mode in ("ECB", "CBC") and padding != "不填充":
            try:
                out = unpad(out, bs, padding)
            except ValueError as e:
                return [fields([["提示", str(e) + "。下面是未去除填充的结果"]]), from_bytes(out, output_format)]
        return from_bytes(out, output_format)
    except ValueError as e:
        raise ToolError(str(e))


@tool(
    "modern.padding", "填充", "modern", "3.2.7",
    summary="PKCS#7、零填充、ANSI X9.23、ISO/IEC 7816-4 的添加与检查",
    principle="""
    分组密码要求数据长度是块长（AES 16、DES 8）的整数倍，不足时按约定补齐：

    | 方式 | 补什么（缺 n 个字节） | 例子（缺 3 个） |
    |---|---|---|
    | PKCS#7 | n 个值为 n 的字节 | `03 03 03` |
    | ANSI X9.23 | n−1 个 0，最后一个为 n | `00 00 03` |
    | ISO/IEC 7816-4 | `80` 后接 0 | `80 00 00` |
    | 零填充 | 全部补 0（原文末尾是 0 时无法区分） | `00 00 00` |

    PKCS#7 在长度恰好是块长倍数时也要补一整块（16 个 `0x10`），这样解密时才能无歧义地去掉填充。
    """,
    inputs=[text_input("数据（十六进制）", placeholder="666c6167")],
    options=[field("action", "segmented", "操作", default="添加填充", choices=["添加填充", "检查并去除"]),
             field("scheme", "select", "方式", default="PKCS#7", choices=PADS[:-1]),
             field("block", "number", "块长", default=16, min=1, max=255)],
    examples=[{"text": "666c6167", "action": "添加填充"}],
    keywords=["padding", "pkcs7", "填充"],
)
def padding_tool(text, action="添加填充", scheme="PKCS#7", block=16):
    data = to_bytes(text, "十六进制")
    bs = int(block)
    if action == "添加填充":
        return pad(data, bs, scheme).hex()
    try:
        return fields([["去除填充后", unpad(data, bs, scheme).hex()], ["填充正确", "是"]])
    except ValueError as e:
        raise ToolError(str(e))
