"""哈希函数（教材 3.4）：计算、HMAC、类型识别、短明文爆破。"""

import hashlib
import hmac
import itertools
import re
import string
import zlib

from ..registry import ToolError, field, text_input, tool
from ..util import INPUT_FORMATS, table, to_bytes

ALGORITHMS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512",
              "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"]


def digest(name, data):
    if name == "crc32":
        return "%08x" % (zlib.crc32(data) & 0xFFFFFFFF)
    if name == "adler32":
        return "%08x" % (zlib.adler32(data) & 0xFFFFFFFF)
    return hashlib.new(name, data).hexdigest()


@tool(
    "hash.digest", "哈希计算", "hash", "3.4.0",
    summary="MD5、SHA-1、SHA-2、SHA-3、BLAKE2、CRC32 一次全部算出",
    principle="""
    哈希函数把任意长度的数据变成固定长度的“摘要”，有三个特点：

    1. **相同输入，结果一定相同**；输入改一个字节，结果完全不同；
    2. **不可逆**：无法从摘要算回原文，只能猜原文再比对（即“爆破”）；
    3. **长度固定**：MD5 是 128 位（32 个十六进制字符），SHA-1 是 160 位（40 个），SHA-256 是 256 位（64 个）。

    MD5 与 SHA-1 已能人为构造碰撞（两段不同数据得到相同摘要），不应再用于安全场合，但 CTF 中仍很常见。
    CRC32 不是密码学哈希，只用于校验数据是否损坏，很容易反推（见教材 1.5.3 CRC 碰撞）。
    """,
    inputs=[text_input(placeholder="flag")],
    options=[field("input_format", "segmented", "输入格式", default="文本", choices=INPUT_FORMATS),
             field("upper", "switch", "大写字母", default=False)],
    examples=[{"text": "abc"}],
    keywords=["hash", "md5", "sha1", "sha256", "crc32", "哈希", "摘要"],
)
def digest_tool(text, input_format="文本", upper=False):
    data = to_bytes(text, input_format)
    rows = []
    for name in ALGORITHMS + ["crc32", "adler32"]:
        h = digest(name, data)
        rows.append([name.upper().replace("_", "-"), len(h) * 4, h.upper() if upper else h])
    return table(["算法", "位数", "结果"], rows)


@tool(
    "hash.hmac", "HMAC", "hash", "3.4.0",
    summary="带密钥的哈希：HMAC-MD5 / SHA-1 / SHA-256 / SHA-512",
    principle="""
    HMAC 是带密钥的哈希：`HMAC(K, m) = H((K ⊕ opad) ‖ H((K ⊕ ipad) ‖ m))`。
    它用来验证消息没有被篡改、且确实来自持有密钥的人，常见于 API 签名与 JWT（HS256 即 HMAC-SHA256）。

    与直接计算 `H(密钥 + 消息)` 不同，HMAC 不受长度扩展攻击（教材 3.4.2）影响。
    """,
    inputs=[text_input("消息", placeholder="message")],
    options=[field("key", "string", "密钥", default="key"),
             field("algorithm", "select", "算法", default="sha256", choices=["md5", "sha1", "sha256", "sha512"])],
    examples=[{"text": "The quick brown fox jumps over the lazy dog", "key": "key", "algorithm": "sha256"}],
    keywords=["hmac", "签名"],
)
def hmac_tool(text, key="key", algorithm="sha256"):
    return hmac.new(key.encode("utf-8"), text.encode("utf-8"), algorithm).hexdigest()


# ---------------------------------------------------------------- 类型识别

HEX_BY_LEN = {
    8: ["CRC32", "Adler-32"],
    16: ["MySQL 3.x（OLD_PASSWORD）", "MD5 的一半（如截取的 16 位 MD5）"],
    32: ["MD5", "NTLM", "MD4"],
    40: ["SHA-1", "MySQL 5.x（去掉开头的 *）", "RIPEMD-160"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b", "Whirlpool"],
}
PREFIXES = [
    (r"^\$1\$", "MD5-crypt（Linux /etc/shadow）"), (r"^\$2[abxy]?\$", "bcrypt"),
    (r"^\$5\$", "SHA-256-crypt（Linux /etc/shadow）"), (r"^\$6\$", "SHA-512-crypt（Linux /etc/shadow）"),
    (r"^\$y\$", "yescrypt（较新的 Linux /etc/shadow）"), (r"^\$apr1\$", "Apache MD5（.htpasswd）"),
    (r"^\$argon2", "Argon2"), (r"^\$P\$|^\$H\$", "phpass（WordPress、phpBB）"),
    (r"^\*[0-9A-F]{40}$", "MySQL 4.1+ 密码哈希"), (r"^pbkdf2_sha256\$", "PBKDF2（Django）"),
    (r"^\{SHA\}", "SHA-1 Base64（LDAP / .htpasswd）"), (r"^[a-f0-9]{32}:[^:]+$", "加盐的 MD5（哈希:盐）"),
]


@tool(
    "hash.identify", "哈希类型识别", "hash", "3.4.1",
    summary="按长度、字符集与前缀推测是哪种哈希",
    principle="""
    哈希值本身不带类型信息，只能根据**长度**和**格式**推测：

    - 32 个十六进制字符多半是 MD5，40 个是 SHA-1，64 个是 SHA-256；
    - `$1$`、`$6$` 开头的是 Linux `/etc/shadow` 中的加盐密码哈希；`$2a$`、`$2y$` 开头的是 bcrypt。

    同一长度可能对应多种算法，识别结果按常见程度排列，需要逐个尝试。
    """,
    inputs=[text_input("哈希值", placeholder="5f4dcc3b5aa765d61d8327deb882cf99")],
    examples=[{"text": "5f4dcc3b5aa765d61d8327deb882cf99"}],
    keywords=["识别", "identify", "hash type"],
)
def identify_tool(text):
    rows = []
    for line in [l.strip() for l in text.splitlines() if l.strip()][:50]:
        guesses = [name for pat, name in PREFIXES if re.search(pat, line)]
        if re.fullmatch(r"[0-9a-fA-F]+", line):
            guesses += HEX_BY_LEN.get(len(line), [])
            if len(line) == 32 and line.lower().startswith("0e") and line[2:].isdigit():
                guesses.append("注意：0e 开头且其余全是数字，PHP 弱类型比较中等于 0（教材 4.3）")
        elif re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", line) and len(line) % 4 == 0:
            n = len(line) * 3 // 4 - line.count("=")
            guesses += ["Base64 编码的 %d 字节数据（%d 字节对应 %s）" % (
                n, n, {16: "MD5", 20: "SHA-1", 32: "SHA-256", 64: "SHA-512"}.get(n, "未知算法"))]
        rows.append([line if len(line) <= 70 else line[:70] + "…", len(line), "；".join(guesses) or "无法识别"])
    if not rows:
        raise ToolError("请输入哈希值，一行一个")
    return table(["哈希值", "长度", "可能的类型"], rows)


# ---------------------------------------------------------------- 爆破

CHARSETS = {
    "数字": string.digits,
    "小写字母": string.ascii_lowercase,
    "小写字母 + 数字": string.ascii_lowercase + string.digits,
    "大小写字母 + 数字": string.ascii_letters + string.digits,
    "可打印字符": "".join(chr(i) for i in range(32, 127)),
}
MAX_TRIES = 20_000_000


def _guess_algorithm(h):
    return {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}.get(len(h))


def crack(target, algorithm="自动", charset="数字", min_len=1, max_len=4, template="*", prefix=False,
          words=None, max_tries=MAX_TRIES):
    target = target.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", target):
        raise ToolError("目标哈希应为十六进制字符串")
    algo = _guess_algorithm(target) if algorithm == "自动" else algorithm
    if prefix:
        algo = algo or "md5"
    if not algo:
        raise ToolError("无法从长度 %d 推断算法，请手动选择；只给出部分哈希时请打开“只比较开头”" % len(target))
    if template.count("*") != 1:
        raise ToolError("明文模板中要有且只有一个 * 表示要枚举的部分，如 flag{*}")
    head, tail = template.split("*", 1)
    head, tail = head.encode("utf-8"), tail.encode("utf-8")
    hfn = (lambda d: zlib.crc32(d) & 0xFFFFFFFF) if algo == "crc32" else None
    tries = 0

    def check(cand):
        d = head + cand + tail
        h = ("%08x" % hfn(d)) if hfn else hashlib.new(algo, d).hexdigest()
        return h.startswith(target) if prefix else h == target

    if words is not None:
        for w in words:
            tries += 1
            if check(w.encode("utf-8")):
                return w, tries, algo
        return None, tries, algo
    chars = [c.encode("utf-8") for c in CHARSETS[charset]]
    for n in range(int(min_len), int(max_len) + 1):
        for combo in itertools.product(chars, repeat=n):
            tries += 1
            if tries > max_tries:
                raise ToolError("已尝试 %d 次仍未找到。请缩小字符集或长度，或在 Docker 环境中使用 hashcat" % max_tries)
            c = b"".join(combo)
            if check(c):
                return c.decode("utf-8"), tries, algo
    return None, tries, algo


@tool(
    "hash.crack", "哈希爆破", "hash", "3.4.1",
    summary="已知哈希，枚举短明文或用字典查找；支持 flag{*} 模板与只比较开头",
    principle="""
    哈希不可逆，但如果原文很短或在字典里，可以**逐个尝试**：对每个候选计算哈希，与目标比较。

    - 4 位数字只有 1 万种，6 位小写字母约 3 亿种——所需时间随长度指数增长；
    - **模板**：已知部分明文时只爆破未知部分，如 `flag{*}` 中 `*` 表示要枚举的位置；
    - **只比较开头**：Web 题常见“`substr(md5($x), 0, 6) === 'a1b2c3'`”类验证码，只需开头几位相同。

    浏览器和手机中最多尝试 2000 万次；更大的范围请在 Docker 环境中使用 `hashcat` 或 `john`。
    """,
    inputs=[field("text", "string", "目标哈希", default="", placeholder="81dc9bdb52d04dc20036dbd8313ed055"),
            field("words", "text", "字典（一行一个，留空则按字符集枚举）", default="")],
    options=[field("algorithm", "select", "算法", default="自动", choices=["自动", "md5", "sha1", "sha256", "sha512", "crc32"]),
             field("charset", "select", "字符集", default="数字", choices=list(CHARSETS)),
             field("min_len", "number", "最短长度", default=1, min=1, max=8),
             field("max_len", "number", "最长长度", default=4, min=1, max=8),
             field("template", "string", "明文模板", default="*", help="* 处为枚举的内容，如 flag{*}"),
             field("prefix", "switch", "只比较开头", default=False)],
    examples=[{"text": "81dc9bdb52d04dc20036dbd8313ed055", "charset": "数字", "max_len": 4}],
    keywords=["爆破", "crack", "brute", "md5", "字典"],
    live=False,
)
def crack_tool(text, words="", algorithm="自动", charset="数字", min_len=1, max_len=4, template="*", prefix=False):
    if not text.strip():
        raise ToolError("请输入目标哈希")
    wl = [w for w in words.splitlines() if w] if words.strip() else None
    found, tries, algo = crack(text, algorithm, charset, int(min_len), int(max_len), template, prefix, wl)
    if found is None:
        return "没有找到（算法 %s，共尝试 %d 次）。可以扩大字符集或长度，或换一个字典。" % (algo, tries)
    return table(["项目", "结果"], [["明文", template.replace("*", found, 1)], ["枚举部分", found],
                                     ["算法", algo], ["尝试次数", tries]])
