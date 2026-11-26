"""压缩包（教材 1.5）：ZIP 结构、伪加密、ZipCrypto 密码爆破、CRC32 碰撞。"""

import itertools
import string
import struct
import zlib

from ..registry import ToolError, field, text_input, tool
from ..util import fields, file_out, table

# ---------------------------------------------------------------- ZIP 结构

METHODS = {0: "存储（不压缩）", 8: "Deflate", 9: "Deflate64", 12: "BZIP2", 14: "LZMA", 93: "Zstandard", 99: "AES 加密"}


def zip_records(data):
    """解析本地文件头与中央目录记录。返回 (本地列表, 中央列表, 结束记录)。"""
    local, central, eocd = [], [], None
    i = 0
    while True:
        i = data.find(b"PK\x03\x04", i)
        if i < 0 or i + 30 > len(data):
            break
        ver, flag, method, mtime, mdate, crc, csize, usize, nlen, elen = struct.unpack("<HHHHHIIIHH", data[i + 4:i + 30])
        name = data[i + 30:i + 30 + nlen]
        local.append({"offset": i, "flag": flag, "method": method, "crc": crc, "csize": csize, "usize": usize,
                      "name": name.decode("utf-8", "replace"), "data_offset": i + 30 + nlen + elen, "mtime": mtime})
        i += 4
    i = 0
    while True:
        i = data.find(b"PK\x01\x02", i)
        if i < 0 or i + 46 > len(data):
            break
        f = struct.unpack("<HHHHHHIIIHHHHHII", data[i + 4:i + 46])
        nlen, elen, clen = f[9], f[10], f[11]
        central.append({"offset": i, "flag": f[2], "method": f[3], "crc": f[6], "csize": f[7], "usize": f[8],
                        "name": data[i + 46:i + 46 + nlen].decode("utf-8", "replace"), "local": f[15],
                        "comment": data[i + 46 + nlen + elen:i + 46 + nlen + elen + clen]})
        i += 4
    j = data.rfind(b"PK\x05\x06")
    if j >= 0 and j + 22 <= len(data):
        n, total, size, off, clen = struct.unpack("<HHIIH", data[j + 8:j + 22])
        eocd = {"offset": j, "entries": total, "cd_offset": off, "comment": data[j + 22:j + 22 + clen]}
    return local, central, eocd


def zip_extract(data, rec):
    """解压一个（未加密的）本地文件记录，返回内容；失败返回 None。"""
    body = data[rec["data_offset"]:rec["data_offset"] + rec["csize"]]
    try:
        if rec["method"] == 0:
            return body
        if rec["method"] == 8:
            return zlib.decompress(body, -15)
    except zlib.error:
        return None
    return None


@tool(
    "forensics.zip", "ZIP 结构与伪加密", "forensics", "1.5.0～1.5.1",
    summary="逐条列出 ZIP 记录的字段，检测伪加密并一键修复，显示注释、CRC 与大小",
    principle="""
    ZIP 中每个文件有两条记录：文件数据前面的**本地文件头**（`PK 03 04`）和文件末尾的**中央目录记录**（`PK 01 02`），
    最后是**中央目录结束记录**（`PK 05 06`，含压缩包注释）。两条记录里都有一个“通用位标记”，最低位表示是否加密。

    **伪加密**：数据没加密，只是把加密位改成了 1，解压软件就会要密码。判断方法：

    - 加密位为 1，但压缩方法是“存储”且数据就是明文，或者 Deflate 数据能直接解压，就是伪加密；
    - 只有一处记录的加密位为 1 也是伪加密的特征。

    把加密位清零（本工具“修复”生成的文件）即可正常解压。另外注意：**压缩包注释**常藏提示；
    CRC32 和原始大小在不解压的情况下就能看到，小文件可以用“CRC32 碰撞”反推内容。
    """,
    inputs=[field("file", "file", "ZIP 文件")],
    options=[field("extract", "switch", "尝试解压未加密的文件", default=True)],
    keywords=["zip", "伪加密", "压缩包", "加密位", "注释"],
    live=False,
)
def zip_tool(file=b"", extract=True):
    if not file:
        raise ToolError("请先上传 ZIP 文件")
    local, central, eocd = zip_records(file)
    if not local and not central:
        raise ToolError("没有找到 ZIP 记录（PK 03 04 / PK 01 02）")
    rows = []
    for r in local:
        c = next((x for x in central if x["local"] == r["offset"]), None)
        enc_l, enc_c = r["flag"] & 1, (c["flag"] & 1) if c else None
        rows.append([r["name"], METHODS.get(r["method"], r["method"]), r["usize"], r["csize"], "%08x" % r["crc"],
                     enc_l, "—" if enc_c is None else enc_c, "是" if r["flag"] & 0x40 or r["method"] == 99 else "否"])
    out = [table(["文件名", "压缩方法", "原始大小", "压缩后大小", "CRC32", "本地加密位", "中央目录加密位", "AES / 强加密"], rows)]
    info = [["文件数", len(local)]]
    if eocd and eocd["comment"]:
        info.append(["压缩包注释", eocd["comment"].decode("utf-8", "replace")])
    for c in central:
        if c["comment"]:
            info.append(["%s 的注释" % c["name"], c["comment"].decode("utf-8", "replace")])
    suspicious = []
    for r in local:
        c = next((x for x in central if x["local"] == r["offset"]), None)
        flags = {r["flag"] & 1, (c["flag"] & 1) if c else r["flag"] & 1}
        if 1 in flags:
            body = file[r["data_offset"]:r["data_offset"] + r["csize"]]
            plain = None
            if r["method"] == 8:
                try:
                    plain = zlib.decompress(body, -15)
                except zlib.error:
                    plain = None
            elif r["method"] == 0:
                plain = body
            if plain is not None and zlib.crc32(plain) & 0xFFFFFFFF == r["crc"]:
                suspicious.append(r["name"])
            elif len(flags) == 2:
                suspicious.append(r["name"])
    if suspicious:
        info.append(["判断", "伪加密：%s 的数据可以直接解压（或两处加密位不一致）" % "、".join(suspicious)])
        fixed = bytearray(file)
        for r in local:
            fixed[r["offset"] + 6] &= 0xFE
        for c in central:
            fixed[c["offset"] + 8] &= 0xFE
        out.append(file_out(bytes(fixed), "fixed.zip", "application/zip", "清除加密位后的压缩包"))
    elif any(r["flag"] & 1 for r in local):
        info.append(["判断", "真加密：可以尝试“ZIP 密码爆破”，或在 Docker 中用 bkcrack 做已知明文攻击"])
    if extract:
        for r in local:
            if r["flag"] & 1 and r["name"] not in suspicious:
                continue
            content = zip_extract(file, r)
            if content is not None and not r["name"].endswith("/"):
                out.append(file_out(content, r["name"].split("/")[-1] or "file", caption="解压：%s" % r["name"]))
                if len(content) < 2000:
                    try:
                        info.append(["%s 的内容" % r["name"], content.decode("utf-8")])
                    except UnicodeDecodeError:
                        pass
    return [fields(info)] + out


# ---------------------------------------------------------------- ZipCrypto 爆破

CRC_TABLE = [0] * 256
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    CRC_TABLE[_n] = _c


class ZipCrypto:
    """传统 ZIP 加密（ZipCrypto）：三个 32 位密钥，由密码逐字节更新。"""

    def __init__(self, pw):
        k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
        T = CRC_TABLE
        for c in pw:
            k0 = (k0 >> 8) ^ T[(k0 ^ c) & 0xFF]
            k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            k2 = (k2 >> 8) ^ T[(k2 ^ (k1 >> 24)) & 0xFF]
        self.k = [k0, k1, k2]

    def decrypt(self, data):
        k0, k1, k2 = self.k
        T = CRC_TABLE
        out = bytearray(len(data))
        for i, b in enumerate(data):
            t = (k2 | 2) & 0xFFFF
            p = b ^ (((t * (t ^ 1)) >> 8) & 0xFF)
            out[i] = p
            k0 = (k0 >> 8) ^ T[(k0 ^ p) & 0xFF]
            k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            k2 = (k2 >> 8) ^ T[(k2 ^ (k1 >> 24)) & 0xFF]
        self.k = [k0, k1, k2]
        return bytes(out)


def try_password(file, rec, pw):
    body = file[rec["data_offset"]:rec["data_offset"] + rec["csize"]]
    z = ZipCrypto(pw)
    head = z.decrypt(body[:12])
    check = (rec["mtime"] >> 8) & 0xFF if rec["flag"] & 0x08 else rec["crc"] >> 24
    if head[11] != check:
        return None                                    # 12 字节加密头的最后一个字节是校验值，可快速排除 255/256 的错误密码
    plain = z.decrypt(body[12:])
    try:
        content = zlib.decompress(plain, -15) if rec["method"] == 8 else plain
    except zlib.error:
        return None
    return content if zlib.crc32(content) & 0xFFFFFFFF == rec["crc"] else None


CHARSETS = {"数字": string.digits, "小写字母": string.ascii_lowercase, "小写字母 + 数字": string.ascii_lowercase + string.digits,
            "大小写字母 + 数字": string.ascii_letters + string.digits}


@tool(
    "forensics.zip_crack", "ZIP 密码恢复", "forensics", "1.5.2",
    summary="对 ZipCrypto 加密的压缩包，用字典或字符集枚举找回密码（仅限自己的文件）",
    principle="""
    传统 ZIP 加密（ZipCrypto）由密码生成三个密钥再逐字节还原数据。每个加密文件前有 12 字节校验头，
    最后一个字节等于 CRC32 的最高字节，因此约 255/256 的错误候选可以立即排除，剩下的再用 CRC32 核对，速度很快。

    - 短数字密码（如 4～6 位）可直接枚举；
    - 常见密码放在字典里逐行尝试；
    - 更长的密码请在 Docker 环境中用 `john`、`hashcat`；若已知压缩包内某文件的部分明文，用 `bkcrack` 做已知明文攻击更高效。

    本工具只应用于你自己拥有或已获授权的文件。浏览器 / 手机端最多尝试 200 万个候选。
    """,
    inputs=[field("file", "file", "加密的 ZIP 文件"),
            text_input("字典（每行一个，留空则按字符集枚举）", id="words")],
    options=[field("charset", "select", "字符集", default="数字", choices=list(CHARSETS)),
             field("min_len", "number", "最短长度", default=1, min=1, max=8),
             field("max_len", "number", "最长长度", default=6, min=1, max=10)],
    keywords=["zip", "密码", "爆破", "zipcrypto", "john", "bkcrack"],
    live=False,
)
def zip_crack_tool(file=b"", words="", charset="数字", min_len=1, max_len=6):
    if not file:
        raise ToolError("请先上传加密的 ZIP 文件")
    local, _, _ = zip_records(file)
    targets = [r for r in local if r["flag"] & 1 and r["method"] in (0, 8) and r["csize"] > 12]
    if not targets:
        raise ToolError("没有找到 ZipCrypto 加密的文件（可能未加密、是伪加密，或使用了 AES 加密）")
    rec = min(targets, key=lambda r: r["csize"])          # 用最小的文件试密码，最快
    MAX = 2_000_000

    def check(pw):
        return try_password(file, rec, pw)

    tried = 0
    if words.strip():
        for line in words.splitlines():
            pw = line.strip()
            if not pw:
                continue
            tried += 1
            content = check(pw.encode("utf-8", "ignore"))
            if content is not None:
                return _crack_result(pw, tried, rec, file, local)
        return "字典中的 %d 个密码都不对。" % tried
    chars = [c.encode() for c in CHARSETS[charset]]
    for ln in range(int(min_len), int(max_len) + 1):
        for combo in itertools.product(chars, repeat=ln):
            tried += 1
            if tried > MAX:
                raise ToolError("已尝试 %d 个密码仍未找到，请缩小范围或改用 Docker 中的 john/hashcat" % MAX)
            pw = b"".join(combo)
            content = check(pw)
            if content is not None:
                return _crack_result(pw.decode("latin-1"), tried, rec, file, local)
    return "枚举完 %d 个候选都不对，请扩大字符集或长度。" % tried


def _crack_result(pw, tried, rec, file, local):
    out = [fields([["密码", pw], ["尝试次数", tried], ["用于试密码的文件", rec["name"]]])]
    for r in local:
        if r["flag"] & 1 and r["method"] in (0, 8):
            content = try_password(file, r, pw.encode("latin-1"))
            if content is not None and not r["name"].endswith("/"):
                out.append(file_out(content, r["name"].split("/")[-1] or "file", caption="解密：%s" % r["name"]))
    return out


# ---------------------------------------------------------------- CRC32 碰撞

def crc32_reverse(target, length):
    """已知内容长度与 CRC32，枚举全部可能的内容（仅在长度很小时可行）。"""
    charset = (string.ascii_letters + string.digits + "_{}!@#$%^&*()-+=").encode()
    results = []
    if length <= 4:
        space = 256 ** length
        full = length > 2 or space <= 70000
        pool = range(256) if full else charset
        for combo in itertools.product(pool if length <= 2 else charset, repeat=length):
            b = bytes(combo)
            if zlib.crc32(b) & 0xFFFFFFFF == target:
                results.append(b)
                if len(results) >= 50:
                    break
    return results


@tool(
    "forensics.crc32", "CRC32 碰撞", "forensics", "1.5.3",
    summary="内容只有几个字节时，由 CRC32 反推内容（常用于逐个还原被分卷的小文件）",
    principle="""
    CRC32 是 4 字节校验值，不是加密。当一个文件的**内容非常短**（通常 1～6 字节）时，
    可以枚举所有可能的内容，算出 CRC32 与目标比对，从而“解出”内容——这是因为短内容的数量
    比 CRC32 的取值范围还小。

    常见题型：压缩包里有许多每个只存 4～6 字节的小文件，不解压就能从 ZIP 结构里读到每个文件的 CRC32
    （用“ZIP 结构”工具），逐个碰撞还原后拼起来就是 flag。

    一次输入一个 CRC32 与长度；长度超过 6 字节时组合太多，无法枚举。
    """,
    inputs=[text_input("CRC32 值（每行一个，格式：crc,长度）", placeholder="0x4a17b156,4\n0x9e83b2cd,4")],
    options=[field("charset", "segmented", "枚举范围", default="可见字符", choices=["可见字符", "全部字节"])],
    examples=[{"text": "0x%08x,4" % (zlib.crc32(b"flag") & 0xFFFFFFFF)}],
    keywords=["crc32", "碰撞", "crc", "反推"],
    live=False,
)
def crc32_tool(text, charset="可见字符"):
    import re as _re
    rows = []
    recovered = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _re.match(r"(?:0x)?([0-9a-fA-F]+)\s*[,\s]\s*(\d+)", line)
        if not m:
            rows.append([line, "格式应为 crc,长度"])
            continue
        crc, length = int(m.group(1), 16), int(m.group(2))
        if length > 6:
            rows.append([line, "长度 %d 太大，无法枚举" % length])
            recovered.append("?" * length)
            continue
        res = crc32_reverse(crc, length)
        if res:
            texts = [r.decode("latin-1") for r in res]
            rows.append(["0x%08x (%d)" % (crc, length), "  ".join(repr(t) for t in texts)])
            recovered.append(texts[0])
        else:
            rows.append(["0x%08x (%d)" % (crc, length), "未找到（可能长度不对或内容含特殊字节）"])
            recovered.append("?" * length)
    if not rows:
        raise ToolError("请按“crc,长度”每行输入一个")
    return [table(["CRC32（长度）", "可能的内容"], rows),
            fields([["按顺序拼接", "".join(recovered)]])]
