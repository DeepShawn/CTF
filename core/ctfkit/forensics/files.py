"""文件识别、分离、字符串提取与十六进制查看（教材 1.4.0～1.4.1）。"""

import re
import zlib

from ..registry import ToolError, field, tool
from ..util import fields, file_out, find_flags, table

# (文件头, 类型, 扩展名, 文件尾)。文件尾用于分离时确定结束位置
SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG 图片", "png", b"IEND\xaeB`\x82"),
    (b"\xff\xd8\xff", "JPG 图片", "jpg", b"\xff\xd9"),
    (b"GIF87a", "GIF 图片", "gif", b"\x00\x3b"),
    (b"GIF89a", "GIF 图片", "gif", b"\x00\x3b"),
    (b"BM", "BMP 图片", "bmp", None),
    (b"PK\x03\x04", "ZIP 压缩包（也可能是 docx / xlsx / apk / jar）", "zip", None),
    (b"PK\x05\x06", "ZIP 压缩包（空）", "zip", None),
    (b"Rar!\x1a\x07\x00", "RAR 4 压缩包", "rar", None),
    (b"Rar!\x1a\x07\x01\x00", "RAR 5 压缩包", "rar", None),
    (b"7z\xbc\xaf\x27\x1c", "7z 压缩包", "7z", None),
    (b"\x1f\x8b\x08", "gzip 压缩", "gz", None),
    (b"BZh", "bzip2 压缩", "bz2", None),
    (b"\xfd7zXZ\x00", "xz 压缩", "xz", None),
    (b"%PDF-", "PDF 文档", "pdf", b"%%EOF"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "旧版 Office 文档（doc / xls / ppt）", "doc", None),
    (b"\x7fELF", "ELF 可执行文件（Linux）", "elf", None),
    (b"MZ", "PE 可执行文件（Windows exe / dll）", "exe", None),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O 通用二进制", "class", None),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64 位可执行文件（macOS）", "macho", None),
    (b"dex\n", "Android DEX", "dex", None),
    (b"RIFF", "RIFF 容器（WAV 音频 / AVI 视频 / WEBP 图片）", "riff", None),
    (b"ID3", "MP3 音频（带 ID3 标签）", "mp3", None),
    (b"\xff\xfb", "MP3 音频", "mp3", None),
    (b"OggS", "OGG 音频", "ogg", None),
    (b"fLaC", "FLAC 音频", "flac", None),
    (b"\x00\x00\x00\x18ftyp", "MP4 视频", "mp4", None),
    (b"\x00\x00\x00\x20ftyp", "MP4 视频", "mp4", None),
    (b"\x1a\x45\xdf\xa3", "MKV / WEBM 视频", "mkv", None),
    (b"\xd4\xc3\xb2\xa1", "pcap 抓包文件", "pcap", None),
    (b"\xa1\xb2\xc3\xd4", "pcap 抓包文件（大端）", "pcap", None),
    (b"\x0a\x0d\x0d\x0a", "pcapng 抓包文件", "pcapng", None),
    (b"SQLite format 3\x00", "SQLite 数据库", "sqlite", None),
    (b"-----BEGIN", "PEM 证书 / 密钥", "pem", None),
    (b"\x00\x00\x01\x00", "ICO 图标", "ico", None),
    (b"II*\x00", "TIFF 图片", "tif", None),
    (b"MM\x00*", "TIFF 图片", "tif", None),
    (b"8BPS", "Photoshop PSD", "psd", None),
    (b"wOFF", "WOFF 字体", "woff", None),
    (b"\x03\xf3\x0d\x0a", "Python 2.7 字节码（.pyc）", "pyc", None),
    (b"\x55\x0d\x0d\x0a", "Python 3.8 字节码（.pyc）", "pyc", None),
    (b"\x61\x0d\x0d\x0a", "Python 3.9 字节码（.pyc）", "pyc", None),
    (b"\x6f\x0d\x0d\x0a", "Python 3.10 字节码（.pyc）", "pyc", None),
    (b"\xa7\x0d\x0d\x0a", "Python 3.11 字节码（.pyc）", "pyc", None),
    (b"\xcb\x0d\x0d\x0a", "Python 3.12 字节码（.pyc）", "pyc", None),
    (b"<?xml", "XML 文本", "xml", None),
    (b"<!DOCTYPE html", "HTML 网页", "html", None),
    (b"<html", "HTML 网页", "html", None),
    (b"#!", "脚本（Shebang）", "sh", None),
    (b"\xef\xbb\xbf", "带 BOM 的 UTF-8 文本", "txt", None),
]


def identify(data):
    """按文件头识别，返回 [(扩展名, 描述)]。"""
    out = []
    for sig, desc, ext, _ in SIGNATURES:
        if data.startswith(sig):
            if sig == b"RIFF" and len(data) >= 12:
                sub = data[8:12]
                desc = {b"WAVE": "WAV 音频", b"AVI ": "AVI 视频", b"WEBP": "WEBP 图片"}.get(sub, desc)
                ext = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}.get(sub, ext)
            if sig == b"PK\x03\x04":
                head = data[:2000]
                if b"word/" in head:
                    desc, ext = "Word 文档（docx，本质是 ZIP）", "docx"
                elif b"xl/" in head:
                    desc, ext = "Excel 文档（xlsx，本质是 ZIP）", "xlsx"
                elif b"AndroidManifest.xml" in head or b"classes.dex" in head:
                    desc, ext = "Android 安装包（apk，本质是 ZIP）", "apk"
                elif b"META-INF/MANIFEST.MF" in head:
                    desc, ext = "Java 包（jar，本质是 ZIP）", "jar"
            if sig == b"BM" and len(data) >= 6 and int.from_bytes(data[2:6], "little") < 54:
                continue                                         # 两个字节太短，排除明显不是 BMP 的情况
            if sig == b"MZ" and b"PE\0\0" not in data[:1024] and len(data) >= 1024:
                continue
            out.append((ext, desc))
            break
    return out


def scan(data, limit=200):
    """在文件内部查找嵌入的其他文件（类似 binwalk）：返回 [(偏移, 扩展名, 描述)]。"""
    found = []
    strong = [s for s in SIGNATURES if len(s[0]) >= 4 or s[0] in (b"\xff\xd8\xff", b"BZh")]
    for sig, desc, ext, _ in strong:
        for m in re.finditer(re.escape(sig), data):
            off = m.start()
            if sig == b"\xff\xfb" or sig == b"-----BEGIN" and off:
                continue
            found.append((off, ext, desc))
            if len(found) > limit:
                break
    # zlib 数据流（PNG 之外的 zlib 压缩块，常见于 PDF）
    for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", data):
        off = m.start()
        try:
            d = zlib.decompressobj()
            out = d.decompress(data[off:off + 65536], 4096)
            if len(out) > 16:
                found.append((off, "zlib", "zlib 压缩数据（解压后至少 %d 字节）" % len(out)))
        except zlib.error:
            pass
        if len(found) > limit:
            break
    return sorted(set(found))


def carve_end(data, start, ext):
    """估计嵌入文件的结束位置。"""
    for sig, _, e, tail in SIGNATURES:
        if e == ext and tail:
            i = data.find(tail, start + len(sig))
            if i >= 0:
                return i + len(tail)
    if ext == "zip":
        i = data.find(b"PK\x05\x06", start)
        if i >= 0 and i + 22 <= len(data):
            clen = int.from_bytes(data[i + 20:i + 22], "little")
            return i + 22 + clen
    if ext == "bmp":
        size = int.from_bytes(data[start + 2:start + 6], "little")
        if 0 < size <= len(data) - start:
            return start + size
    return len(data)


def need(data, what="文件"):
    if not data:
        raise ToolError("请先上传%s" % what)


@tool(
    "forensics.filetype", "文件识别", "forensics", "1.4.0",
    summary="按文件头判断真实类型，并扫描文件内部嵌入的其他文件（类似 file + binwalk）",
    principle="""
    文件的类型由开头几个字节（**文件头、魔数**）决定，与扩展名无关。改了扩展名的文件，看文件头就知道真实类型：

    | 文件头（十六进制） | 类型 |
    |---|---|
    | `89 50 4E 47` | PNG |
    | `FF D8 FF` | JPG |
    | `47 49 46 38` | GIF |
    | `50 4B 03 04` | ZIP（docx、apk、jar 也是 ZIP） |
    | `52 61 72 21` | RAR |
    | `37 7A BC AF` | 7z |
    | `25 50 44 46` | PDF |
    | `7F 45 4C 46` | ELF（Linux 程序） |
    | `4D 5A` | Windows 程序 |

    **文件拼接**是最常见的隐写：在图片后面接一个压缩包，图片照常显示，压缩包被“藏”在里面。
    扫描文件内部所有位置的文件头就能发现，找到后用“文件分离”取出。
    """,
    inputs=[field("file", "file", "文件")],
    keywords=["file", "binwalk", "文件头", "魔数", "magic", "文件类型"],
    live=False,
)
def filetype_tool(file=b""):
    need(file)
    kind = identify(file)
    head = file[:16]
    out = [fields([["文件大小", "%d 字节" % len(file)], ["文件头", " ".join("%02X" % b for b in head)],
                   ["识别结果", kind[0][1] if kind else "未识别（可能是纯文本、加密数据或被修改了文件头）"],
                   ["文本中的 flag", "，".join(find_flags(file.decode("latin-1"))[:5]) or "无"]])]
    hits = [h for h in scan(file) if h[0] > 0]
    if hits:
        out.append(table(["偏移（十进制）", "偏移（十六进制）", "类型"], [[o, "0x%X" % o, d] for o, _, d in hits[:100]]))
    else:
        out.append("没有在文件内部发现其他文件头。")
    return out


@tool(
    "forensics.carve", "文件分离", "forensics", "1.4.1",
    summary="把嵌入在文件内部的其他文件切出来（类似 binwalk -e / foremost / dd）",
    principle="""
    找到嵌入文件的起始偏移后，从这里一直取到它的结束位置就得到了这个文件：

    - 有固定结尾的格式（PNG 的 `IEND`、JPG 的 `FF D9`、ZIP 的中央目录结束记录）按结尾截取；
    - 其他格式默认取到文件末尾，多出的部分一般不影响打开。

    选择“自动”时，切出文件识别中发现的全部嵌入文件。也可以手动指定偏移和长度，相当于命令
    `dd if=原文件 of=输出 bs=1 skip=偏移 count=长度`。
    """,
    inputs=[field("file", "file", "文件")],
    options=[field("mode", "segmented", "方式", default="自动", choices=["自动", "手动"]),
             field("offset", "string", "起始偏移", default="0", help="十进制或 0x 开头的十六进制", visible_when={"mode": "手动"}),
             field("length", "string", "长度（留空取到末尾）", default="", visible_when={"mode": "手动"})],
    keywords=["binwalk", "foremost", "分离", "dd", "carve", "提取"],
    live=False,
)
def carve_tool(file=b"", mode="自动", offset="0", length=""):
    need(file)
    from ..util import parse_int
    if mode == "手动":
        off = parse_int(offset, "偏移")
        ln = parse_int(length, "长度") if length.strip() else len(file) - off
        part = file[off:off + ln]
        kind = identify(part)
        return [fields([["切出", "%d 字节" % len(part)], ["识别结果", kind[0][1] if kind else "未识别"]]),
                file_out(part, "carved_%x.%s" % (off, kind[0][0] if kind else "bin"))]
    hits = [h for h in scan(file) if h[0] > 0 and h[1] != "zlib"]
    if not hits:
        return "没有发现嵌入的文件。可以改用“手动”指定偏移。"
    out = []
    for off, ext, desc in hits[:20]:
        end = carve_end(file, off, ext)
        out.append(file_out(file[off:end], "carved_%x.%s" % (off, ext), caption="偏移 0x%X：%s，%d 字节" % (off, desc, end - off)))
    return out


@tool(
    "forensics.strings", "字符串提取", "forensics", "1.4",
    summary="提取文件中连续的可打印字符（ASCII 与 UTF-16），并标出疑似 flag",
    principle="""
    二进制文件中的可读文字往往是最快的突破口：程序里的提示语、密码、URL、flag，图片末尾附加的文字……
    这个工具相当于 Linux 命令 `strings`：找出长度不少于 N 的连续可打印字符。

    Windows 程序中的字符串常是 UTF-16（每个字符后跟一个 `00` 字节），普通 strings 看不到，要单独提取。
    """,
    inputs=[field("file", "file", "文件")],
    options=[field("min_len", "number", "最短长度", default=6, min=2, max=100),
             field("encoding", "segmented", "编码", default="全部", choices=["全部", "ASCII", "UTF-16LE"]),
             field("filter", "string", "只显示包含（可选）", default="")],
    keywords=["strings", "字符串", "可打印"],
    live=False,
)
def strings_tool(file=b"", min_len=6, encoding="全部", filter=""):
    need(file)
    n = int(min_len)
    rows = []
    if encoding in ("全部", "ASCII"):
        for m in re.finditer(rb"[\x20-\x7e\t]{%d,}" % n, file):
            rows.append([m.start(), "ASCII", m.group(0).decode("ascii")])
    if encoding in ("全部", "UTF-16LE"):
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % n, file):
            rows.append([m.start(), "UTF-16", m.group(0).decode("utf-16-le")])
    rows.sort()
    if filter:
        rows = [r for r in rows if filter.lower() in r[2].lower()]
    flags = [f for r in rows for f in find_flags(r[2])]
    head = fields([["找到的字符串", len(rows)], ["疑似 flag", "，".join(flags[:10]) or "无"]])
    return [head, table(["偏移", "编码", "内容"], [[r[0], r[1], r[2][:300]] for r in rows[:3000]])]


@tool(
    "forensics.hexview", "十六进制查看", "forensics", "1.4",
    summary="以“偏移 | 十六进制 | ASCII”三栏查看文件任意位置，可搜索字节或文本",
    principle="""
    十六进制查看是分析一切文件的基础：看文件头判断类型、看结构字段、找附加的数据。
    每行显示 16 个字节：左边是偏移，中间是十六进制，右边是对应的 ASCII（不可打印的显示为 `.`）。

    “搜索”可以输入文本（如 `flag`）或十六进制（如 `50 4B 03 04`），结果给出全部出现位置。
    """,
    inputs=[field("file", "file", "文件")],
    options=[field("offset", "string", "起始偏移", default="0"),
             field("length", "number", "显示字节数", default=512, min=16, max=65536),
             field("search", "string", "搜索（文本或十六进制）", default="")],
    keywords=["hex", "十六进制", "xxd", "winhex", "010 editor"],
    live=False,
)
def hexview_tool(file=b"", offset="0", length=512, search=""):
    need(file)
    from ..util import parse_hex, parse_int
    out = []
    if search.strip():
        s = search.strip()
        try:
            needle = parse_hex(s) if re.fullmatch(r"[0-9a-fA-F\s]+", s) and len(re.sub(r"\s", "", s)) % 2 == 0 else s.encode("utf-8")
        except ToolError:
            needle = s.encode("utf-8")
        hits = [m.start() for m in re.finditer(re.escape(needle), file)][:200]
        out.append(fields([["搜索", needle.hex()], ["出现位置", "，".join("0x%X" % h for h in hits) or "没有找到"]]))
        if hits and offset.strip() in ("", "0"):
            offset = str(max(0, hits[0] - hits[0] % 16))
    start = parse_int(offset or "0", "偏移")
    chunk = file[start:start + int(length)]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hx = " ".join("%02x" % b for b in row)
        hx = hx[:23] + " " + hx[23:] if len(row) > 8 else hx
        lines.append("%08x  %-48s |%s|" % (start + i, hx, "".join(chr(b) if 32 <= b < 127 else "." for b in row)))
    out.append({"type": "code", "lang": "hex", "value": "\n".join(lines) or "（超出文件范围）"})
    out.insert(0, fields([["文件大小", "%d 字节（0x%X）" % (len(file), len(file))], ["显示范围", "0x%X ～ 0x%X" % (start, start + len(chunk))]]))
    return out
