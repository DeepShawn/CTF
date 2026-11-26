"""图像隐写（教材 2.1）：PNG / JPG / GIF 结构、宽高修复、位平面、LSB、两图运算、像素与图片互转。"""

import re
import struct
import zlib

from ..imagelib import encode_png, open_image, png_chunks
from ..registry import ToolError, field, text_input, tool
from ..util import fields, file_out, find_flags, image, show, table


def _need(data, what="图片"):
    if not data:
        raise ToolError("请先上传%s" % what)


def file_input(label="图片"):
    return field("file", "file", label)


# ---------------------------------------------------------------- PNG 结构

def brute_png_size(ihdr_body, crc, max_side=4096):
    """IHDR 的 CRC 与内容不符时，枚举宽高找回原始值。先只改高，再只改宽，最后宽高都改。"""
    w, h = struct.unpack(">II", ihdr_body[:8])
    rest = ihdr_body[8:]

    def ok(ww, hh):
        return zlib.crc32(b"IHDR" + struct.pack(">II", ww, hh) + rest) & 0xFFFFFFFF == crc

    for hh in range(1, max_side * 2):
        if ok(w, hh):
            return w, hh
    for ww in range(1, max_side * 2):
        if ok(ww, h):
            return ww, h
    for ww in range(1, max_side):
        for hh in range(1, max_side):
            if ok(ww, hh):
                return ww, hh
    return None


@tool(
    "stego.png", "PNG 结构与宽高修复", "stego", "2.1.1",
    summary="列出全部数据块、校验 CRC、找出文件尾多余数据；宽高被改时自动爆破并修复",
    principle="""
    PNG 由 8 字节文件头和一串数据块（chunk）组成，每块是“长度 + 类型 + 数据 + CRC”：

    | 块 | 内容 |
    |---|---|
    | IHDR | 宽、高、位深、颜色类型（必须是第一块） |
    | PLTE | 调色板 |
    | IDAT | zlib 压缩的像素数据（可以有多块） |
    | tEXt / zTXt / iTXt | 文字信息，常藏提示或 flag |
    | IEND | 结束 |

    **常见考点**：

    1. **宽高被修改**：改小高度后只显示上半部分。CRC 是按原始宽高算的，枚举宽高找到 CRC 相符的值即可还原；
    2. **IEND 之后附加数据**：可能是另一个文件（压缩包、图片），用“文件分离”工具提取；
    3. **多余的 IDAT 块**或 IDAT 解压后多出的数据；
    4. **tEXt 块**中的文字。
    """,
    inputs=[file_input("PNG 图片")],
    options=[field("fix", "switch", "宽高不对时生成修复后的文件", default=True)],
    keywords=["png", "crc", "宽高", "ihdr", "idat", "chunk"],
    live=False,
)
def png_tool(file=b"", fix=True):
    _need(file, "PNG 图片")
    chunks, end = png_chunks(file)
    rows, out = [], []
    texts = []
    ihdr_fix = None
    for off, ctype, body, crc, real in chunks:
        note = ""
        if ctype == "IHDR":
            w, h, depth, ct, _, _, il = struct.unpack(">IIBBBBB", body[:13])
            note = "%d × %d，位深 %d，颜色类型 %d%s" % (w, h, depth, ct, "，隔行" if il else "")
            if crc != real:
                note += "；CRC 不符，宽高可能被改过"
                ihdr_fix = (off, body, crc)
        elif ctype in ("tEXt", "zTXt", "iTXt"):
            try:
                if ctype == "zTXt":
                    k, rest = body.split(b"\0", 1)
                    text = k.decode("latin-1") + ": " + zlib.decompress(rest[1:]).decode("utf-8", "replace")
                elif ctype == "iTXt":
                    k, rest = body.split(b"\0", 1)
                    comp = rest[0]
                    _, _, txt = rest[2:].split(b"\0", 2)
                    text = k.decode("latin-1") + ": " + (zlib.decompress(txt) if comp else txt).decode("utf-8", "replace")
                else:
                    text = body.replace(b"\0", b": ", 1).decode("latin-1")
            except Exception:
                text = repr(body[:100])
            note = text[:200]
            texts.append(text)
        rows.append([off, ctype, len(body), "%08x" % crc if crc is not None else "缺失", "正确" if crc == real else "错误", note])
    out.append(table(["偏移", "类型", "长度", "记录的 CRC", "CRC", "说明"], rows))
    summary = [["数据块数量", len(chunks)]]
    if end < len(file):
        tail = file[end:]
        summary.append(["IEND 之后的数据", "%d 字节，开头：%s" % (len(tail), tail[:16].hex())])
        out.append(file_out(tail, "png_tail.bin", caption="IEND 之后的附加数据（可用“文件识别”查看类型）"))
    for t in texts:
        for f in find_flags(t):
            summary.append(["文字块中的 flag", f])
    if ihdr_fix:
        off, body, crc = ihdr_fix
        r = brute_png_size(body, crc)
        if r:
            summary.append(["原始宽高（按 CRC 爆破）", "%d × %d" % r])
            if fix:
                fixed = file[:off + 8] + struct.pack(">II", *r) + file[off + 16:]
                out.append(file_out(fixed, "fixed.png", "image/png", "修复宽高后的图片"))
                try:
                    out.append(image(fixed, "image/png", "修复后的预览"))
                except Exception:
                    pass
        else:
            summary.append(["宽高爆破", "没有找到 CRC 相符的宽高，CRC 本身可能也被改过"])
    try:
        info = open_image(file).info
        summary += [[k, v] for k, v in info.items()]
    except ToolError as e:
        summary.append(["像素解码", str(e)])
    return [fields(summary)] + out


# ---------------------------------------------------------------- 位平面

CHANNEL_IDX = {"R": 0, "G": 1, "B": 2, "A": 3}


@tool(
    "stego.bitplane", "通道与位平面", "stego", "2.1.4",
    summary="单独查看每个颜色通道的每一位（类似 Stegsolve），找出 LSB 隐写的痕迹",
    principle="""
    每个像素有 R、G、B（可能还有 A）四个通道，每个通道是 0～255 的 8 位数。
    “位平面”是把所有像素某个通道的某一位单独拿出来：这一位为 1 画白色、为 0 画黑色。

    - 高位平面（第 7 位）基本就是图片的轮廓；
    - **最低位平面（第 0 位）**本应是杂乱的噪点。如果里面出现文字、二维码，或者顶部有一条规律的条纹，
      就说明有人在最低位藏了数据（LSB 隐写），接着用“LSB 提取”工具取出。

    依次查看 R0、G0、B0、A0 通常就能发现问题。
    """,
    inputs=[file_input()],
    options=[field("channel", "segmented", "通道", default="R", choices=["R", "G", "B", "A", "RGB 合成"]),
             field("bit", "number", "位（0 为最低位）", default=0, min=0, max=7)],
    keywords=["stegsolve", "位平面", "bit plane", "通道", "lsb"],
    live=False,
)
def bitplane_tool(file=b"", channel="R", bit=0):
    img = open_image(file)
    b = int(bit)
    if channel == "RGB 合成":
        px = [tuple(255 if (p[c] >> b) & 1 else 0 for c in range(3)) + (255,) for p in img.pixels]
    else:
        c = CHANNEL_IDX[channel]
        px = [(255,) * 3 + (255,) if (p[c] >> b) & 1 else (0, 0, 0, 255) for p in img.pixels]
    ones = sum(1 for p in px if p[0] or p[1] or p[2])
    return [image(encode_png(img.width, img.height, px, "RGB"), "image/png", "%s 通道第 %d 位" % (channel, b)),
            fields([["尺寸", "%d × %d" % (img.width, img.height)], ["该位为 1 的像素比例", "%.1f%%" % (100.0 * ones / len(px))]])]


# ---------------------------------------------------------------- LSB 提取

def lsb_bits(img, channels="RGB", bits=(0,), order="按行", alpha_skip=False):
    w, h = img.width, img.height
    idx = [CHANNEL_IDX[c] for c in channels]
    coords = ((y * w + x) for y in range(h) for x in range(w)) if order == "按行" else \
        ((y * w + x) for x in range(w) for y in range(h))
    out = []
    for i in coords:
        p = img.pixels[i]
        for c in idx:
            v = p[c]
            for b in bits:
                out.append((v >> b) & 1)
    return out


def bits_to_bytes(bits, msb_first=True):
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        chunk = bits[i:i + 8]
        if not msb_first:
            chunk = chunk[::-1]
        v = 0
        for b in chunk:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


@tool(
    "stego.lsb", "LSB 提取", "stego", "2.1.4",
    summary="按指定通道、位、顺序取出最低位隐藏的数据（类似 zsteg）；可自动尝试常见组合",
    principle="""
    LSB（最低有效位）隐写把数据的每一位写进像素颜色值的最低位，颜色最多变化 1，肉眼看不出来。
    提取时要知道出题人“按什么顺序写的”：

    | 参数 | 常见取值 |
    |---|---|
    | 通道顺序 | `RGB`（最常见）、`BGR`、只用 `R`，或含透明通道 `RGBA` |
    | 位 | 第 0 位；有时用最低两位 `0,1` |
    | 像素顺序 | 按行（从左到右、从上到下）或按列 |
    | 位序 | 每 8 位组成一个字节时，先取到的位作为最高位（MSB 优先）还是最低位 |

    不知道参数时选“自动尝试”：本工具会试遍常见组合，按“是否出现可读文本 / flag / 文件头”排序。
    提取结果开头若是 `PK`、`89 50 4E 47` 等文件头，说明藏的是文件，可以下载后用“文件识别”查看。
    """,
    inputs=[file_input()],
    options=[field("mode", "segmented", "方式", default="自动尝试", choices=["自动尝试", "手动设置"]),
             field("channels", "string", "通道顺序", default="RGB", visible_when={"mode": "手动设置"}),
             field("bits", "string", "位", default="0", help="多位用逗号分隔，如 0,1", visible_when={"mode": "手动设置"}),
             field("order", "segmented", "像素顺序", default="按行", choices=["按行", "按列"], visible_when={"mode": "手动设置"}),
             field("msb", "segmented", "位序", default="MSB 优先", choices=["MSB 优先", "LSB 优先"], visible_when={"mode": "手动设置"})],
    keywords=["lsb", "zsteg", "最低位", "隐写"],
    live=False,
)
def lsb_tool(file=b"", mode="自动尝试", channels="RGB", bits="0", order="按行", msb="MSB 优先"):
    img = open_image(file)
    if mode == "手动设置":
        chs = channels.upper().strip()
        if not chs or set(chs) - set("RGBA"):
            raise ToolError("通道顺序只能由 R、G、B、A 组成，如 RGB、BGR")
        try:
            bl = [int(x) for x in re.split(r"[,\s]+", bits.strip()) if x != ""]
        except ValueError:
            raise ToolError("位应为 0～7 的数字，用逗号分隔")
        data = bits_to_bytes(lsb_bits(img, chs, bl, order), msb == "MSB 优先")
        return [fields([["前 64 字节（十六进制）", data[:64].hex()], ["按文本显示", show(data[:400])[:400]],
                        ["找到的 flag", "，".join(find_flags(data.decode("latin-1"))) or "无"]]),
                file_out(data, "lsb.bin", caption="提取出的全部数据")]
    from ..forensics.files import identify
    rows = []
    for chs in ("RGB", "BGR", "R", "G", "B", "RGBA", "A"):
        if "A" in chs and all(p[3] == 255 for p in img.pixels[:1000]):
            continue
        for bl in ((0,), (1,), (0, 1)):
            for order in ("按行", "按列"):
                for msb in (True, False):
                    data = bits_to_bytes(lsb_bits(img, chs, bl, order), msb)[:4096]
                    text = data.decode("latin-1")
                    flags = find_flags(text)
                    m = re.match(rb"[\x20-\x7e\r\n\t]{6,}", data)
                    kind = identify(data[:64])
                    score = (100 if flags else 0) + (len(m.group(0)) if m else 0) + (50 if kind else 0)
                    if score >= 8:
                        rows.append([score, chs, ",".join(map(str, bl)), order, "MSB" if msb else "LSB",
                                     flags[0] if flags else (kind[0][1] if kind else show(m.group(0) if m else data[:40])[:80])])
    rows.sort(key=lambda r: -r[0])
    if not rows:
        return "常见组合中都没有发现可读文本、flag 或文件头。可以用“通道与位平面”工具查看各个位平面，再手动设置参数。"
    return table(["得分", "通道", "位", "像素顺序", "位序", "发现"], rows[:20])


# ---------------------------------------------------------------- 两图运算

@tool(
    "stego.combine", "两图运算", "stego", "2.1.5",
    summary="两张图逐像素异或、相减、相加、取与、取或，找出差异或叠加出隐藏信息",
    principle="""
    题目给出两张看起来一样的图片时，往往一张是原图、一张藏了东西。逐像素计算：

    - **异或 / 相减**：相同的像素变成 0（黑色），不同的地方显现出来；
    - **相加 / 取与 / 取或**：两张各藏一半的图（视觉密码）叠加后显示完整内容。

    两张图尺寸需要相同。
    """,
    inputs=[field("file", "file", "图片 1"), field("file2", "file", "图片 2")],
    options=[field("op", "segmented", "运算", default="异或", choices=["异或", "相减", "相加", "取与", "取或"])],
    keywords=["xor", "异或", "两张图", "差异", "combine"],
    live=False,
)
def combine_tool(file=b"", file2=b"", op="异或"):
    a, b = open_image(file), open_image(file2)
    if (a.width, a.height) != (b.width, b.height):
        raise ToolError("两张图尺寸不同：%d × %d 与 %d × %d" % (a.width, a.height, b.width, b.height))
    f = {"异或": lambda x, y: x ^ y, "相减": lambda x, y: abs(x - y), "相加": lambda x, y: min(255, x + y),
         "取与": lambda x, y: x & y, "取或": lambda x, y: x | y}[op]
    px = [tuple(f(p[c], q[c]) for c in range(3)) + (255,) for p, q in zip(a.pixels, b.pixels)]
    diff = sum(1 for p, q in zip(a.pixels, b.pixels) if p != q)
    return [image(encode_png(a.width, a.height, px, "RGB"), "image/png", "运算结果"),
            fields([["不同的像素", "%d 个（%.2f%%）" % (diff, 100.0 * diff / len(px))]])]


# ---------------------------------------------------------------- 像素与图片

def factor_pairs(n):
    return [(w, n // w) for w in range(1, n + 1) if n % w == 0 and 1 < w < n]


@tool(
    "stego.pixels", "像素值转图片", "stego", "2.1.6",
    summary="01 串或 (r, g, b) 列表画成图片；不知道宽度时列出所有可能并推荐接近正方形的",
    principle="""
    有些题目给出一大串像素值，需要自己画成图（常常画出来是二维码或文字）：

    - **01 串**：1 画黑、0 画白（或反过来）。长度往往是平方数（如 625 = 25 × 25 的二维码）；
    - **RGB 列表**：每行一个 `(r, g, b)` 或 `r,g,b`。

    宽 × 高必须等于像素总数。宽度不确定时，本工具列出所有因数分解，默认取最接近正方形的一种。
    """,
    inputs=[text_input("像素数据", placeholder="0101100...\n或\n(255, 0, 0)\n(0, 255, 0)")],
    options=[field("width", "number", "宽度（0 为自动）", default=0, min=0, max=10000),
             field("invert", "switch", "01 串中 1 画白色", default=False),
             field("scale", "number", "放大倍数", default=8, min=1, max=32)],
    examples=[{"text": "1111111001111111\n" * 2, "width": 0}],
    keywords=["像素", "01", "二维码", "rgb", "画图"],
    live=False,
)
def pixels_tool(text, width=0, invert=False, scale=8):
    t = text.strip()
    if not t:
        raise ToolError("请输入像素数据")
    if re.fullmatch(r"[01\s]+", t):
        bits = re.sub(r"\s", "", t)
        on, off = ((255, 255, 255), (0, 0, 0)) if invert else ((0, 0, 0), (255, 255, 255))
        px = [on if b == "1" else off for b in bits]
    else:
        nums = [int(x) for x in re.findall(r"\d+", t)]
        if len(nums) % 3:
            raise ToolError("RGB 数值个数应为 3 的倍数，当前为 %d 个" % len(nums))
        px = [tuple(min(255, v) for v in nums[i:i + 3]) for i in range(0, len(nums), 3)]
    n = len(px)
    pairs = factor_pairs(n)
    w = int(width)
    if not w:
        lines = [l for l in t.splitlines() if l.strip()]
        if len(lines) > 1 and re.fullmatch(r"[01\s]+", t) and len(set(len(l.strip()) for l in lines)) == 1:
            w = len(lines[0].strip())                           # 01 串按行给出时，行长就是宽度
        elif pairs:
            w = min(pairs, key=lambda p: abs(p[0] - p[1]))[0]
        else:
            w = n
    if n % w:
        raise ToolError("像素总数 %d 不能被宽度 %d 整除。可选宽度：%s" % (n, w, "、".join(str(p[0]) for p in pairs[:30]) or "无"))
    h = n // w
    s = max(1, min(int(scale), 4096 // max(w, h)))
    big = [px[(y // s) * w + x // s] for y in range(h * s) for x in range(w * s)]
    return [image(encode_png(w * s, h * s, big, "RGB"), "image/png", "%d × %d" % (w, h)),
            fields([["像素总数", n], ["使用的宽 × 高", "%d × %d" % (w, h)],
                    ["其他可能的宽 × 高", "、".join("%d×%d" % p for p in pairs[:20]) or "无（总数是素数）"]])]


@tool(
    "stego.img2pixels", "图片转像素值", "stego", "2.1.6",
    summary="列出图片每个像素的 RGBA 值，并统计用到的颜色",
    principle="""
    把图片的像素值写出来，便于观察规律：例如整张图只用了两三种颜色、某一列颜色值是 ASCII 码等。
    颜色统计中如果有两种颜色只差 1（如 `(255, 255, 255)` 和 `(254, 255, 255)`），说明可能做过 LSB 修改。
    """,
    inputs=[file_input()],
    options=[field("limit", "number", "最多输出的像素数", default=2000, min=1, max=200000)],
    keywords=["像素", "rgb", "颜色统计"],
    live=False,
)
def img2pixels_tool(file=b"", limit=2000):
    img = open_image(file)
    from collections import Counter
    cnt = Counter(img.pixels)
    lines = "\n".join("(%d, %d, %d, %d)" % p for p in img.pixels[:int(limit)])
    return [fields([["尺寸", "%d × %d" % (img.width, img.height)], ["不同颜色数", len(cnt)]]),
            table(["颜色 RGBA", "像素数"], [["(%d, %d, %d, %d)" % c, n] for c, n in cnt.most_common(30)]),
            lines]


# ---------------------------------------------------------------- GIF

@tool(
    "stego.gif", "GIF 帧拆分", "stego", "2.1.3",
    summary="拆出每一帧并列出停留时间（时间间隔也能藏信息）",
    principle="""
    GIF 动图由多帧组成，每帧有自己的停留时间（单位 1/100 秒）。常见考法：

    - 某一帧一闪而过，里面有 flag：拆帧后逐帧查看；
    - **停留时间本身藏信息**：如只有两种时长，分别代表 0 和 1，拼起来转成 ASCII；
    - 多帧叠加后才能看到完整内容。
    """,
    inputs=[file_input("GIF 图片")],
    options=[field("max_frames", "number", "最多显示的帧数", default=30, min=1, max=300)],
    keywords=["gif", "帧", "动图", "停留时间"],
    live=False,
)
def gif_tool(file=b"", max_frames=30):
    img = open_image(file)
    if img.format != "GIF":
        raise ToolError("请上传 GIF 图片")
    delays = [f.delay for f in img.frames]
    kinds = sorted(set(delays))
    out = [fields([["帧数", len(img.frames)], ["尺寸", "%d × %d" % (img.width, img.height)],
                   ["停留时间序列", " ".join(map(str, delays))]])]
    if len(kinds) == 2:
        bits = "".join("0" if d == kinds[0] else "1" for d in delays)
        txt = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
        out.append(fields([["两种停留时间按 0 / 1 解读", bits], ["转成 ASCII", show(txt)]]))
    for k, f in enumerate(img.frames[:int(max_frames)]):
        out.append(image(encode_png(f.width, f.height, f.pixels), "image/png", "第 %d 帧（%d/100 秒）" % (k + 1, f.delay)))
    return out


# ---------------------------------------------------------------- JPG

JPEG_MARKERS = {0xD8: "SOI 文件开始", 0xE0: "APP0（JFIF）", 0xE1: "APP1（EXIF / XMP）", 0xDB: "DQT 量化表", 0xC0: "SOF0 基线",
                0xC2: "SOF2 渐进", 0xC4: "DHT 哈夫曼表", 0xDA: "SOS 扫描开始", 0xFE: "COM 注释", 0xD9: "EOI 文件结束",
                0xDD: "DRI"}

EXIF_TAGS = {0x010F: "相机厂商", 0x0110: "相机型号", 0x0132: "修改时间", 0x9003: "拍摄时间", 0x013B: "作者",
             0x8298: "版权", 0x010E: "图片描述", 0x9286: "用户注释", 0x0131: "软件", 0x8825: "GPS",
             0x8769: "EXIF 子目录", 0xA420: "图片 ID", 0x9C9B: "标题（Windows）", 0x9C9C: "备注（Windows）",
             0x9C9D: "作者（Windows）", 0x9C9F: "主题（Windows）"}
GPS_TAGS = {1: "纬度方向", 2: "纬度", 3: "经度方向", 4: "经度", 6: "海拔"}


def parse_exif(data):
    """读取 EXIF（TIFF 结构）中的常见字段与 GPS。"""
    if not data.startswith(b"Exif\0\0"):
        return []
    t = data[6:]
    end = "<" if t[:2] == b"II" else ">"
    out = []
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}

    def value(typ, cnt, raw_off, inline):
        size = sizes.get(typ, 1) * cnt
        buf = inline[:size] if size <= 4 else t[raw_off:raw_off + size]
        if typ == 2:
            return buf.rstrip(b"\0").decode("utf-8", "replace")
        if typ == 3:
            return list(struct.unpack(end + "%dH" % cnt, buf[:2 * cnt]))
        if typ == 4:
            return list(struct.unpack(end + "%dI" % cnt, buf[:4 * cnt]))
        if typ in (5, 10):
            vals = struct.unpack(end + "%dI" % (2 * cnt), buf[:8 * cnt])
            return [vals[i] / vals[i + 1] if vals[i + 1] else 0 for i in range(0, len(vals), 2)]
        if typ == 1 or typ == 7:
            try:
                return buf.decode("utf-16-le").rstrip("\0") if len(buf) % 2 == 0 and b"\0" in buf else buf.decode("utf-8", "replace")
            except UnicodeDecodeError:
                return buf.hex()
        return buf.hex()

    def ifd(off, names, depth=0):
        if off + 2 > len(t) or depth > 3:
            return
        n = struct.unpack(end + "H", t[off:off + 2])[0]
        for k in range(min(n, 200)):
            e = off + 2 + 12 * k
            tag, typ, cnt = struct.unpack(end + "HHI", t[e:e + 8])
            inline = t[e + 8:e + 12]
            raw_off = struct.unpack(end + "I", inline)[0]
            if tag in (0x8769, 0x8825) and names is EXIF_TAGS:
                ifd(raw_off, GPS_TAGS if tag == 0x8825 else EXIF_TAGS, depth + 1)
                continue
            if tag in names:
                out.append([names[tag], value(typ, cnt, raw_off, inline)])

    ifd(struct.unpack(end + "I", t[4:8])[0], EXIF_TAGS)
    gps = dict(out)
    if "纬度" in gps and "经度" in gps:
        def dms(v):
            return v[0] + v[1] / 60 + v[2] / 3600 if isinstance(v, list) and len(v) == 3 else v
        out.append(["GPS 坐标（十进制度）", "%.6f %s, %.6f %s" % (dms(gps["纬度"]), gps.get("纬度方向", ""),
                                                          dms(gps["经度"]), gps.get("经度方向", ""))])
    return out


@tool(
    "stego.jpg", "JPG 结构与 EXIF", "stego", "2.1.2",
    summary="列出 JPG 的标记段、注释、EXIF（含 GPS 坐标），找出文件尾 FFD9 之后的附加数据",
    principle="""
    JPG 由一串以 `FF xx` 开头的标记段组成，以 `FF D8` 开始、`FF D9` 结束。隐写常见位置：

    | 位置 | 说明 |
    |---|---|
    | `FF D9` 之后 | 附加的文件或文字（最常见，用“文件识别”可以看到） |
    | COM 注释段（`FF FE`） | 直接写入的文字 |
    | EXIF（`FF E1`） | 相机信息、作者、备注，**GPS 坐标**（社工题找地点） |
    | 像素数据（DCT 系数） | steghide、F5、outguess 等工具的隐写，需要密码或专用工具，请在 Docker 环境中用 `steghide`、`stegseek` |

    JPG 是有损压缩，**不能做 LSB 隐写**（重新压缩就丢失了），所以 JPG 不必查看位平面。
    """,
    inputs=[file_input("JPG 图片")],
    keywords=["jpg", "jpeg", "exif", "gps", "ffd9", "steghide"],
    live=False,
)
def jpg_tool(file=b""):
    _need(file, "JPG 图片")
    if not file.startswith(b"\xff\xd8"):
        raise ToolError("不是 JPG 文件（文件头应为 FF D8）")
    i, rows, out, info = 2, [[0, "FFD8", "SOI 文件开始", 0]], [], []
    eoi = None
    while i < len(file) - 1:
        if file[i] != 0xFF:
            i += 1
            continue
        m = file[i + 1]
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7 or m == 0xFF:
            i += 1 if m == 0xFF else 2
            continue
        if m == 0xD9:
            rows.append([i, "FFD9", "EOI 文件结束", 0])
            eoi = i + 2
            break
        ln = struct.unpack(">H", file[i + 2:i + 4])[0]
        body = file[i + 4:i + 2 + ln]
        rows.append([i, "FF%02X" % m, JPEG_MARKERS.get(m, "APP%d" % (m - 0xE0) if 0xE0 <= m <= 0xEF else ""), ln])
        if m == 0xFE:
            info.append(["注释", body.decode("utf-8", "replace")])
        elif m == 0xE1:
            info += parse_exif(body)
            if body.startswith(b"http://ns.adobe.com/xap"):
                info.append(["XMP", body.split(b"\0", 1)[-1][:500].decode("utf-8", "replace")])
        elif m in (0xC0, 0xC2):
            h, w = struct.unpack(">HH", body[1:5])
            info.append(["尺寸", "%d × %d（%s）" % (w, h, "渐进式" if m == 0xC2 else "基线")])
        if m == 0xDA:                                             # 扫描数据：直接跳到下一个非 RST 标记
            j = i + 2 + ln
            while j < len(file) - 1 and not (file[j] == 0xFF and file[j + 1] not in (0, *range(0xD0, 0xD8))):
                j += 1
            i = j
            continue
        i += 2 + ln
    out.append(table(["偏移", "标记", "含义", "长度"], rows))
    if eoi is None:
        info.append(["警告", "没有找到 FF D9 结束标记，文件可能被截断"])
    elif eoi < len(file):
        tail = file[eoi:]
        from ..forensics.files import identify
        kind = identify(tail[:64])
        info.append(["FFD9 之后的数据", "%d 字节；%s；开头：%s" % (len(tail), kind[0][1] if kind else "未知类型", tail[:24].hex())])
        flags = find_flags(tail.decode("latin-1"))
        if flags:
            info.append(["其中的 flag", "，".join(flags)])
        out.append(file_out(tail, "jpg_tail.bin", caption="FFD9 之后的附加数据"))
    return [fields(info or [["信息", "没有注释和 EXIF"]])] + out
