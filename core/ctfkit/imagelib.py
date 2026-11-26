"""极简图片库：纯 Python 读写 PNG、读取 BMP 与 GIF。

隐写工具需要逐个读取像素。Pillow 在 iOS 上没有现成的包，所以这里用标准库（zlib、struct）自己实现，
只覆盖隐写题中常见的情况：PNG（全部颜色类型、1～16 位、含隔行扫描）、BMP（24 / 32 位、8 位调色板）、
GIF（全部帧）。JPEG 解码过于复杂，不在此实现（JPEG 隐写多用 steghide 等工具，见 Docker 环境）。

像素统一表示为 RGBA 四元组的扁平列表：pixels[y * width + x] = (r, g, b, a)。
"""

import struct
import zlib

from .registry import ToolError

PNG_SIG = b"\x89PNG\r\n\x1a\n"


class Image:
    def __init__(self, width, height, pixels, fmt="PNG", info=None):
        self.width, self.height, self.pixels, self.format = width, height, pixels, fmt
        self.info = info or {}
        self.frames = [self]

    def channel(self, c):
        return [p[c] for p in self.pixels]


# ================================================================ PNG

def png_chunks(data):
    """逐个列出 PNG 数据块：(偏移, 类型, 数据, 记录的 CRC, 实际 CRC)。"""
    if not data.startswith(PNG_SIG):
        raise ToolError("不是 PNG 文件（文件头应为 89 50 4E 47 0D 0A 1A 0A）")
    i, out = 8, []
    while i + 8 <= len(data):
        length, ctype = struct.unpack(">I4s", data[i:i + 8])
        body = data[i + 8:i + 8 + length]
        crc_raw = data[i + 8 + length:i + 12 + length]
        crc = struct.unpack(">I", crc_raw)[0] if len(crc_raw) == 4 else None
        out.append((i, ctype.decode("latin-1"), body, crc, zlib.crc32(ctype + body) & 0xFFFFFFFF))
        i += 12 + length
        if ctype == b"IEND":
            break
    return out, i


def _unfilter(raw, width, height, bpp, row_bytes):
    out = bytearray()
    prev = bytearray(row_bytes)
    pos = 0
    for _ in range(height):
        ft = raw[pos]
        line = bytearray(raw[pos + 1:pos + 1 + row_bytes])
        pos += 1 + row_bytes
        if len(line) < row_bytes:
            raise ToolError("图像数据不完整：可能宽高被改过，试试“PNG 结构”工具中的宽高修复")
        if ft == 1:
            for i in range(bpp, row_bytes):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ft == 2:
            for i in range(row_bytes):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ft == 3:
            for i in range(row_bytes):
                left = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ft == 4:
            for i in range(row_bytes):
                a = line[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xFF
        elif ft != 0:
            raise ToolError("PNG 过滤类型 %d 无效：数据可能损坏" % ft)
        out += line
        prev = line
    return bytes(out), pos


def _samples(row, depth, count):
    if depth == 8:
        return list(row[:count])
    if depth == 16:
        return [row[2 * i] for i in range(count)]               # 16 位只取高字节
    per = 8 // depth
    mask = (1 << depth) - 1
    out = []
    for i in range(count):
        b = row[i // per]
        shift = 8 - depth * (i % per + 1)
        out.append((b >> shift) & mask)
    return out


CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def decode_png(data):
    chunks, _ = png_chunks(data)
    ihdr = next((c for c in chunks if c[1] == "IHDR"), None)
    if not ihdr:
        raise ToolError("PNG 缺少 IHDR 块")
    w, h, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", ihdr[2][:13])
    if ctype not in CHANNELS:
        raise ToolError("PNG 颜色类型 %d 无效" % ctype)
    if w * h > 25_000_000:
        raise ToolError("图片太大（%d × %d）" % (w, h))
    palette = next((c[2] for c in chunks if c[1] == "PLTE"), b"")
    trns = next((c[2] for c in chunks if c[1] == "tRNS"), b"")
    try:
        raw = zlib.decompress(b"".join(c[2] for c in chunks if c[1] == "IDAT"))
    except zlib.error as e:
        raise ToolError("IDAT 数据解压失败：%s" % e)
    nch = CHANNELS[ctype]
    bpp = max(1, nch * depth // 8)
    scale = 255 // ((1 << depth) - 1) if depth < 8 else 1

    def to_rgba(vals):
        if ctype == 0:
            v = vals[0] * scale
            return (v, v, v, 255)
        if ctype == 2:
            return (vals[0], vals[1], vals[2], 255)
        if ctype == 3:
            i = vals[0]
            r, g, b = palette[3 * i:3 * i + 3] if 3 * i + 3 <= len(palette) else (0, 0, 0)
            a = trns[i] if i < len(trns) else 255
            return (r, g, b, a)
        if ctype == 4:
            return (vals[0], vals[0], vals[0], vals[1])
        return tuple(vals[:4])

    def decode_pass(raw, pw, ph):
        row_bytes = (pw * nch * depth + 7) // 8
        flat, used = _unfilter(raw, pw, ph, bpp, row_bytes)
        rows = []
        for y in range(ph):
            s = _samples(flat[y * row_bytes:(y + 1) * row_bytes], depth, pw * nch)
            rows.append([to_rgba(s[x * nch:(x + 1) * nch]) for x in range(pw)])
        return rows, used

    info = {"位深": depth, "颜色类型": ctype, "隔行扫描": "Adam7" if interlace else "无"}
    if not interlace:
        rows, used = decode_pass(raw, w, h)
        pixels = [p for row in rows for p in row]
    else:
        pixels = [(0, 0, 0, 0)] * (w * h)
        passes = [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]
        pos = 0
        for x0, y0, dx, dy in passes:
            pw, ph = (w - x0 + dx - 1) // dx, (h - y0 + dy - 1) // dy
            if pw == 0 or ph == 0:
                continue
            rows, used = decode_pass(raw[pos:], pw, ph)
            pos += used
            for j, row in enumerate(rows):
                for i, p in enumerate(row):
                    pixels[(y0 + j * dy) * w + x0 + i * dx] = p
        used = pos
    if len(raw) > used:
        info["IDAT 解压后多余的字节"] = len(raw) - used
    return Image(w, h, pixels, "PNG", info)


def encode_png(width, height, pixels, mode="RGBA"):
    """编码 PNG。mode 为 RGBA、RGB 或 L（灰度，像素取 r）。"""
    nch = {"RGBA": 4, "RGB": 3, "L": 1}[mode]
    ctype = {"RGBA": 6, "RGB": 2, "L": 0}[mode]
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        row = pixels[y * width:(y + 1) * width]
        if nch == 1:
            raw += bytes(p[0] if isinstance(p, tuple) else p for p in row)
        else:
            for p in row:
                raw += bytes(p[:nch]) if len(p) >= nch else bytes(p) + b"\xff"
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (PNG_SIG + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, ctype, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


# ================================================================ BMP

def decode_bmp(data):
    if data[:2] != b"BM":
        raise ToolError("不是 BMP 文件")
    off = struct.unpack("<I", data[10:14])[0]
    hsize = struct.unpack("<I", data[14:18])[0]
    w, h = struct.unpack("<ii", data[18:26])
    bpp = struct.unpack("<H", data[28:30])[0]
    comp = struct.unpack("<I", data[30:34])[0]
    if comp not in (0, 3):
        raise ToolError("不支持压缩的 BMP")
    top_down = h < 0
    h = abs(h)
    palette = []
    if bpp <= 8:
        pal = data[14 + hsize:off]
        palette = [(pal[i + 2], pal[i + 1], pal[i], 255) for i in range(0, len(pal) - 3, 4)]
    row_bytes = (w * bpp + 31) // 32 * 4
    pixels = [None] * (w * h)
    for y in range(h):
        row = data[off + y * row_bytes:off + (y + 1) * row_bytes]
        yy = y if top_down else h - 1 - y
        for x in range(w):
            if bpp == 24:
                b, g, r = row[3 * x:3 * x + 3]
                p = (r, g, b, 255)
            elif bpp == 32:
                b, g, r, a = row[4 * x:4 * x + 4]
                p = (r, g, b, 255 if comp == 0 else a)
            elif bpp == 8:
                p = palette[row[x]]
            elif bpp in (1, 4):
                per = 8 // bpp
                v = (row[x // per] >> (8 - bpp * (x % per + 1))) & ((1 << bpp) - 1)
                p = palette[v]
            else:
                raise ToolError("不支持 %d 位 BMP" % bpp)
            pixels[yy * w + x] = p
    return Image(w, h, pixels, "BMP", {"位深": bpp, "像素数据偏移": off})


# ================================================================ GIF

def _lzw_decode(data, min_size):
    clear, end = 1 << min_size, (1 << min_size) + 1
    size = min_size + 1
    table = [bytes([i]) for i in range(clear)] + [b"", b""]
    out = bytearray()
    prev = None
    bit_pos, n = 0, len(data) * 8
    while bit_pos + size <= n:
        code = 0
        for i in range(size):                                    # 按位读取（低位在前）
            byte = data[(bit_pos + i) >> 3]
            code |= ((byte >> ((bit_pos + i) & 7)) & 1) << i
        bit_pos += size
        if code == clear:
            size = min_size + 1
            table = table[:clear + 2]
            prev = None
            continue
        if code == end:
            break
        if code < len(table):
            entry = table[code]
            if prev is not None:
                table.append(prev + entry[:1])
        elif prev is not None:
            entry = prev + prev[:1]
            table.append(entry)
        else:
            break
        out += entry
        prev = entry
        if len(table) == (1 << size) and size < 12:
            size += 1
    return bytes(out)


def decode_gif(data):
    if data[:3] != b"GIF":
        raise ToolError("不是 GIF 文件")
    w, h, flags, bg = struct.unpack("<HHBB", data[6:12])
    i = 13
    gct = []
    if flags & 0x80:
        n = 2 << (flags & 7)
        gct = [tuple(data[i + 3 * k:i + 3 * k + 3]) for k in range(n)]
        i += 3 * n
    canvas = [(0, 0, 0, 0)] * (w * h)
    frames, delay, transp = [], 0, None
    while i < len(data):
        b = data[i]
        if b == 0x21:                                            # 扩展块
            label = data[i + 1]
            i += 2
            blocks = bytearray()
            while data[i]:
                blocks += data[i + 1:i + 1 + data[i]]
                i += 1 + data[i]
            i += 1
            if label == 0xF9 and len(blocks) >= 4:
                delay = struct.unpack("<H", bytes(blocks[1:3]))[0]
                transp = blocks[3] if blocks[0] & 1 else None
        elif b == 0x2C:                                          # 图像
            fx, fy, fw, fh, fl = struct.unpack("<HHHHB", data[i + 1:i + 10])
            i += 10
            pal = gct
            if fl & 0x80:
                n = 2 << (fl & 7)
                pal = [tuple(data[i + 3 * k:i + 3 * k + 3]) for k in range(n)]
                i += 3 * n
            min_size = data[i]
            i += 1
            blocks = bytearray()
            while i < len(data) and data[i]:
                blocks += data[i + 1:i + 1 + data[i]]
                i += 1 + data[i]
            i += 1
            idx = _lzw_decode(bytes(blocks), min_size)
            rows = list(range(fh))
            if fl & 0x40:                                        # 隔行
                rows = list(range(0, fh, 8)) + list(range(4, fh, 8)) + list(range(2, fh, 4)) + list(range(1, fh, 2))
            canvas = list(canvas)
            for k, ci in enumerate(idx[:fw * fh]):
                if ci == transp or ci >= len(pal):
                    continue
                y = fy + rows[k // fw]
                x = fx + k % fw
                if x < w and y < h:
                    canvas[y * w + x] = pal[ci] + (255,)
            frame = Image(w, h, canvas, "GIF", {"停留时间（1/100 秒）": delay})
            frame.delay = delay
            frames.append(frame)
            delay, transp = 0, None
        elif b == 0x3B:
            break
        else:
            break
    if not frames:
        raise ToolError("GIF 中没有图像帧")
    img = frames[0]
    img.frames = frames
    img.info = {"帧数": len(frames), "尺寸": "%d × %d" % (w, h)}
    return img


def open_image(data):
    if not data:
        raise ToolError("请先上传图片")
    if data.startswith(PNG_SIG):
        return decode_png(data)
    if data[:2] == b"BM":
        return decode_bmp(data)
    if data[:3] == b"GIF":
        return decode_gif(data)
    if data[:3] == b"\xff\xd8\xff":
        raise ToolError("JPG 是有损压缩，浏览器与手机端不解码 JPG 像素。请用“JPG 结构”工具检查文件，或在 Docker 环境中用 steghide、stegseek 处理")
    raise ToolError("不支持的图片格式：目前支持 PNG、BMP、GIF")


def to_png(img, mode="RGBA"):
    return encode_png(img.width, img.height, img.pixels, mode)
