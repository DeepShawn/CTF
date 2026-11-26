"""流量分析（教材 1.2）：pcap / pcapng 解析、HTTP / DNS / FTP 提取、USB 键盘与鼠标还原。"""

import struct

from ..registry import ToolError, field, tool
from ..util import fields, file_out, find_flags, show, table


def parse_pcap(data):
    """解析 pcap 或 pcapng，返回数据包列表 [(时间戳, 链路层类型, 帧字节)]。"""
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        return _parse_classic(data)
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return _parse_pcapng(data)
    raise ToolError("不是 pcap / pcapng 文件")


def _parse_classic(data):
    le = data[:4] == b"\xd4\xc3\xb2\xa1"
    end = "<" if le else ">"
    linktype = struct.unpack(end + "I", data[20:24])[0]
    pkts, i = [], 24
    while i + 16 <= len(data):
        ts, tsu, caplen, origlen = struct.unpack(end + "IIII", data[i:i + 16])
        i += 16
        if i + caplen > len(data) or caplen > 262144:
            break
        pkts.append((ts + tsu / 1e6, linktype, data[i:i + caplen]))
        i += caplen
    return pkts


def _parse_pcapng(data):
    pkts, i = [], 0
    end = "<"
    linktype = 1
    while i + 12 <= len(data):
        btype, blen = struct.unpack(end + "II", data[i:i + 8])
        if blen < 12 or i + blen > len(data):
            break
        body = data[i + 8:i + blen - 4]
        if btype == 0x0A0D0D0A:
            end = "<" if data[i + 8:i + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        elif btype == 1:
            linktype = struct.unpack(end + "H", body[0:2])[0]
        elif btype == 6:
            caplen = struct.unpack(end + "I", body[12:16])[0]
            pkts.append((0, linktype, body[20:20 + caplen]))
        elif btype == 3:
            caplen = struct.unpack(end + "I", body[0:4])[0]
            pkts.append((0, linktype, body[4:4 + caplen]))
        i += blen
    return pkts


def eth_parse(frame, linktype):
    """返回 (协议, 源, 目的, 载荷)。只处理以太网 / IPv4 / TCP / UDP。"""
    if linktype == 1:
        if len(frame) < 14:
            return None
        etype = struct.unpack(">H", frame[12:14])[0]
        payload = frame[14:]
        if etype != 0x0800:
            return ("其他", "", "", payload)
    elif linktype == 101:
        payload = frame
    elif linktype in (113,):
        payload = frame[16:]
    else:
        return ("链路层%d" % linktype, "", "", frame)
    if len(payload) < 20:
        return None
    ihl = (payload[0] & 0xF) * 4
    proto = payload[9]
    src = ".".join(map(str, payload[12:16]))
    dst = ".".join(map(str, payload[16:20]))
    seg = payload[ihl:]
    if proto == 6 and len(seg) >= 20:
        sport, dport = struct.unpack(">HH", seg[0:4])
        doff = (seg[12] >> 4) * 4
        return ("TCP", "%s:%d" % (src, sport), "%s:%d" % (dst, dport), seg[doff:])
    if proto == 17 and len(seg) >= 8:
        sport, dport = struct.unpack(">HH", seg[0:4])
        return ("UDP", "%s:%d" % (src, sport), "%s:%d" % (dst, dport), seg[8:])
    if proto == 1:
        return ("ICMP", src, dst, seg[8:] if len(seg) >= 8 else b"")
    return ("IP/%d" % proto, src, dst, seg)


@tool(
    "forensics.pcap", "流量包分析", "forensics", "1.2",
    summary="打开 pcap / pcapng，统计协议与会话，提取 HTTP 文件、DNS 查询、ICMP 数据与所有字符串",
    principle="""
    pcap 文件记录了一段时间内的网络数据包。分析步骤：

    1. **看协议分布和会话**：知道有哪些主机在通信、用的什么协议；
    2. **追踪流**：把某条 TCP 连接的所有数据拼起来看完整内容（HTTP 请求响应、FTP 命令等）；
    3. **导出对象**：HTTP 传输的文件、图片；
    4. **搜 flag**：直接在全部载荷里搜 `flag{`。

    本工具相当于 Wireshark 的“协议分级 + 追踪流 + 导出对象”。常见考点：
    HTTP 上传 / 下载的文件、DNS 隧道（把数据拆进域名）、ICMP 载荷藏数据、WebShell 的 Base64 流量。
    大文件（超过几十 MB）建议在电脑上用 Wireshark。
    """,
    inputs=[field("file", "file", "pcap / pcapng 文件")],
    options=[field("view", "select", "查看", default="概览",
                   choices=["概览", "HTTP", "DNS", "ICMP 载荷", "搜索 flag", "全部字符串"])],
    keywords=["pcap", "wireshark", "流量", "tshark", "pcapng", "http", "dns"],
    live=False,
)
def pcap_tool(file=b"", view="概览"):
    if not file:
        raise ToolError("请先上传 pcap 文件")
    pkts = parse_pcap(file)
    if not pkts:
        raise ToolError("没有解析到数据包")
    parsed = [p for p in (eth_parse(f, lt) for _, lt, f in pkts) if p]
    if view == "概览":
        from collections import Counter
        protos = Counter(p[0] for p in parsed)
        convs = Counter()
        for proto, s, d, _ in parsed:
            if proto in ("TCP", "UDP"):
                convs[tuple(sorted([s, d]))] += 1
        return [fields([["数据包总数", len(pkts)], ["协议分布", "，".join("%s %d" % kv for kv in protos.most_common())]]),
                table(["会话（双方）", "包数"], [[" ↔ ".join(k), v] for k, v in convs.most_common(30)])]
    if view == "HTTP":
        return _http_view(parsed)
    if view == "DNS":
        rows = []
        for proto, s, d, payload in parsed:
            if proto == "UDP" and (":53" in d or ":53" in s) and len(payload) > 12:
                name = _dns_name(payload)
                if name:
                    rows.append([s, d, name])
        if not rows:
            return "没有找到 DNS 查询。"
        joined = "".join(r[2].split(".")[0] for r in rows)
        return [table(["源", "目的", "查询域名"], rows[:500]),
                fields([["各域名首段拼接（DNS 隧道常见）", joined[:500]]])]
    if view == "ICMP 载荷":
        rows, blob = [], bytearray()
        for proto, s, d, payload in parsed:
            if proto == "ICMP" and payload:
                rows.append([s, d, len(payload), show(payload[:40])])
                blob += payload
        if not rows:
            return "没有找到带载荷的 ICMP 包。"
        return [table(["源", "目的", "载荷长度", "载荷"], rows[:500]),
                fields([["所有载荷拼接", show(bytes(blob))[:500]], ["每包取首字节", show(bytes(p[0] for p in [pl for *_, pl in [(s, d, payload) for proto, s, d, payload in parsed if proto == "ICMP" and payload]]))[:200]]])]
    # 搜索 flag / 全部字符串
    import re
    alldata = b"\n".join(p[3] for p in parsed)
    if view == "搜索 flag":
        flags = find_flags(alldata.decode("latin-1"))
        return fields([["找到的 flag", "，".join(dict.fromkeys(flags)) or "无（试试“全部字符串”或先导出 HTTP 对象）"]])
    strings = sorted(set(m.group(0).decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{6,}", alldata)))
    return table(["字符串"], [[s[:300]] for s in strings[:2000]])


def _dns_name(payload):
    i, parts = 12, []
    while i < len(payload):
        ln = payload[i]
        if ln == 0 or ln & 0xC0:
            break
        parts.append(payload[i + 1:i + 1 + ln].decode("latin-1", "replace"))
        i += 1 + ln
    return ".".join(parts)


def _http_view(parsed):
    # 按 TCP 会话重组载荷
    streams = {}
    for proto, s, d, payload in parsed:
        if proto != "TCP" or not payload:
            continue
        streams.setdefault((s, d), bytearray()).extend(payload)
    out, rows = [], []
    from ..forensics.files import identify
    for (s, d), data in streams.items():
        data = bytes(data)
        if data[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ") or data.startswith(b"HTTP/"):
            line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            rows.append([s, d, line[:120]])
            # 导出响应体
            if b"\r\n\r\n" in data:
                body = data.split(b"\r\n\r\n", 1)[1]
                kind = identify(body[:64])
                if kind and kind[0][0] in ("png", "jpg", "gif", "zip", "pdf", "elf", "bmp", "gz"):
                    out.append(file_out(body, "http_object.%s" % kind[0][0], caption="%s → %s：%s" % (s, d, kind[0][1])))
    if not rows:
        return "没有找到 HTTP 流量。"
    return [table(["源", "目的", "请求 / 响应行"], rows[:300])] + out


# ---------------------------------------------------------------- USB 键盘 / 鼠标

USB_KEYS = {
    0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e", 0x09: "f", 0x0a: "g", 0x0b: "h", 0x0c: "i", 0x0d: "j",
    0x0e: "k", 0x0f: "l", 0x10: "m", 0x11: "n", 0x12: "o", 0x13: "p", 0x14: "q", 0x15: "r", 0x16: "s", 0x17: "t",
    0x18: "u", 0x19: "v", 0x1a: "w", 0x1b: "x", 0x1c: "y", 0x1d: "z",
    0x1e: "1", 0x1f: "2", 0x20: "3", 0x21: "4", 0x22: "5", 0x23: "6", 0x24: "7", 0x25: "8", 0x26: "9", 0x27: "0",
    0x28: "\n", 0x29: "[ESC]", 0x2a: "[BACKSPACE]", 0x2b: "\t", 0x2c: " ", 0x2d: "-", 0x2e: "=", 0x2f: "[",
    0x30: "]", 0x31: "\\", 0x33: ";", 0x34: "'", 0x35: "`", 0x36: ",", 0x37: ".", 0x38: "/",
}
USB_SHIFT = {"1": "!", "2": "@", "3": "#", "4": "$", "5": "%", "6": "^", "7": "&", "8": "*", "9": "(", "0": ")",
             "-": "_", "=": "+", "[": "{", "]": "}", "\\": "|", ";": ":", "'": "\"", "`": "~", ",": "<", ".": ">", "/": "?"}


def decode_usb_keyboard(reports):
    out = []
    for r in reports:
        if len(r) < 8:
            continue
        mod, key = r[0], r[2]
        if key == 0:
            continue
        ch = USB_KEYS.get(key)
        if ch is None:
            continue
        shift = mod & 0x22
        if shift and ch.isalpha():
            ch = ch.upper()
        elif shift and ch in USB_SHIFT:
            ch = USB_SHIFT[ch]
        if ch == "[BACKSPACE]":
            if out:
                out.pop()
        else:
            out.append(ch)
    return "".join(out)


@tool(
    "forensics.usb", "USB 流量还原", "forensics", "1.2.8",
    summary="从 USB HID 数据还原键盘输入（含大小写、退格）或画出鼠标轨迹",
    principle="""
    USB 键盘、鼠标通过 HID 报文传输按键和移动。题目通常用 `tshark` 把这些报文导出成一列十六进制，交给本工具还原。

    **键盘**：每个报文 8 字节，第 1 字节是修饰键（Shift 等），第 3 字节是按键编码
    （`0x04`=a、`0x05`=b……）。按编码查表就能还原输入，Shift 决定大小写和符号。

    **鼠标**：每个报文第 1 字节是按键，第 2、3 字节是 X、Y 的相对移动量（有符号）。
    把每一步累加画成轨迹图，常常画出 flag。

    **导出方法**：`tshark -r usb.pcap -T fields -e usbhid.data`（或 `usb.capdata`），
    把输出粘贴进来，一行一个报文。
    """,
    inputs=[field("text", "text", "USB HID 数据（每行一个报文，十六进制）", placeholder="00000400000000\n00000500000000")],
    options=[field("device", "segmented", "设备", default="键盘", choices=["键盘", "鼠标"])],
    keywords=["usb", "hid", "键盘", "鼠标", "tshark", "usbhid"],
    live=False,
)
def usb_tool(text, device="键盘"):
    import re
    reports = []
    for line in text.splitlines():
        h = re.sub(r"[^0-9a-fA-F]", "", line)
        if h:
            reports.append(bytes.fromhex(h) if len(h) % 2 == 0 else bytes.fromhex(h[:-1]))
    if not reports:
        raise ToolError("请粘贴 USB HID 数据，一行一个报文")
    if device == "键盘":
        # 有些报文第一个字节不是修饰键而是报文号，自动对齐到 8 字节
        norm = []
        for r in reports:
            if len(r) == 8:
                norm.append(r)
            elif len(r) > 8:
                norm.append(r[-8:])
            else:
                norm.append(r.rjust(8, b"\0"))
        typed = decode_usb_keyboard(norm)
        return fields([["还原的输入", typed], ["其中的 flag", "，".join(find_flags(typed)) or "无"]])
    # 鼠标：画轨迹
    x = y = 0
    pts = [(0, 0)]
    minx = miny = maxx = maxy = 0
    for r in reports:
        if len(r) < 3:
            continue
        dx = r[1] - 256 if r[1] > 127 else r[1]
        dy = r[2] - 256 if r[2] > 127 else r[2]
        x += dx
        y += dy
        pts.append((x, y))
        minx, maxx, miny, maxy = min(minx, x), max(maxx, x), min(miny, y), max(maxy, y)
    w, h = maxx - minx + 1, maxy - miny + 1
    if w * h > 4_000_000 or w <= 0 or h <= 0:
        raise ToolError("轨迹范围异常（%d × %d），数据可能不是鼠标报文" % (w, h))
    from ..imagelib import encode_png
    from ..util import image
    scale = max(1, min(4, 1200 // max(w, h)))
    canvas = [(255, 255, 255)] * (w * scale * h * scale)
    for px, py in pts:
        cx, cy = (px - minx) * scale, (py - miny) * scale
        for a in range(scale):
            for b in range(scale):
                idx = (cy + b) * w * scale + cx + a
                if 0 <= idx < len(canvas):
                    canvas[idx] = (15, 107, 99)
    return [image(encode_png(w * scale, h * scale, canvas, "RGB"), "image/png", "鼠标轨迹（%d × %d）" % (w, h)),
            fields([["报文数", len(reports)], ["轨迹范围", "%d × %d" % (w, h)]])]
