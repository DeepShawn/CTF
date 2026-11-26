"""工业控制系统安全（教材第 8 章）：Modbus / S7 报文解析、梯形图与指令表速查、协议速查。"""

import struct

from ..registry import ToolError, field, text_input, tool
from ..util import fields, table

# ---------------------------------------------------------------- Modbus

MODBUS_FUNC = {
    1: "读线圈", 2: "读离散输入", 3: "读保持寄存器", 4: "读输入寄存器", 5: "写单个线圈", 6: "写单个寄存器",
    15: "写多个线圈", 16: "写多个寄存器", 22: "屏蔽写寄存器", 23: "读写多个寄存器", 43: "读设备标识",
}


def parse_modbus_pdu(func, data):
    """解析 Modbus PDU（功能码之后的部分）。"""
    if func == 6 and len(data) >= 4:
        addr, val = struct.unpack(">HH", data[:4])
        return "写寄存器 %d = %d (0x%04x)" % (addr, val, val)
    if func == 5 and len(data) >= 4:
        addr, val = struct.unpack(">HH", data[:4])
        return "写线圈 %d = %s" % (addr, "ON" if val == 0xFF00 else "OFF")
    if func in (3, 4) and len(data) >= 4:
        addr, cnt = struct.unpack(">HH", data[:4])
        return "读寄存器 起始 %d，数量 %d" % (addr, cnt)
    if func in (1, 2) and len(data) >= 4:
        addr, cnt = struct.unpack(">HH", data[:4])
        return "读 起始 %d，数量 %d" % (addr, cnt)
    if func == 16 and len(data) >= 5:
        addr, cnt, nbytes = struct.unpack(">HHB", data[:5])
        vals = [struct.unpack(">H", data[5 + 2 * i:7 + 2 * i])[0] for i in range(min(cnt, (len(data) - 5) // 2))]
        return "写多个寄存器 起始 %d，数量 %d，值 %s" % (addr, cnt, vals)
    if func & 0x80:
        return "异常响应，异常码 %d" % (data[0] if data else 0)
    return "数据 " + data.hex()


@tool(
    "ics.modbus", "Modbus 报文解析", "ics", "8.2.0",
    summary="解析 Modbus/TCP 报文，识别功能码、寄存器地址与读写的值",
    principle="""
    Modbus 是最常见的工控协议。Modbus/TCP 报文结构：

    | 字段 | 说明 |
    |---|---|
    | 事务 ID（2） | 请求与响应配对 |
    | 协议 ID（2） | 固定 0 |
    | 长度（2） | 后面的字节数 |
    | 单元 ID（1） | 从站地址 |
    | 功能码（1） | 3=读保持寄存器、6=写单个寄存器、16=写多个寄存器…… |
    | 数据 | 寄存器地址、数量、值 |

    **工控流量题常见考法**：从一连串 Modbus 写操作里，按寄存器地址或写入的值拼出 flag
    （比如每次往某个寄存器写一个 ASCII 码）。把 `tshark -r x.pcap -T fields -e modbus.xxx` 或
    每个报文的十六进制粘进来即可。
    """,
    inputs=[text_input("Modbus 报文（十六进制，一行一个）", placeholder="00010000000601060001006d")],
    examples=[{"text": "000100000006010600010066\n00020000000601060002006c\n000300000006010600030061\n000400000006010600040067"}],
    keywords=["modbus", "工控", "scada", "plc", "寄存器"],
    live=False,
)
def modbus_tool(text):
    import re
    rows = []
    written = {}
    for line in text.splitlines():
        h = re.sub(r"[^0-9a-fA-F]", "", line)
        if not h:
            continue
        try:
            data = bytes.fromhex(h)
        except ValueError:
            continue
        if len(data) >= 8 and data[2:4] == b"\x00\x00":    # 带 MBAP 头的 Modbus/TCP
            tid, pid, length, unit, func = struct.unpack(">HHHBB", data[:8])
            pdu = data[8:]
        elif len(data) >= 2:                                # 裸 PDU
            func = data[0]
            pdu = data[1:]
            unit = "-"
        else:
            continue
        desc = parse_modbus_pdu(func, pdu)
        rows.append([unit, "%d %s" % (func & 0x7f, MODBUS_FUNC.get(func & 0x7f, "?")), desc])
        if func in (6, 5) and len(pdu) >= 4:
            a, v = struct.unpack(">HH", pdu[:4])
            written[a] = v
    if not rows:
        raise ToolError("没有解析到 Modbus 报文，请粘贴十六进制")
    out = [table(["单元 ID", "功能码", "内容"], rows)]
    if written:
        # 尝试把写入的值按地址顺序拼成 ASCII
        ascii_vals = "".join(chr(v & 0xFF) for _, v in sorted(written.items()) if 32 <= (v & 0xFF) < 127)
        if ascii_vals:
            out.append(fields([["按寄存器地址顺序，写入值的低字节拼成 ASCII", ascii_vals]]))
    return out


# ---------------------------------------------------------------- S7

@tool(
    "ics.s7", "S7 报文解析", "ics", "8.2.1",
    summary="解析西门子 S7comm 报文，识别作业类型与读写区域",
    principle="""
    S7comm 是西门子 PLC 使用的协议，跑在 TPKT + COTP 之上（端口 102）。S7comm 报文：

    - 协议 ID `0x32`；
    - 消息类型：1=作业请求、2=确认、3=确认带数据、7=用户数据；
    - 功能：0x04=读变量、0x05=写变量、0xf0=建立通信。

    读写变量时会指定区域（DB 数据块、M 位存储器、I 输入、Q 输出）和地址。
    和 Modbus 一样，题目常把 flag 拆进多次读写里。粘贴 S7comm 层的十六进制即可。
    """,
    inputs=[text_input("S7comm 报文（十六进制）", placeholder="32010000...")],
    examples=[{"text": "320100000400000e00000401120a10020001000084000000"}],
    keywords=["s7", "s7comm", "西门子", "plc", "工控"],
    live=False,
)
def s7_tool(text):
    import re
    types = {1: "作业请求", 2: "确认", 3: "确认带数据", 7: "用户数据"}
    funcs = {0x04: "读变量", 0x05: "写变量", 0xf0: "建立通信", 0x1a: "下载", 0x1b: "下载块", 0x1d: "上传",
             0x28: "PLC 启动", 0x29: "PLC 停止"}
    areas = {0x81: "I 输入", 0x82: "Q 输出", 0x83: "M 位存储器", 0x84: "DB 数据块", 0x1c: "计数器", 0x1d: "定时器"}
    rows = []
    for line in text.splitlines():
        h = re.sub(r"[^0-9a-fA-F]", "", line)
        if not h:
            continue
        data = bytes.fromhex(h)
        i = data.find(b"\x32")                              # 找 S7 协议 ID
        if i < 0 or i + 10 > len(data):
            rows.append(["-", "没有找到 S7 协议头 0x32", ""])
            continue
        s7 = data[i:]
        msgtype = s7[1]
        # 参数区在头部之后：作业请求头 10 字节，参数第 1 字节是功能码
        plen = struct.unpack(">H", s7[6:8])[0] if len(s7) >= 8 else 0
        param_start = 12 if msgtype == 7 else 10
        func = s7[param_start] if len(s7) > param_start else 0
        desc = ""
        for a, name in areas.items():                      # 读 / 写变量时在参数里找区域字节
            pos = s7.find(bytes([a]), param_start, param_start + plen + 2)
            if pos >= 0:
                desc = "区域：%s" % name
                break
        rows.append([types.get(msgtype, msgtype), funcs.get(func, "0x%02x" % func), desc])
    if not rows:
        raise ToolError("没有解析到 S7 报文")
    return table(["消息类型", "功能", "说明"], rows)


# ---------------------------------------------------------------- 梯形图 / 指令表 / 协议速查

LADDER = [
    ["—| |—", "常开触点", "LD / A（与）/ O（或）"],
    ["—|/|—", "常闭触点", "LDI / ANI / ORI"],
    ["—( )—", "线圈输出", "OUT"],
    ["—(S)—", "置位", "SET"],
    ["—(R)—", "复位", "RST"],
    ["—|↑|—", "上升沿", "LDP"],
    ["TON", "定时器（通电延时）", "OUT T / TON"],
    ["CTU", "加计数器", "OUT C / CTU"],
]

PROTOCOLS = [
    ["Modbus", "502", "最常见，功能码 + 寄存器；有 TCP 和 RTU（串口）两种"],
    ["S7comm", "102", "西门子，跑在 TPKT/COTP 上"],
    ["DNP3", "20000", "电力行业，北美常见"],
    ["IEC 60870-5-104", "2404", "电力，欧洲常见"],
    ["EtherNet/IP", "44818 / 2222", "Rockwell / Allen-Bradley"],
    ["BACnet", "47808", "楼宇自动化"],
    ["OPC UA", "4840", "通用工业通信"],
    ["Profinet", "34962-34964", "西门子工业以太网"],
]


@tool(
    "ics.reference", "工控速查", "ics", "8.1",
    summary="梯形图符号与指令表对照、常见工控协议与端口",
    principle="""
    工控 CTF 需要看懂梯形图（PLC 编程语言）和识别协议。

    **梯形图**：像电路图，左右两条竖线是电源，中间是触点和线圈。常开触点 `—| |—` 导通时输出，
    常闭触点 `—|/|—` 相反。每种符号对应一条指令表语句（LD、AND、OUT 等）。

    **协议识别**：看端口和特征字节，502 是 Modbus，102 是西门子 S7。
    """,
    inputs=[field("text", "string", "查询（可选）", default="")],
    options=[field("view", "segmented", "查看", default="梯形图符号", choices=["梯形图符号", "工控协议"])],
    examples=[{"view": "工控协议"}],
    keywords=["梯形图", "指令表", "plc", "modbus", "协议", "端口"],
)
def reference_tool(text="", view="梯形图符号"):
    if view == "工控协议":
        rows = [r for r in PROTOCOLS if not text or text.lower() in r[0].lower() or text in r[1]]
        return table(["协议", "默认端口", "说明"], rows)
    rows = [r for r in LADDER if not text or any(text.lower() in str(c).lower() for c in r)]
    return table(["符号", "含义", "指令表"], rows)
