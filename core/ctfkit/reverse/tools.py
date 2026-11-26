"""逆向辅助工具（教材第 5 章）：ELF / PE 结构、算法特征识别、汇编速查、pyc 版本。"""

import re
import struct

from ..registry import ToolError, field, tool
from ..util import fields, table

# ---------------------------------------------------------------- 算法常量特征

SIGNATURES = [
    ("MD5 初始值", [b"\x01\x23\x45\x67", b"\x89\xab\xcd\xef"], "MD5 / MD4 的 A=0x67452301 等初始化常量"),
    ("MD5 常量表", [b"\x78\xa4\x6a\xd7"], "MD5 的 K[0]=0xd76aa478（sin 表）"),
    ("SHA-1 初始值", [b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98"], "SHA-1 的 H 初始值"),
    ("SHA-256 初始值", [b"\x67\xe6\x09\x6a"], "SHA-256 的 H0=0x6a09e667（小端）"),
    ("SHA-256 常量", [b"\x98\x2f\x8a\x42"], "SHA-256 的 K[0]=0x428a2f98"),
    ("AES S 盒", [b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5"], "AES 的 S 盒前几字节 63 7c 77 7b..."),
    ("AES 逆 S 盒", [b"\x52\x09\x6a\xd5"], "AES 的逆 S 盒 52 09 6a d5..."),
    ("AES Rcon", [b"\x01\x02\x04\x08\x10\x20\x40\x80\x1b\x36"], "AES 轮常量"),
    ("DES / 初始置换", [b"\x3a\x32\x2a\x22"], "DES 的 IP 置换表特征（58,50,42,34 → 索引）"),
    ("Base64 标准表", [b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"], "标准 Base64 码表"),
    ("CRC32 表", [b"\x00\x00\x00\x00\x96\x30\x07\x77"], "CRC32 查找表（多项式 0xEDB88320）"),
    ("TEA / XTEA delta", [b"\xb9\x79\x37\x9e"], "TEA 系列的 delta=0x9e3779b9（黄金分割）"),
    ("RC4 标志", [b"\x00\x01\x02\x03\x04\x05\x06\x07"], "可能是 RC4 的 S 盒初始化 0,1,2,3..."),
]


@tool(
    "reverse.algo", "算法特征识别", "reverse", "5.2.2",
    summary="在二进制中搜索 MD5 / SHA / AES / DES / TEA / Base64 等算法的特征常量",
    principle="""
    逆向时识别出用了什么标准算法，能省下大量时间。这些算法都有固定的常量，在二进制里搜这些常量就能认出来：

    | 算法 | 特征常量 |
    |---|---|
    | MD5 | 初始值 `67452301`，sin 常量表 `d76aa478...` |
    | SHA-256 | 初始值 `6a09e667`，K 表 `428a2f98...` |
    | AES | S 盒 `63 7c 77 7b...`，Rcon `01 02 04 08...` |
    | TEA / XTEA | delta `9e3779b9`（黄金分割数） |
    | Base64 | 码表 `ABC...xyz0-9+/`（换表时就能看到新码表） |
    | CRC32 | 查找表 `00000000 77073096...` |

    找到后，用对应的工具（哈希、AES、XOR 等）处理，或按标准算法反推。相当于 IDA 的 FindCrypt 插件。
    """,
    inputs=[field("file", "file", "二进制文件")],
    keywords=["findcrypt", "算法", "特征", "md5", "aes", "tea", "常量", "signature"],
    live=False,
)
def algo_tool(file=b""):
    if not file:
        raise ToolError("请上传文件")
    rows = []
    for name, patterns, desc in SIGNATURES:
        for pat in patterns:
            idx = file.find(pat)
            if idx >= 0:
                rows.append([name, "0x%X" % idx, desc])
                break
    # 找可能的换表 Base64：64 个不重复可打印字符
    for m in re.finditer(rb"[A-Za-z0-9+/=_\-]{64}", file):
        s = m.group(0)
        if len(set(s)) == 64:
            rows.append(["可能的 Base64 码表", "0x%X" % m.start(), s.decode("latin-1")])
    if not rows:
        return "没有识别到常见算法的特征常量。可以用“字符串提取”看看有没有线索，或手动分析。"
    return table(["算法", "偏移", "说明"], rows)


# ---------------------------------------------------------------- ELF / PE 结构

def parse_elf(data):
    e = "<" if data[5] == 1 else ">"
    is64 = data[4] == 2
    bits = 64 if is64 else 32
    etype, machine = struct.unpack(e + "HH", data[16:20])
    entry = struct.unpack(e + ("Q" if is64 else "I"), data[24:24 + (8 if is64 else 4)])[0]
    machines = {0x3e: "x86-64", 0x03: "x86", 0xb7: "AArch64", 0x28: "ARM", 0x08: "MIPS", 0xf3: "RISC-V"}
    # section headers
    if is64:
        shoff = struct.unpack(e + "Q", data[40:48])[0]
        shentsize, shnum, shstrndx = struct.unpack(e + "HHH", data[58:64])
    else:
        shoff = struct.unpack(e + "I", data[32:36])[0]
        shentsize, shnum, shstrndx = struct.unpack(e + "HHH", data[46:52])
    sections = []
    if shoff and shstrndx < shnum:
        strtab_hdr = shoff + shstrndx * shentsize
        if is64:
            stroff = struct.unpack(e + "Q", data[strtab_hdr + 24:strtab_hdr + 32])[0]
        else:
            stroff = struct.unpack(e + "I", data[strtab_hdr + 16:strtab_hdr + 20])[0]
        for i in range(min(shnum, 60)):
            base = shoff + i * shentsize
            nameoff = struct.unpack(e + "I", data[base:base + 4])[0]
            name = data[stroff + nameoff:data.find(b"\0", stroff + nameoff)].decode("latin-1", "replace")
            if is64:
                addr = struct.unpack(e + "Q", data[base + 16:base + 24])[0]
                size = struct.unpack(e + "Q", data[base + 32:base + 40])[0]
            else:
                addr = struct.unpack(e + "I", data[base + 12:base + 16])[0]
                size = struct.unpack(e + "I", data[base + 20:base + 24])[0]
            if name:
                sections.append([name, "0x%X" % addr, size])
    return {"格式": "ELF", "架构": machines.get(machine, "0x%x" % machine), "位数": bits,
            "类型": {1: "可重定位 .o", 2: "可执行", 3: "共享库 / PIE", 4: "core"}.get(etype, etype),
            "入口点": "0x%X" % entry}, sections


def parse_pe(data):
    pe = struct.unpack("<I", data[0x3c:0x40])[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ToolError("不是有效的 PE 文件")
    machine, nsec = struct.unpack("<HH", data[pe + 4:pe + 8])
    opt = pe + 24
    magic = struct.unpack("<H", data[opt:opt + 2])[0]
    is64 = magic == 0x20b
    entry = struct.unpack("<I", data[opt + 16:opt + 20])[0]
    machines = {0x8664: "x86-64", 0x14c: "x86", 0xaa64: "ARM64", 0x1c0: "ARM"}
    secbase = opt + (240 if is64 else 224)
    sections = []
    for i in range(min(nsec, 40)):
        base = secbase + i * 40
        name = data[base:base + 8].rstrip(b"\0").decode("latin-1", "replace")
        vsize, vaddr = struct.unpack("<II", data[base + 8:base + 16])
        sections.append([name, "0x%X" % vaddr, vsize])
    return {"格式": "PE（Windows）", "架构": machines.get(machine, "0x%x" % machine),
            "位数": 64 if is64 else 32, "入口点 RVA": "0x%X" % entry}, sections


@tool(
    "reverse.fileinfo", "ELF / PE 结构", "reverse", "5.2.0",
    summary="读取可执行文件的架构、位数、入口点与节表",
    principle="""
    逆向第一步是看文件的基本信息：什么架构（x86 / ARM）、多少位、从哪里开始执行、有哪些节（section）。

    - **ELF**（Linux）：`.text` 代码、`.data` 数据、`.rodata` 只读数据（字符串常在这）、`.bss` 未初始化数据；
    - **PE**（Windows）：`.text`、`.data`、`.rdata`、`.rsrc` 资源。

    节的名字被改过（如加壳后变成 `UPX0`、`UPX1`）往往说明加了壳。相当于 `readelf -h -S` 或 `objdump -h`。
    """,
    inputs=[field("file", "file", "ELF / PE 文件")],
    keywords=["elf", "pe", "readelf", "节", "section", "入口点"],
    live=False,
)
def fileinfo_tool(file=b""):
    if not file:
        raise ToolError("请上传文件")
    if file[:4] == b"\x7fELF":
        info, sections = parse_elf(file)
    elif file[:2] == b"MZ":
        info, sections = parse_pe(file)
    else:
        raise ToolError("不是 ELF 或 PE 文件（文件头应为 7F 45 4C 46 或 4D 5A）")
    out = [fields(list(info.items()))]
    if sections:
        packer = [s[0] for s in sections if re.match(r"UPX|\.upx|aspack|\.petite|\.nsp", s[0], re.I)]
        if packer:
            out.append(fields([["提示", "节名 %s 说明可能加了壳，需要先脱壳（如 upx -d）" % "、".join(packer)]]))
        out.append(table(["节名", "地址 / RVA", "大小"], sections))
    return out


# ---------------------------------------------------------------- pyc 版本

PYC_MAGIC = {
    b"\x03\xf3": "2.7", b"\xee\x0c": "3.4", b"\x16\x0d": "3.5", b"\x17\x0d": "3.5.3+", b"\x33\x0d": "3.6",
    b"\x42\x0d": "3.7", b"\x55\x0d": "3.8", b"\x61\x0d": "3.9", b"\x6f\x0d": "3.10", b"\xa7\x0d": "3.11",
    b"\xcb\x0d": "3.12", b"\xf3\x0d": "3.13",
}


@tool(
    "reverse.pyc", "pyc 文件识别", "reverse", "5",
    summary="识别 Python 字节码文件的版本，给出反编译命令",
    principle="""
    `.pyc` 是 Python 编译后的字节码。开头 2 字节的魔数决定 Python 版本，必须用对应版本的工具反编译：

    - Python 3.8 及以下：`uncompyle6`；
    - 较新版本：`decompyle3`、`pycdc`（C++ 写的，支持到 3.12）。

    如果 pyc 开头的魔数被抹掉了，可以根据已知版本补上。本工具识别版本并给出命令。反编译本身请在 Docker 环境中进行。
    """,
    inputs=[field("file", "file", ".pyc 文件")],
    keywords=["pyc", "python", "字节码", "uncompyle", "反编译", "pycdc"],
    live=False,
)
def pyc_tool(file=b""):
    if not file:
        raise ToolError("请上传 .pyc 文件")
    magic = file[:2]
    ver = PYC_MAGIC.get(magic, "未知")
    rows = [["魔数", file[:4].hex()], ["Python 版本", ver]]
    if ver != "未知":
        tool_name = "uncompyle6" if ver <= "3.8" else "pycdc 或 decompyle3"
        rows.append(["反编译命令", "%s file.pyc" % tool_name])
        rows.append(["在线", "可用 pydisasm 查看字节码"])
    else:
        rows.append(["提示", "魔数可能被修改。常见：55 0d=3.8，61 0d=3.9，6f 0d=3.10，a7 0d=3.11"])
    return fields(rows)


# ---------------------------------------------------------------- 汇编速查

ASM = {
    "寄存器（x86-64）": [["rax", "返回值 / 累加器"], ["rdi, rsi, rdx, rcx, r8, r9", "函数前 6 个参数（System V）"],
                    ["rsp", "栈顶指针"], ["rbp", "栈基址"], ["rip", "指令指针"]],
    "调用约定": [["Linux x64", "参数：rdi rsi rdx rcx r8 r9，返回：rax，系统调用号：rax"],
             ["Windows x64", "参数：rcx rdx r8 r9，返回：rax"],
             ["x86 cdecl", "参数全部压栈（从右到左），调用者清栈"]],
    "常用指令": [["mov a, b", "a = b"], ["lea a, [b]", "a = b 的地址"], ["push / pop", "压栈 / 出栈"],
             ["call / ret", "调用 / 返回"], ["cmp a, b; je", "比较后相等跳转"], ["xor a, a", "把 a 清零"],
             ["test a, a; jz", "a 为 0 则跳转"]],
}


@tool(
    "reverse.asm", "汇编速查", "reverse", "5.3.1",
    summary="x86 / x64 常用寄存器、调用约定、指令速查",
    principle="读汇编时最常查的几张表：寄存器用途、函数参数怎么传、常见指令什么意思。",
    inputs=[field("text", "string", "查询（可选）", default="")],
    options=[field("view", "select", "查看", default="寄存器（x86-64）", choices=list(ASM))],
    examples=[{"view": "调用约定"}],
    keywords=["汇编", "asm", "寄存器", "调用约定", "x86", "x64"],
)
def asm_tool(text="", view="寄存器（x86-64）"):
    rows = [r for r in ASM[view] if not text or any(text.lower() in str(c).lower() for c in r)]
    return table(["", ""], rows)
