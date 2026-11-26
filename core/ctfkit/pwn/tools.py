"""PWN 辅助工具（教材第 6～7 章）：cyclic 偏移、打包解包、checksec、格式化字符串载荷、
ret2libc 计算、shellcode 速查、safe-linking、堆结构。这些是纯计算，实际调试请在 Docker 环境中进行。"""

import re
import struct

from ..registry import ToolError, field, tool
from ..util import fields, parse_hex, parse_int, table

# ---------------------------------------------------------------- cyclic

ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def de_bruijn(n, alphabet=ALPHABET):
    """生成 de Bruijn 序列：任意 n 个连续字符都唯一，用于定位溢出偏移。"""
    k = len(alphabet)
    a = [0] * k * n
    seq = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return "".join(alphabet[i] for i in seq)


def cyclic(length, n=4):
    seq = de_bruijn(n)
    while len(seq) < length:
        seq += seq
    return seq[:length]


def cyclic_find(sub, n=4):
    full = cyclic(0x10000, n)
    if len(sub) == n:
        return full.find(sub)
    return -1


@tool(
    "pwn.cyclic", "cyclic 偏移计算", "pwn", "6.2.3",
    summary="生成不重复的模式串，或由崩溃时覆盖的值反查溢出偏移",
    principle="""
    栈溢出要先知道从缓冲区到返回地址有多少字节（偏移）。用 **cyclic（de Bruijn 序列）**最快：

    1. 生成一段任意 4（或 8）个连续字符都唯一的字符串，当作输入；
    2. 程序崩溃，用调试器看返回地址 / EIP / RSP 被覆盖成了哪 4（或 8）个字节；
    3. 在序列中查这几个字节出现的位置，就是偏移。

    pwntools 里对应 `cyclic(200)` 和 `cyclic_find(0x61616164)`。
    64 位程序用“字组 8”，因为地址是 8 字节。
    """,
    inputs=[field("text", "string", "长度 / 要查找的值", default="200")],
    options=[field("action", "segmented", "操作", default="生成", choices=["生成", "查找偏移"]),
             field("n", "segmented", "字组大小", default="4", choices=["4", "8"])],
    examples=[{"text": "200", "action": "生成"}, {"text": "0x6161616b", "action": "查找偏移", "n": "4"},
              {"text": "kaaa", "action": "查找偏移"}],
    keywords=["cyclic", "de bruijn", "偏移", "offset", "pattern"],
)
def cyclic_tool(text, action="生成", n="4"):
    nn = int(n)
    if action == "生成":
        length = parse_int(text, "长度")
        if length > 1_000_000:
            raise ToolError("长度过大")
        return cyclic(length, nn)
    s = text.strip()
    if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", s) and s.lower().startswith("0x") or re.fullmatch(r"[0-9]+", s) and int(s) > 0x10000:
        val = parse_int(s, "值")
        sub = val.to_bytes(nn, "little").decode("latin-1")   # 寄存器里是小端
    else:
        sub = s
    if len(sub) != nn:
        raise ToolError("查找的子串应为 %d 个字符（或 %d 字节的值）" % (nn, nn))
    off = cyclic_find(sub, nn)
    if off < 0:
        raise ToolError("在序列中没有找到，确认字组大小是否正确")
    return fields([["偏移", off], ["说明", "从输入开头到被覆盖位置共 %d 字节；payload = b'A'*%d + 目标地址" % (off, off)]])


# ---------------------------------------------------------------- 打包 / 解包

@tool(
    "pwn.pack", "打包 / 解包（p32 / p64）", "pwn", "6.2.3",
    summary="整数与字节互转，等价于 pwntools 的 p32 / p64 / u32 / u64",
    principle="""
    PWN 中要把地址写成字节发给程序。地址在内存里是**小端序**（低字节在前），如地址 `0x400586`
    发送的字节是 `86 05 40 00`。pwntools 用 `p32(0x400586)` / `p64(...)` 打包，`u32(data)` / `u64(...)` 解包。
    """,
    inputs=[field("text", "string", "整数 / 十六进制字节", default="0x400586")],
    options=[field("action", "segmented", "操作", default="打包（整数→字节）", choices=["打包（整数→字节）", "解包（字节→整数）"]),
             field("bits", "segmented", "位数", default="64", choices=["32", "64"]),
             field("endian", "segmented", "字节序", default="小端", choices=["小端", "大端"])],
    examples=[{"text": "0x400586", "action": "打包（整数→字节）", "bits": "64"},
              {"text": "86 05 40 00", "action": "解包（字节→整数）", "bits": "32"}],
    keywords=["p32", "p64", "u32", "u64", "pack", "打包", "小端"],
)
def pack_tool(text, action="打包（整数→字节）", bits="64", endian="小端"):
    nbytes = int(bits) // 8
    e = "<" if endian == "小端" else ">"
    if action.startswith("打包"):
        v = parse_int(text, "整数")
        if v >= 1 << int(bits) or v < 0:
            raise ToolError("数值超出 %s 位范围" % bits)
        data = v.to_bytes(nbytes, "little" if endian == "小端" else "big")
        return fields([["字节（十六进制）", data.hex()], ["Python 字节串", repr(data)],
                       ["\\x 形式", "".join("\\x%02x" % b for b in data)]])
    data = parse_hex(text)
    if len(data) > nbytes:
        data = data[:nbytes]
    data = data.ljust(nbytes, b"\0")
    return fields([["整数", str(struct.unpack(e + {4: "I", 8: "Q"}[nbytes], data)[0])],
                   ["十六进制", hex(struct.unpack(e + {4: "I", 8: "Q"}[nbytes], data)[0])]])


# ---------------------------------------------------------------- checksec

def read_elf_header(data):
    if data[:4] != b"\x7fELF":
        raise ToolError("不是 ELF 文件")
    is64 = data[4] == 2
    le = data[5] == 1
    e = "<" if le else ">"
    bits = 64 if is64 else 32
    off = 16
    etype, machine = struct.unpack(e + "HH", data[off:off + 4])
    if is64:
        phoff = struct.unpack(e + "Q", data[32:40])[0]
        phentsize, phnum = struct.unpack(e + "HH", data[54:58])
    else:
        phoff = struct.unpack(e + "I", data[28:32])[0]
        phentsize, phnum = struct.unpack(e + "HH", data[42:46])
    machines = {0x3e: "x86-64", 0x03: "x86", 0xb7: "AArch64", 0x28: "ARM", 0x08: "MIPS"}
    return {"bits": bits, "e": e, "is64": is64, "etype": etype, "machine": machines.get(machine, "0x%x" % machine),
            "phoff": phoff, "phentsize": phentsize, "phnum": phnum}


def checksec(data):
    h = read_elf_header(data)
    e, is64 = h["e"], h["is64"]
    segs = []
    for i in range(h["phnum"]):
        base = h["phoff"] + i * h["phentsize"]
        if is64:
            ptype, flags = struct.unpack(e + "II", data[base:base + 8])
            voff = struct.unpack(e + "Q", data[base + 8:base + 16])[0]
            fsz = struct.unpack(e + "Q", data[base + 32:base + 40])[0]
        else:
            ptype = struct.unpack(e + "I", data[base:base + 4])[0]
            voff = struct.unpack(e + "I", data[base + 4:base + 8])[0]
            flags = struct.unpack(e + "I", data[base + 24:base + 28])[0]
            fsz = struct.unpack(e + "I", data[base + 16:base + 20])[0]
        segs.append((ptype, flags, voff, fsz))
    # NX: 有没有 GNU_STACK（ptype 0x6474e551）且不可执行
    nx = True
    for ptype, flags, _, _ in segs:
        if ptype == 0x6474E551:
            nx = not (flags & 1)
    # PIE: etype == 3 (ET_DYN)
    pie = h["etype"] == 3
    # RELRO
    relro = "无"
    for ptype, _, _, _ in segs:
        if ptype == 0x6474E552:   # GNU_RELRO
            relro = "部分"
    canary = b"__stack_chk_fail" in data
    # Full RELRO 的粗略判断：有 GNU_RELRO 段，且导入表里没有延迟绑定的迹象（这里保守地标为部分）
    fortify = b"__printf_chk" in data or b"__memcpy_chk" in data or b"__strcpy_chk" in data
    return h, {"NX（栈不可执行）": "开启" if nx else "关闭", "Canary（栈保护）": "开启" if canary else "关闭",
               "PIE（地址随机化）": "开启" if pie else "关闭", "RELRO": relro + " RELRO" if relro != "无" else "无",
               "FORTIFY": "开启" if fortify else "未检测到"}


@tool(
    "pwn.checksec", "checksec", "pwn", "6.2.2",
    summary="读取 ELF 文件，检查 NX、Canary、PIE、RELRO 等保护机制",
    principle="""
    拿到 PWN 题目的二进制文件，先看开了哪些保护，再决定利用方法：

    | 保护 | 开启后 | 常见应对 |
    |---|---|---|
    | NX | 栈上数据不能执行 | ROP、ret2libc 复用已有代码 |
    | Canary | 返回地址前有随机值，被改会终止 | 先泄露 canary 再溢出 |
    | PIE | 程序每次加载到随机地址 | 先泄露一个程序内地址算基址 |
    | RELRO | Full 时 GOT 表只读 | 改为打 返回地址 / hook |

    相当于命令 `checksec --file=./pwn`。本工具通过解析 ELF 头和符号表判断，与 pwntools 的 checksec 基本一致。
    """,
    inputs=[field("file", "file", "ELF 文件")],
    keywords=["checksec", "nx", "canary", "pie", "relro", "elf", "保护"],
    live=False,
)
def checksec_tool(file=b""):
    if not file:
        raise ToolError("请上传 ELF 文件")
    h, sec = checksec(file)
    return fields([["架构", "%s（%d 位）" % (h["machine"], h["bits"])],
                   ["类型", {1: "可重定位", 2: "可执行（无 PIE）", 3: "共享对象 / PIE"}.get(h["etype"], h["etype"])]]
                  + list(sec.items()))


# ---------------------------------------------------------------- 格式化字符串

def _build_fmt(order, chunks, sz, sign, slots):
    """给定各写入块所在的参数槽位，生成格式串部分。"""
    fmt = b""
    written = 0
    for rank, i in enumerate(order):
        delta = (chunks[i] - written) % (1 << (8 * sz))
        if delta:
            fmt += b"%" + str(delta).encode() + b"c"
            written += delta
        fmt += b"%" + str(slots[rank]).encode() + b"$" + sign.encode() + b"n"
    return fmt


@tool(
    "pwn.fmtstr", "格式化字符串载荷", "pwn", "6.3",
    summary="生成任意地址写的格式化字符串 payload（%n），支持 32 / 64 位、hhn / hn",
    principle="""
    当程序把用户输入直接当作 `printf` 的格式串（`printf(buf)` 而不是 `printf("%s", buf)`），
    就能用 `%x` 泄露栈、用 `%n` 往任意地址写值：

    - `%n` 把“已经打印的字符数”写进参数指向的地址；
    - 用 `%数字c` 控制打印的字符数，就能写入任意值；
    - 一次写 4 字节太慢（要打印几十亿字符），所以分成两次 `%hn`（2 字节）或四次 `%hhn`（1 字节）。

    本工具生成“把 value 写到 address”的 payload。需要先知道**格式串参数的偏移**（用 `%p.%p.%p...` 探测，
    找到输入出现在第几个）。pwntools 的 `fmtstr_payload(offset, {addr: value})` 做的就是这件事。
    """,
    inputs=[field("text", "string", "目标地址", default="0x601028")],
    options=[field("value", "string", "要写入的值", default="0xdeadbeef"),
             field("offset", "number", "参数偏移", default=6, min=1, max=200),
             field("bits", "segmented", "位数", default="64", choices=["32", "64"]),
             field("write", "segmented", "每次写入", default="hhn（1字节×4）", choices=["hhn（1字节×4）", "hn（2字节×2）"])],
    examples=[{"text": "0x601028", "value": "0xdeadbeef", "offset": 6, "bits": "64"}],
    keywords=["格式化字符串", "format string", "%n", "fmtstr", "printf"],
)
def fmtstr_tool(text, value="0xdeadbeef", offset=6, bits="64", write="hhn（1字节×4）"):
    addr = parse_int(text, "地址")
    val = parse_int(value, "值")
    nbytes = int(bits) // 8
    off = int(offset)
    sz = 1 if "hhn" in write else 2
    n = nbytes // sz
    sign = "hh" if sz == 1 else "h"
    # 把 value 拆成 sz 字节一块，按“要打印的字符数”从小到大排，避免计数回绕
    chunks = [(val >> (8 * sz * i)) & ((1 << (8 * sz)) - 1) for i in range(n)]
    order = sorted(range(n), key=lambda i: chunks[i])
    # 布局：[格式串 | 补零对齐到字长 | n 个目标地址]。地址在格式串之后，其槽位 = off + 格式串占的字长数。
    # 格式串长度与槽位数字的位数相互影响，迭代到稳定。
    base = off + n
    for _ in range(8):
        slots = [base + rank for rank in range(n)]
        fmt = _build_fmt(order, chunks, sz, sign, slots)
        pad = (-len(fmt)) % nbytes
        new_base = off + (len(fmt) + pad) // nbytes
        if new_base == base:
            break
        base = new_base
    fmt = _build_fmt(order, chunks, sz, sign, [base + rank for rank in range(n)])
    fmt += b"\x00" * ((-len(fmt)) % nbytes)
    addrs = b"".join((addr + sz * order[rank]).to_bytes(nbytes, "little") for rank in range(n))
    payload = fmt + addrs
    return fields([["payload（Python 字节串）", repr(payload)],
                   ["payload（十六进制）", payload.hex()],
                   ["长度", len(payload)],
                   ["地址起始参数槽", base],
                   ["提示", "布局：格式串 + 对齐 + %d 个目标地址，地址从第 %d 个参数开始。若偏移不对用 %%p 探测确认 offset。更复杂的情况建议用 pwntools 的 fmtstr_payload" % (n, base)]])


# ---------------------------------------------------------------- ret2libc

@tool(
    "pwn.ret2libc", "ret2libc 地址计算", "pwn", "6.2.9",
    summary="由泄露的函数地址和 libc 偏移，算出 libc 基址与 system、/bin/sh 的地址",
    principle="""
    关闭了 ASLR 以外的程序仍会随机加载 libc。先泄露某个 libc 函数的真实地址（如 puts），
    减去它在 libc 里的偏移，就得到 **libc 基址**；再加上 system、`/bin/sh` 的偏移，就得到它们的真实地址。

    偏移可以用 `readelf -s libc.so | grep system`，或在本工具中直接填已知偏移；
    不知道 libc 版本时，用泄露地址的低 3 位十六进制去 libc-database / libc.blukat.me 查询。
    """,
    inputs=[field("text", "string", "泄露的函数地址", default="0x7f1234567890")],
    options=[field("leak_name", "string", "泄露的是哪个函数", default="puts"),
             field("leak_off", "string", "该函数在 libc 的偏移", default="0x80e50"),
             field("system_off", "string", "system 偏移", default="0x4f550"),
             field("binsh_off", "string", "/bin/sh 偏移", default="0x1b3e1a")],
    examples=[{"text": "0x7f1234567890", "leak_off": "0x80e50", "system_off": "0x4f550", "binsh_off": "0x1b3e1a"}],
    keywords=["ret2libc", "libc", "system", "binsh", "基址", "offset"],
)
def ret2libc_tool(text, leak_name="puts", leak_off="0x80e50", system_off="0x4f550", binsh_off="0x1b3e1a"):
    leak = parse_int(text, "泄露地址")
    lo = parse_int(leak_off, "偏移")
    base = leak - lo
    if base < 0:
        raise ToolError("泄露地址比偏移还小，检查偏移是否正确")
    sysa = base + parse_int(system_off, "system 偏移")
    binsh = base + parse_int(binsh_off, "/bin/sh 偏移")
    return fields([["libc 基址", hex(base)], ["system 地址", hex(sysa)], ["/bin/sh 地址", hex(binsh)],
                   ["低 3 位十六进制（查 libc 版本用）", "...%03x" % (leak & 0xFFF)],
                   ["提示", "基址末 3 位应为 000；不是则偏移或泄露不对"]])


# ---------------------------------------------------------------- shellcode 速查

SHELLCODES = {
    "x86 execve(/bin/sh)（23 字节）": "31c050682f2f7368682f62696e89e3505389e131d2b00bcd80",
    "x86-64 execve(/bin/sh)（22 字节）": "4831d248bb2f62696e2f2f736848c1eb0853544889e752574889e60f05",
}

SYSCALLS_64 = [["read", 0], ["write", 1], ["open", 2], ["close", 3], ["mmap", 9], ["mprotect", 10],
               ["dup2", 33], ["execve", 59], ["exit", 60]]
SYSCALLS_32 = [["exit", 1], ["read", 3], ["write", 4], ["open", 5], ["execve", 11], ["mprotect", 125],
               ["dup2", 63]]


@tool(
    "pwn.shellcode", "Shellcode 与系统调用速查", "pwn", "6.2.8",
    summary="常用 execve(/bin/sh) 机器码；x86 / x64 系统调用号对照",
    principle="""
    当栈可执行（没开 NX）时，可以直接往栈上写一段机器码（shellcode）并跳过去执行。
    最常用的是 `execve("/bin/sh", 0, 0)` 拿到 shell。

    系统调用号在 32 位和 64 位下不同：64 位 execve 是 59，用 `syscall` 指令；
    32 位 execve 是 11，用 `int 0x80`。ret2syscall 要用到这些号。
    """,
    inputs=[field("text", "string", "查询（可选）", default="")],
    options=[field("view", "segmented", "查看", default="shellcode", choices=["shellcode", "系统调用号"])],
    examples=[{"view": "shellcode"}],
    keywords=["shellcode", "execve", "syscall", "系统调用", "bin/sh"],
)
def shellcode_tool(text="", view="shellcode"):
    if view == "系统调用号":
        return [fields([["说明", "64 位用 syscall 指令，rax 放调用号；32 位用 int 0x80，eax 放调用号"]]),
                table(["调用", "x86-64（rax）", "x86（eax）"],
                      [[n, dict(SYSCALLS_64).get(n, "-"), dict(SYSCALLS_32).get(n, "-")]
                       for n in dict(SYSCALLS_64) if not text or text in n])]
    rows = [[name, code, "".join("\\x%s" % code[i:i + 2] for i in range(0, len(code), 2))]
            for name, code in SHELLCODES.items()]
    return table(["说明", "十六进制", "\\x 形式"], rows)


# ---------------------------------------------------------------- safe-linking

@tool(
    "pwn.safelinking", "tcache safe-linking", "pwn", "7.8",
    summary="glibc 2.32+ 的 fd 指针加密 / 解密计算（PROTECT_PTR）",
    principle="""
    glibc 2.32 起，tcache 和 fast bin 的 `fd` 指针不再是明文地址，而是
    `加密值 = (chunk地址 >> 12) ⊕ 真实fd`（safe-linking）。所以堆利用时：

    - 读到 fd 要**解密**才是真实地址；
    - 写 fd 要先**加密**。

    解密需要知道 chunk 所在页的地址（即泄露的堆地址）。本工具做这两个方向的计算。
    """,
    inputs=[field("text", "string", "fd 值（加密或明文）", default="0x555555559290")],
    options=[field("action", "segmented", "操作", default="解密", choices=["加密", "解密"]),
             field("pos", "string", "存放 fd 的地址（chunk 的 fd 位置）", default="0x5555555592a0")],
    examples=[{"text": "0x555556aad290", "action": "解密", "pos": "0x5555555592a0"}],
    keywords=["safe-linking", "tcache", "fd", "加密", "protect_ptr", "glibc"],
)
def safelinking_tool(text, action="解密", pos="0x5555555592a0"):
    val = parse_int(text, "fd")
    p = parse_int(pos, "地址")
    key = p >> 12
    # 加密和解密是同一个异或，但解密要逐步（因为 key 依赖结果）——这里 key 由存放地址决定，直接异或即可
    result = val ^ key
    return fields([["%s结果" % action, hex(result)], ["使用的 key（地址 >> 12）", hex(key)],
                   ["说明", "加密 / 解密都是 值 ⊕ (存放地址 >> 12)"]])
