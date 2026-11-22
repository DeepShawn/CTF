"""Brainfuck 与 Ook!（教材 1.1.12）。"""

import re

from ..registry import ToolError, field, text_input, tool

MAX_STEPS = 5_000_000


def run_bf(code, stdin=b"", max_steps=MAX_STEPS):
    """执行 Brainfuck 程序。纸带 30000 格、每格 0～255 循环。"""
    code = [c for c in code if c in "+-<>[].,"]
    jump, stack = {}, []
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                raise ToolError("第 %d 个指令处的 ] 没有对应的 [" % (i + 1))
            j = stack.pop()
            jump[i], jump[j] = j, i
    if stack:
        raise ToolError("有 %d 个 [ 没有对应的 ]" % len(stack))
    tape = bytearray(30000)
    ptr = pc = steps = 0
    inp = list(stdin)
    out = bytearray()
    while pc < len(code):
        c = code[pc]
        if c == "+":
            tape[ptr] = (tape[ptr] + 1) & 255
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) & 255
        elif c == ">":
            ptr += 1
            if ptr >= len(tape):
                raise ToolError("指针越过了纸带右端")
        elif c == "<":
            ptr -= 1
            if ptr < 0:
                raise ToolError("指针越过了纸带左端")
        elif c == ".":
            out.append(tape[ptr])
        elif c == ",":
            tape[ptr] = inp.pop(0) if inp else 0
        elif c == "[" and tape[ptr] == 0:
            pc = jump[pc]
        elif c == "]" and tape[ptr] != 0:
            pc = jump[pc]
        pc += 1
        steps += 1
        if steps > max_steps:
            raise ToolError("执行超过 %d 步仍未结束，可能是死循环" % max_steps)
    return bytes(out)


OOK = {"Ook. Ook?": ">", "Ook? Ook.": "<", "Ook. Ook.": "+", "Ook! Ook!": "-",
       "Ook! Ook.": ".", "Ook. Ook!": ",", "Ook! Ook?": "[", "Ook? Ook!": "]"}
SHORT_OOK = {k.replace("Ook", "").replace(" ", ""): v for k, v in OOK.items()}


def ook_to_bf(text):
    tokens = re.findall(r"Ook[.?!]", text)
    if tokens:
        return "".join(OOK.get(tokens[i] + " " + tokens[i + 1], "") for i in range(0, len(tokens) - 1, 2))
    marks = re.sub(r"[^.?!]", "", text)                    # 简写形式：只有 . ? !
    return "".join(SHORT_OOK.get(marks[i:i + 2], "") for i in range(0, len(marks) - 1, 2))


def text_to_bf(data):
    """生成输出给定字节的 Brainfuck 程序（每个字符从上一个字符的值加减得到）。"""
    out, cur = [], 0
    for b in data:
        d = b - cur
        if abs(d) > 15:
            q, r = divmod(abs(d), 10)
            sign = "+" if d > 0 else "-"
            out.append(">" + "+" * q + "[<" + sign * 10 + ">-]<" + sign * r + ".")
        else:
            out.append(("+" if d > 0 else "-") * abs(d) + ".")
        cur = b
    return "".join(out)


@tool(
    "encoding.brainfuck", "Brainfuck / Ook! 解释器", "encoding", "1.1.12",
    summary="执行 Brainfuck 或 Ook! 程序，或把文本转成 Brainfuck",
    principle="""
    Brainfuck 是只有 8 个指令的编程语言，操作一条每格存一个字节的纸带：

    | 指令 | 作用 |
    |---|---|
    | `>` `<` | 指针右移、左移一格 |
    | `+` `-` | 当前格加 1、减 1 |
    | `.` `,` | 输出、读入当前格（一个字节） |
    | `[` `]` | 当前格为 0 时跳过循环 / 不为 0 时回到循环开头 |

    **Ook!** 把这 8 个指令换成 `Ook.`、`Ook?`、`Ook!` 两两组合，可以一一翻译成 Brainfuck。

    **怎么认出来**：满屏的 `+-<>[].`，或满屏的 `Ook`。
    """,
    inputs=[text_input("程序", placeholder="++++++++[>++++++++++++<-]>++++++.")],
    options=[field("action", "segmented", "操作", default="执行", choices=["执行", "文本 → Brainfuck", "Ook! → Brainfuck"]),
             field("stdin", "string", "程序输入", default="", visible_when={"action": "执行"})],
    examples=[{"text": "++++++++++[>++++++++++<-]>++.++++++.-----------.++++++.", "action": "执行"}],
    keywords=["brainfuck", "bf", "ook"],
)
def brainfuck_tool(text, action="执行", stdin=""):
    if action == "文本 → Brainfuck":
        return text_to_bf(text.encode("utf-8"))
    if action == "Ook! → Brainfuck":
        return ook_to_bf(text)
    code = ook_to_bf(text) if "Ook" in text else text
    from ..util import show
    return show(run_bf(code, stdin.encode("utf-8")))
