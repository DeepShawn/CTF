"""摩斯密码（教材 1.1.10）。"""

import re

from ..registry import ToolError, field, mode, text_input, tool

MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....",
    "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.",
    "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....",
    "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--", "/": "-..-.",
    "(": "-.--.", ")": "-.--.-", "&": ".-...", ":": "---...", ";": "-.-.-.", "=": "-...-",
    "+": ".-.-.", "-": "-....-", "_": "..--.-", "\"": ".-..-.", "$": "...-..-", "@": ".--.-.",
    "{": "-.--.", "}": "-.--.-",   # 花括号没有标准写法，CTF 中通常借用圆括号
}
REVERSE = {}
for _k, _v in MORSE.items():
    REVERSE.setdefault(_v, _k)


@tool(
    "encoding.morse", "摩斯密码", "encoding", "1.1.10",
    summary="点、划与分隔符；可自定义符号（如 0/1、A/B）",
    principle="""
    摩斯密码用短信号（点 `.`）和长信号（划 `-`）的组合表示字母和数字，字母之间用空格隔开，
    单词之间常用 `/` 隔开。例如 `SOS` 是 `... --- ...`。

    **常见变形**：点和划换成其他符号（`0`/`1`、`A`/`B`、`嘀`/`嗒`），或藏在音频、灯光闪烁中。
    摩斯密码不区分大小写，解出来全是大写，提交 flag 时注意题目要求。
    摩斯密码没有花括号，题目中常用圆括号代替，或者只编码花括号里面的内容。
    """,
    inputs=[text_input(placeholder="..-. .-.. .- --. / -- --- .-. ... .")],
    options=[mode(default="解码"),
             field("dot", "string", "点", default="."),
             field("dash", "string", "划", default="-"),
             field("sep", "string", "字母分隔符", default=" ", help="解码时也会把 / | 换行当作分隔符")],
    examples=[{"text": "..-. .-.. .- --. / -- --- .-. ... .", "mode": "解码"}],
    keywords=["morse", "摩斯", "摩尔斯"],
)
def morse_tool(text, mode="解码", dot=".", dash="-", sep=" "):
    if not dot or not dash or dot == dash:
        raise ToolError("点和划必须是两个不同的符号")
    sep = sep or " "
    if mode == "编码":
        words = []
        for w in text.upper().split():
            codes = []
            for c in w:
                if c not in MORSE:
                    raise ToolError("“%s”没有对应的摩斯码" % c)
                codes.append(MORSE[c].replace(".", "\0").replace("-", dash).replace("\0", dot))
            words.append(sep.join(codes))
        return (" / " if sep == " " else sep * 2).join(words)
    s = text.strip()
    words = re.split(r"\s*[/|]\s*|\n+|(?:%s){2,}" % re.escape(sep) if sep != " " else r"\s*[/|]\s*|\n+|\s{3,}", s)
    out = []
    for w in words:
        parts = [p for p in (w.split(sep) if sep != " " else w.split()) if p]
        letters = []
        for p in parts:
            code = p.replace(dot, "\0").replace(dash, "-").replace("\0", ".")
            if set(code) - set(".-"):
                raise ToolError("“%s”中有点、划以外的符号，检查点和划的设置" % p)
            letters.append(REVERSE.get(code, "[%s]" % p))
        out.append("".join(letters))
    return " ".join(out)
