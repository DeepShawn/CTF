"""flag 搜索：在文本中查找 flag，也查找经过 Base64、十六进制、反转等变换后的 flag。"""

import base64
import re

from ..registry import ToolError, field, text_input, tool
from ..util import table


def variants(prefix):
    """flag 前缀经过常见变换后的样子，例如 flag{ 的 Base64 以 ZmxhZ 开头。"""
    p = prefix.encode("utf-8")
    out = {"原文": prefix, "反转": prefix[::-1], "十六进制": p.hex()}
    for shift in range(3):
        # 前缀前面有 shift 个未知字节时，只有完全落在前缀范围内的 6 位分组才是确定的
        enc = base64.b64encode(b"\0" * shift + p).decode("ascii")
        first = -(-8 * shift // 6)                 # 向上取整
        last = 8 * (shift + len(p)) // 6           # 不含
        if last - first >= 4:
            out["Base64（偏移 %d）" % shift] = enc[first:last]
    out["Base32"] = base64.b32encode(p).decode("ascii")[:8 * len(p) // 5]
    return out


@tool(
    "misc.flagsearch", "flag 搜索", "misc", "",
    summary="在大段文本中找 flag，以及它的 Base64、十六进制、反转形式",
    principle="""
    flag 常常埋在大量数据里（日志、流量导出的文本、文件中的字符串）。除了直接搜索 `flag{`，
    还要考虑它被编码后的样子：

    | 形式 | `flag{` 变成 |
    |---|---|
    | Base64 | `ZmxhZ3`（前面的字节数不同时也可能是 `ZsYWd7`、`mbGFne`） |
    | 十六进制 | `666c61677b` |
    | 反转 | `{galf` |

    本工具同时搜索这些形式，并给出所在行号，找到后再用对应的解码工具处理。
    """,
    inputs=[text_input("要搜索的文本")],
    options=[field("prefix", "string", "flag 前缀", default="flag{"),
             field("regex", "string", "自定义正则（可选）", default="", placeholder=r"如 ctf\{[^}]+\}")],
    examples=[{"text": "noise...\nkey=ZmxhZ3tiYXNlNjRfaW5zaWRlfQ==\nmore 666c61677b6865787d and }desrever{galf", "prefix": "flag{"}],
    keywords=["flag", "搜索", "grep"],
)
def flagsearch_tool(text, prefix="flag{", regex=""):
    if not prefix and not regex:
        raise ToolError("请填写 flag 前缀或自定义正则")
    rows = []
    lines = text.splitlines()
    if regex:
        try:
            r = re.compile(regex, re.I)
        except re.error as e:
            raise ToolError("正则表达式有误：%s" % e)
        for i, line in enumerate(lines, 1):
            for m in r.finditer(line):
                rows.append([i, "正则", m.group(0)[:200]])
    if prefix:
        for name, v in variants(prefix).items():
            for i, line in enumerate(lines, 1):
                low = line.lower() if name in ("原文", "反转") or name.startswith("十六进制") else line
                needle = v.lower() if low is not line else v
                start = low.find(needle)
                if start >= 0:
                    rows.append([i, name, line[max(0, start - 10):start + 80]])
    if not rows:
        return "没有找到。可以换一个前缀（如 ctf{、key{），或先用“智能识别”解码后再搜索。"
    return table(["行号", "形式", "上下文"], rows[:200])
