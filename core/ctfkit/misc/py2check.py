"""Python 2 → 3 检查（教材 0.4.1）。

不运行代码，只逐行检查 Python 2 特有的写法，给出 Python 3 的改法。
Python 3.13 已移除 lib2to3，这里用正则表达式加 tokenize 做轻量检查，覆盖 CTF 脚本中最常见的问题。
"""

import io
import re
import tokenize

from ..registry import ToolError, text_input, tool
from ..util import table

RULES = [
    (r"^\s*print\s+(?![\s(=])", "print 语句", "改为函数调用：print(...)；同时兼容两个版本可加 from __future__ import print_function"),
    (r"^\s*print\s*$", "print 语句", "改为 print()"),
    (r"^\s*exec\s+[\"'\w]", "exec 语句", "改为函数调用：exec(...)"),
    (r"\bexcept\s+[\w.]+\s*,\s*\w+\s*:", "except X, e 写法", "改为 except X as e:"),
    (r"\braise\s+\w+\s*,", "raise X, msg 写法", "改为 raise X(msg)"),
    (r"\braw_input\s*\(", "raw_input()", "Python 3 中改为 input()（Python 2 的 input() 会执行输入的内容，不安全）"),
    (r"\bxrange\s*\(", "xrange()", "改为 range()"),
    (r"\.has_key\s*\(", "dict.has_key()", "改为 key in d"),
    (r"\.(iteritems|itervalues|iterkeys)\s*\(", "dict.iter*()", "改为 .items() / .values() / .keys()"),
    (r"\.encode\(\s*['\"](hex|base64)['\"]\s*\)", ".encode('hex' / 'base64')", "改为 binascii.hexlify(b) / b.hex() 或 base64.b64encode(b)"),
    (r"\.decode\(\s*['\"](hex|base64)['\"]\s*\)", ".decode('hex' / 'base64')", "改为 bytes.fromhex(s) 或 base64.b64decode(s)"),
    (r"\bunicode\s*\(", "unicode()", "Python 3 的 str 就是 Unicode 文本，改为 str()"),
    (r"\blong\s*\(|\b\d+[lL]\b", "long 类型", "Python 3 只有 int，且没有大小上限；去掉 L 后缀，long() 改为 int()"),
    (r"\bbasestring\b", "basestring", "改为 str（需要同时接受字节时用 (str, bytes)）"),
    (r"<>", "<> 运算符", "改为 !="),
    (r"`[^`]+`", "反引号 `x`", "改为 repr(x)"),
    (r"\b0[0-7]+\b", "八进制写法 0777", "改为 0o777"),
    (r"\bimport\s+(urllib2|urlparse|cPickle|StringIO|cStringIO|Queue|ConfigParser|httplib|commands)\b|"
     r"\bfrom\s+(urllib2|urlparse|cPickle|StringIO|cStringIO|Queue|ConfigParser|httplib|commands)\s+import",
     "已改名的模块", "urllib2 → urllib.request；urlparse → urllib.parse；cPickle → pickle；"
                     "StringIO → io；Queue → queue；ConfigParser → configparser；httplib → http.client；commands → subprocess"),
    (r"\bstring\.(letters|lowercase|uppercase|maketrans)\b", "string 模块中已移除的名称",
     "letters → ascii_letters；lowercase → ascii_lowercase；uppercase → ascii_uppercase；maketrans → str.maketrans / bytes.maketrans"),
    (r"\bord\s*\(\s*\w+\s*\[", "ord(s[i])", "如果 s 是 bytes，Python 3 中 s[i] 已经是整数，直接写 s[i]；两个版本通用可用 bytearray(s)[i]"),
    (r"\breduce\s*\(", "reduce()", "Python 3 中需要 from functools import reduce"),
    (r"\.sort\s*\(\s*(cmp\s*=|lambda)", "sort(cmp=...)", "改为 key=...，或用 functools.cmp_to_key"),
    (r"\bdict\.keys\(\)\[|\.keys\(\)\s*\[\d", "keys()[0]", "Python 3 中 keys() 不能下标访问，改为 list(d.keys())[0]"),
    (r"\bmap\s*\(|\bfilter\s*\(|\bzip\s*\(", "map / filter / zip 返回迭代器",
     "Python 3 中返回的是迭代器而不是列表，需要列表时包一层 list(...)"),
]

DIVISION_HINT = re.compile(r"[\w)\]]\s*/\s*[\w(]")


def check(source):
    issues = []
    lines = source.splitlines()
    # 用 tokenize 找出注释的位置并抹掉，避免误报注释中的内容（字符串保留，因为 .encode('hex') 要看引号里的内容）
    masked = list(lines)
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type == tokenize.COMMENT:
                r, c1, c2 = tok.start[0] - 1, tok.start[1], tok.end[1]
                if r < len(masked):
                    masked[r] = masked[r][:c1] + " " * (c2 - c1)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass  # Python 2 代码经常无法被 Python 3 的 tokenize 完整解析，按原文检查即可
    has_future_div = "from __future__ import" in source and "division" in source
    has_coding = any(re.search(r"coding[:=]", l) for l in lines[:2])
    non_ascii = any(ord(c) > 127 for c in source)
    if non_ascii and not has_coding:
        issues.append([1, "缺少编码声明", "文件中有中文等非 ASCII 字符，Python 2 会报 SyntaxError；"
                                          "两个版本通用时在第一行加 # -*- coding: utf-8 -*-（Python 3 可不加）"])
    for i, line in enumerate(masked, 1):
        for pat, name, fix in RULES:
            if re.search(pat, line):
                issues.append([i, name, fix])
        if not has_future_div and DIVISION_HINT.search(line) and "//" not in line:
            issues.append([i, "除法 /", "Python 2 中整数 / 整数是整除，Python 3 中结果是小数；"
                                       "整数运算（如 RSA）请改为 //"])
    return issues


@tool(
    "misc.py2check", "Python 2 → 3 检查", "misc", "0.4.1",
    summary="粘贴旧的 Python 2 脚本，逐行指出需要修改的写法",
    principle="""
    网上较早的 CTF 题解很多是 Python 2 写的。直接用 Python 3 运行，最常见的报错有：

    | 报错 | 原因 |
    |---|---|
    | `SyntaxError: Missing parentheses in call to 'print'` | Python 3 的 print 是函数 |
    | `TypeError: can't concat str to bytes` | Python 3 区分文本 str 与字节 bytes |
    | `TypeError: ord() expected string of length 1, but int found` | Python 3 中 `b"abc"[0]` 已经是整数 |
    | `LookupError: 'hex' is not a text encoding` | `.encode('hex')` 在 Python 3 中已移除 |
    | 结果多了小数点 / 大数结果不对 | `/` 在 Python 3 中是真除法，应改为 `//` |

    本工具不运行代码，只按规则逐行检查，可能有少量误报（如 `/` 本来就要算小数）。
    来不及修改时，可以在 Docker 环境中直接用 `python2` 运行原脚本。
    """,
    inputs=[text_input("Python 2 代码", placeholder="print 'hello'\nprint 'flag'.encode('hex')")],
    examples=[{"text": "import urllib2\nn = 3233L\nfor i in xrange(10):\n    print i / 2, 'flag'.encode('hex')\ntry:\n    pass\nexcept Exception, e:\n    print e"}],
    keywords=["python2", "python3", "2to3", "迁移"],
)
def py2check_tool(text):
    if not text.strip():
        raise ToolError("请粘贴要检查的代码")
    issues = check(text)
    if not issues:
        return "没有发现常见的 Python 2 写法。如果运行仍然报错，请把报错信息与代码一起对照上面的原理说明。"
    return table(["行号", "问题", "修改方法"], issues)
