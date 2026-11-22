"""命令行入口：ctfkit list / info / run / magic / manifest。

示例：
    ctfkit list
    ctfkit run encoding.base64 "ZmxhZ3toaX0="
    ctfkit run classical.caesar "synt{pnrfne}"
    ctfkit run encoding.base64 --set mode=编码 "flag{hi}"
    echo "ZmxhZ3toaX0=" | ctfkit magic -
"""

import argparse
import json
import sys

from . import __version__
from .registry import CATEGORIES, all_tools, get, manifest, run, source


def _read(text):
    if text == "-" or text is None and not sys.stdin.isatty():
        return sys.stdin.read()
    return text or ""


def _render(out, indent=""):
    t = out.get("type")
    if t == "text":
        print(out["value"])
    elif t == "fields":
        for k, v in out["items"]:
            print("%s%s: %s" % (indent, k, v))
    elif t == "table":
        print(indent + "\t".join(str(c) for c in out["columns"]))
        for row in out["rows"]:
            print(indent + "\t".join(str(c) for c in row))
    elif t == "group":
        for i, item in enumerate(out["items"]):
            if i:
                print()
            _render(item, indent)


def _coerce(t, key, value):
    for f in t["inputs"] + t["options"]:
        if f["id"] == key:
            if f["type"] == "number":
                return int(value)
            if f["type"] == "switch":
                return value.lower() in ("1", "true", "yes", "on", "是")
            return value
    raise SystemExit("工具 %s 没有参数 %s。用 ctfkit info %s 查看参数" % (t["id"], key, t["id"]))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ctfkit", description="CTFKit：面向初学者的 CTF 工具包")
    ap.add_argument("--version", action="version", version="ctfkit " + __version__)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("list", help="列出全部工具")
    p.add_argument("category", nargs="?", choices=list(CATEGORIES), help="只列出某一类")

    p = sub.add_parser("info", help="查看工具的参数与原理")
    p.add_argument("id")
    p.add_argument("--source", action="store_true", help="同时显示 Python 源代码")

    p = sub.add_parser("run", help="运行工具")
    p.add_argument("id")
    p.add_argument("text", nargs="?", help="输入内容；写 - 或省略时从标准输入读取")
    p.add_argument("--set", "-s", action="append", default=[], metavar="参数=值", help="设置选项，可写多个")
    p.add_argument("--json", action="store_true", help="以 JSON 输出")

    p = sub.add_parser("magic", help="智能识别编码（等同于 run encoding.magic）")
    p.add_argument("text", nargs="?")

    p = sub.add_parser("manifest", help="导出全部工具的描述文件（JSON）")
    p.add_argument("-o", "--output", help="写入文件，默认输出到屏幕")

    args = ap.parse_args(argv)
    if args.cmd == "list":
        for cat, meta in CATEGORIES.items():
            if args.category and cat != args.category:
                continue
            tools = [t for t in all_tools() if t["category"] == cat]
            if not tools:
                continue
            print("\n[%s]" % meta["title"])
            for t in tools:
                print("  %-26s %-8s %s" % (t["id"], t["chapter"], t["title"]))
        return 0
    if args.cmd == "info":
        t = get(args.id)
        print("%s（%s，教材 %s）\n%s\n" % (t["title"], t["id"], t["chapter"] or "—", t["summary"]))
        print("参数：")
        for f in t["inputs"] + t["options"]:
            extra = ("，可选：" + " / ".join(map(str, f["choices"]))) if "choices" in f else ""
            print("  %-12s %s（默认：%s）%s" % (f["id"], f["label"], f.get("default", ""), extra))
        print("\n原理：\n" + t["principle"])
        if args.source:
            print("\n源代码：\n" + source(args.id))
        return 0
    if args.cmd in ("run", "magic"):
        tid = "encoding.magic" if args.cmd == "magic" else args.id
        t = get(tid)
        params = {t["inputs"][0]["id"]: _read(args.text).rstrip("\n")}
        for kv in getattr(args, "set", []):
            if "=" not in kv:
                raise SystemExit("--set 的格式是 参数=值，例如 --set mode=编码")
            k, v = kv.split("=", 1)
            params[k] = _coerce(t, k, v)
        res = run(tid, params)
        if getattr(args, "json", False):
            print(json.dumps(res, ensure_ascii=False, indent=2))
        elif res["ok"]:
            _render(res["output"])
        else:
            print("错误：" + res["error"], file=sys.stderr)
        return 0 if res["ok"] else 1
    if args.cmd == "manifest":
        data = json.dumps(manifest(), ensure_ascii=False, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fp:
                fp.write(data + "\n")
        else:
            print(data)
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
