"""工具注册表。

每个工具是一个普通的 Python 函数，用 ``@tool(...)`` 登记它的描述信息
（标题、教材章节、输入、选项、原理）。三端界面和命令行都从这里读取
描述信息（:func:`manifest`）并调用工具（:func:`run`），因此新增工具时
只需写一个函数，不需要分别写界面。

字段类型与 TesseraUI 组件的对应关系：

========== ==============================
类型        TesseraUI 组件
========== ==============================
text       TextArea（多行文本）
string     TextField（单行文本）
number     NumberInput
select     Select
segmented  SegmentedControl
switch     Switch
========== ==============================
"""

import inspect
import json

CATEGORIES = {
    "encoding": {"title": "编码", "chapter": "1.1"},
    "classical": {"title": "古典密码", "chapter": "3.1"},
    "hash": {"title": "哈希", "chapter": "3.4"},
    "misc": {"title": "通用", "chapter": ""},
}

_TOOLS = {}


class ToolError(ValueError):
    """工具输入有误时抛出，消息直接显示给用户，应写清楚如何修正。"""


def field(id, type="text", label="", default=None, choices=None, help="", placeholder="",
          min=None, max=None, visible_when=None):
    f = {"id": id, "type": type, "label": label}
    if default is not None:
        f["default"] = default
    if choices is not None:
        f["choices"] = list(choices)
    if help:
        f["help"] = help
    if placeholder:
        f["placeholder"] = placeholder
    if min is not None:
        f["min"] = min
    if max is not None:
        f["max"] = max
    if visible_when:
        f["visibleWhen"] = visible_when
    return f


def text_input(label="输入", placeholder="", id="text"):
    return field(id, "text", label, default="", placeholder=placeholder)


def mode(choices=("编码", "解码"), default=None, id="mode", label="模式"):
    return field(id, "segmented", label, default=default or choices[0], choices=choices)


def tool(id, title, category, chapter="", summary="", principle="", inputs=None, options=None,
         examples=None, keywords=(), live=True):
    """登记一个工具。

    - ``summary``：一句话说明，显示在工具列表中；
    - ``principle``：原理讲解（Markdown），显示在工具页的“讲解”中；
    - ``examples``：示例参数，界面上的“填入示例”按钮使用，也用于自动测试；
    - ``live``：是否在输入变化时自动计算（耗时的爆破类工具设为 False）。
    """
    if category not in CATEGORIES:
        raise ValueError("未知分类: %s" % category)

    def deco(fn):
        if id in _TOOLS:
            raise ValueError("工具 id 重复: %s" % id)
        _TOOLS[id] = {
            "id": id,
            "title": title,
            "category": category,
            "chapter": chapter,
            "summary": summary,
            "principle": inspect.cleandoc(principle) if principle else "",
            "inputs": list(inputs or [text_input()]),
            "options": list(options or []),
            "examples": list(examples or []),
            "keywords": list(keywords),
            "live": live,
            "fn": fn,
        }
        return fn

    return deco


def _ensure_loaded():
    # 导入各工具模块，使其中的 @tool 生效
    from . import tools  # noqa: F401


def all_tools():
    _ensure_loaded()
    return [t for t in _TOOLS.values()]


def get(id):
    _ensure_loaded()
    try:
        return _TOOLS[id]
    except KeyError:
        raise ToolError("没有这个工具：%s（用 ctfkit list 查看全部工具）" % id)


def defaults(t):
    params = {}
    for f in t["inputs"] + t["options"]:
        if "default" in f:
            params[f["id"]] = f["default"]
    return params


def normalize(result):
    """把工具的返回值统一成界面可以直接显示的结构。

    - 字符串 → ``{"type": "text", "value": ...}``
    - ``{"type": "table", "columns": [...], "rows": [[...]]}`` 原样返回
    - ``{"type": "fields", "items": [[标签, 值], ...]}`` 原样返回（DescriptionList）
    - 列表 → 依次规范化后放进 ``{"type": "group", "items": [...]}``
    """
    if result is None:
        return {"type": "text", "value": ""}
    if isinstance(result, str):
        return {"type": "text", "value": result}
    if isinstance(result, dict) and "type" in result:
        return result
    if isinstance(result, (list, tuple)):
        return {"type": "group", "items": [normalize(r) for r in result]}
    return {"type": "text", "value": str(result)}


def run(id, params=None):
    """调用工具，返回 ``{"ok": True, "output": ...}`` 或 ``{"ok": False, "error": ...}``。"""
    try:
        t = get(id)
        p = defaults(t)
        p.update(params or {})
        known = {f["id"] for f in t["inputs"] + t["options"]}
        p = {k: v for k, v in p.items() if k in known}
        return {"ok": True, "output": normalize(t["fn"](**p))}
    except ToolError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:  # 工具内部错误也给出可读的提示，而不是让界面崩溃
        return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}


def run_json(id, params_json):
    """供 Web（Pyodide）与移动端调用：参数和结果都是 JSON 字符串。"""
    return json.dumps(run(id, json.loads(params_json) if params_json else {}), ensure_ascii=False)


def source(id):
    """返回工具所在模块的源代码，界面上的“Python 代码”标签页显示它。"""
    t = get(id)
    return inspect.getsource(inspect.getmodule(t["fn"]))


def manifest():
    """全部工具的描述信息（不含函数本身），三端界面据此生成工具页。"""
    from . import __version__
    tools = []
    for t in all_tools():
        d = {k: v for k, v in t.items() if k != "fn"}
        d["module"] = t["fn"].__module__
        tools.append(d)
    return {"version": __version__, "categories": CATEGORIES, "tools": tools}
