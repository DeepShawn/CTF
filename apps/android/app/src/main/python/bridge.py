"""Android 端与 Kotlin 之间的桥：参数和结果都用 JSON 字符串传递，和 Web 端 worker.js 完全一致。"""
from ctfkit.registry import manifest as _manifest, run_json as _run_json, source as _source
import json

def manifest():
    return json.dumps(_manifest(), ensure_ascii=False)

def run(tool_id, params_json):
    return _run_json(tool_id, params_json or "{}")

def source(tool_id):
    return _source(tool_id)
