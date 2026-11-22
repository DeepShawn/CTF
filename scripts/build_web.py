"""构建 Web 版：把页面、TesseraUI、ctfkit 源码与工具描述文件放进 dist/site，可直接部署到 GitHub Pages。

用法（在仓库根目录）：
    git submodule update --init      # 取得 vendor/TesseraUI
    python3 scripts/build_web.py
    python3 -m http.server -d dist/site 8000
"""

import json
import os
import shutil
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "dist", "site")
TESSERA = os.path.join(ROOT, "vendor", "TesseraUI", "platforms", "web", "dist")


def main():
    sys.path.insert(0, os.path.join(ROOT, "core"))
    from ctfkit import __version__
    from ctfkit.registry import manifest

    if not os.path.isfile(os.path.join(TESSERA, "tessera.css")):
        sys.exit("找不到 TesseraUI，请先运行：git submodule update --init")
    shutil.rmtree(OUT, ignore_errors=True)
    shutil.copytree(os.path.join(ROOT, "apps", "web"), OUT)
    shutil.copytree(TESSERA, os.path.join(OUT, "tessera"))
    shutil.copy(os.path.join(ROOT, "LICENSE"), os.path.join(OUT, "LICENSE.txt"))
    shutil.copy(os.path.join(ROOT, "vendor", "TesseraUI", "LICENSE"), os.path.join(OUT, "tessera", "LICENSE.txt"))

    # ctfkit 源码打成 zip，由 worker.js 解压到 Pyodide 的文件系统中
    os.makedirs(os.path.join(OUT, "py"))
    src = os.path.join(ROOT, "core", "ctfkit")
    with zipfile.ZipFile(os.path.join(OUT, "py", "ctfkit.zip"), "w", zipfile.ZIP_DEFLATED) as z:
        for base, dirs, files in os.walk(src):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in sorted(files):
                if f.endswith(".py"):
                    full = os.path.join(base, f)
                    z.write(full, os.path.relpath(full, os.path.dirname(src)))

    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as fp:
        json.dump(manifest(), fp, ensure_ascii=False)

    sw = os.path.join(OUT, "sw.js")
    with open(sw, encoding="utf-8") as fp:
        text = fp.read().replace("__VERSION__", __version__ + "-" + os.environ.get("GITHUB_SHA", "local")[:7])
    with open(sw, "w", encoding="utf-8") as fp:
        fp.write(text)
    open(os.path.join(OUT, ".nojekyll"), "w").close()
    n = len(manifest()["tools"])
    print("已生成 %s（ctfkit %s，%d 个工具）" % (os.path.relpath(OUT, ROOT), __version__, n))


if __name__ == "__main__":
    main()
