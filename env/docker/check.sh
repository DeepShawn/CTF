#!/bin/sh
# 检查两个 Python 版本及常用库是否可用
set -e
echo "== Python 3"; python3 - <<'PY'
import sys; print(sys.version.split()[0])
for m in ["Crypto", "gmpy2", "sympy", "PIL", "numpy", "requests", "elftools", "dpkt", "z3", "pwn", "ctfkit"]:
    __import__(m); print("  ok", m)
PY
echo "== Python 2"; python2 - <<'PY'
import sys; print(sys.version.split()[0])
for m in ["Crypto", "gmpy2", "sympy", "PIL", "requests", "elftools", "dpkt", "pwn"]:
    __import__(m); print("  ok", m)
PY
echo "全部通过"
