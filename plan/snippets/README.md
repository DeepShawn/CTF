# 讲解示例脚本

[explainers.md](../explainers.md) 中用到的示例脚本。每个脚本都只用标准库，**Python 2.7 与 Python 3 都能直接运行**，运行结果相同（Python 2 显示字节串时不带 `b''` 前缀，这本身就是两个版本的区别之一）。

| 脚本 | 内容 |
|---|---|
| `01_py2_vs_py3.py` | Python 2 与 Python 3 在字节串、除法上的区别 |
| `02_base64.py` | 手写 Base64 编码，并与标准库结果对比 |
| `03_caesar.py` | 凯撒密码枚举 26 种位移 |
| `04_zip_fake_encrypt.py` | ZIP 伪加密的检测与修复（脚本自带测试压缩包） |
| `05_png_height.py` | 根据 CRC 爆破 PNG 的真实高度 |
| `06_lsb.py` | LSB 隐写的写入与提取 |
| `07_rsa.py` | RSA 加解密与小 e 攻击 |

## 运行方法

```bash
# Python 3
python3 02_base64.py

# Python 2（没有安装 Python 2 时，用 Docker）
docker run --rm -v "$PWD:/s" -w /s python:2.7-slim python 02_base64.py
```

Windows 上 Python 3 的命令通常是 `python` 或 `py -3`。

计划阶段已在 Python 2.7.18 与 Python 3.13 上逐个运行通过（2026-11-22）。项目建立持续集成后，这些脚本会在每次提交时用两个版本自动运行。
