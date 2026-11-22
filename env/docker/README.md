# CTFKit 完整环境（Docker）

一条命令得到 **Python 2.7 与 Python 3 并存**、装好 CTF 常用库的环境，不用在自己电脑上配环境。

```bash
docker run -it --rm -v "$PWD:/work" ghcr.io/deepshawn/ctfkit:lite
```

当前目录会挂载到容器内的 `/work`，在里面写的脚本、下载的附件退出后仍在。

## 内容

| | Python 3（3.13） | Python 2（2.7.18） |
|---|---|---|
| 命令 | `python3`、`python`、`pip` | `python2`、`python2 -m pip` |
| 预装库 | ctfkit、pwntools、pycryptodome、gmpy2、sympy、z3-solver、Pillow、numpy、requests、pyelftools、dpkt | pwntools 4.15.1、pycryptodome、gmpy2、sympy、Pillow、requests、pyelftools、dpkt（均为仍支持 2.7 的版本） |

命令行工具：`ctfkit`、`binwalk`、`exiftool`、`file`、`xxd`、`strings` 等 binutils、`nc`、`git`、`curl`、`gcc`。

进入容器后运行 `ctfkit-check` 可检查两个 Python 版本和全部库是否可用。

```bash
python2 old_writeup.py           # 直接运行 Python 2 的旧题解
python3 solve.py                 # Python 3 脚本
ctfkit run classical.caesar "synt{pnrfne}"
```

## 自己构建

在仓库根目录：

```bash
docker build -t ctfkit:lite -f env/docker/Dockerfile .
```

学校或公司网络使用自签名证书时，把证书（`.crt`）放进 `env/docker/extra-ca/` 再构建；这个目录中的证书不会被提交到仓库。

## 说明

- 镜像以官方 `python:2.7.18-slim-buster` 为基础。Python 2 与 Debian 10 都已停止维护，**不要把这个容器暴露在公网上**，只用于本机学习和做题；
- Python 3 由 [uv](https://github.com/astral-sh/uv) 安装独立构建版本，与 Python 2 互不影响；
- 计划中的 `latest` 完整版（gdb + pwndbg、多版本 glibc、sqlmap 等）随 PWN、Web 章节一起在 v0.5～v0.7 加入。当前的 `latest` 标签与 `lite` 内容相同；
- 镜像中的第三方软件遵循各自的许可协议。
