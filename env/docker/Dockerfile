# CTFKit 完整环境（lite）：Python 2.7 与 Python 3 并存，装好 CTF 常用的 Python 库
#
#   docker build -t ctfkit:lite -f env/docker/Dockerfile .
#   docker run -it --rm -v "$PWD:/work" ctfkit:lite
#
# 基础镜像使用官方 python:2.7-slim（Debian 10，已停止更新，内容固定），
# Python 3 由 uv 安装独立构建版本（python-build-standalone），两者互不干扰。
FROM python:2.7.18-slim-buster

ARG PY3_VERSION=3.13
ENV LANG=C.UTF-8 \
    TERM=xterm-256color \
    UV_SYSTEM_CERTS=1 \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PYTHONIOENCODING=utf-8 \
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_TOOL_BIN_DIR=/usr/local/bin \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Debian 10 的软件源已移到 archive.debian.org
RUN sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g; /buster-updates/d' /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends \
      build-essential libgmp-dev libmpfr-dev libmpc-dev libffi-dev libssl-dev \
      ca-certificates curl git file xxd less vim-tiny netcat-openbsd \
      binutils binwalk libimage-exiftool-perl \
 && rm -rf /var/lib/apt/lists/*

# 公司或学校网络使用自签名证书时，把证书（.crt）放进 env/docker/extra-ca/ 再构建；默认为空
COPY env/docker/extra-ca/ /usr/local/share/ca-certificates/extra/
RUN update-ca-certificates

# ---------- Python 3 ----------
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
RUN uv python install ${PY3_VERSION} \
 && uv venv --seed --python ${PY3_VERSION} /opt/py3
# 虚拟环境放在 PATH 最前面：python、python3、pip 都指向 Python 3；
# python2 仍是系统的 Python 2.7，给它装库用 python2 -m pip
ENV VIRTUAL_ENV=/opt/py3 \
    PATH=/opt/py3/bin:$PATH
COPY env/docker/requirements-py3.txt /tmp/requirements-py3.txt
RUN uv pip install --python /opt/py3/bin/python -r /tmp/requirements-py3.txt

# ---------- Python 2.7 ----------
COPY env/docker/requirements-py2.txt /tmp/requirements-py2.txt
RUN ln -sf /usr/local/bin/python2.7 /usr/local/bin/python2 \
 && python2 -m pip install -r /tmp/requirements-py2.txt

# ---------- ctfkit ----------
COPY core /opt/ctfkit-src
RUN uv pip install --python /opt/py3/bin/python /opt/ctfkit-src

COPY env/docker/motd.sh /etc/profile.d/ctfkit-motd.sh
COPY env/docker/check.sh /usr/local/bin/ctfkit-check
RUN chmod +x /usr/local/bin/ctfkit-check

WORKDIR /work
CMD ["bash", "-l"]
