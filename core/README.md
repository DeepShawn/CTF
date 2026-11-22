# ctfkit：CTFKit 核心库

CTFKit 的全部工具算法。Web、Android、iOS 三端和 Docker 环境运行的都是这一份 Python 代码。

- 需要 Python 3.8 及以上，**只用标准库**，没有第三方依赖；
- 每个工具都是一个普通函数，用 `@tool(...)` 登记标题、教材章节、参数与原理讲解；
- 三端界面根据 `ctfkit manifest` 导出的描述文件自动生成工具页（见 [ctfkit/registry.py](ctfkit/registry.py)）。

## 安装与使用

```bash
cd core
pip install .            # 或者不安装，直接用 python3 -m ctfkit

ctfkit list                                        # 列出全部工具
ctfkit info classical.caesar                       # 查看参数与原理
ctfkit info classical.caesar --source              # 同时显示源代码
ctfkit run encoding.base64 "ZmxhZ3toaX0="          # 运行工具（默认解码）
ctfkit run encoding.base64 -s mode=编码 "flag{hi}"  # 用 -s 参数=值 设置选项
ctfkit run classical.caesar "synt{pnrfne}"         # 凯撒密码：枚举 26 种位移
echo "Wm14aFozdG9hWDA9" | ctfkit magic -           # 智能识别，从标准输入读取
ctfkit run hash.crack -s template="flag{*}" -s max_len=3 <MD5 值>
```

在 Python 中调用：

```python
from ctfkit.registry import run
print(run("encoding.base64", {"text": "ZmxhZ3toaX0="}))
# {'ok': True, 'output': {'type': 'text', 'value': 'flag{hi}'}}
```

## v0.1 工具清单（42 个）

| 分类 | 教材章节 | 工具 |
|---|---|---|
| 编码 | 1.1 | Base64（含换表）、Base32、Base16、Base58、Base62、Base85 / ASCII85、Base91、Base92、ASCII 转换、ASCII 码表、Shellcode、Quoted-printable、UUencode、XXencode、URL、摩斯密码、Brainfuck / Ook!、Unicode 转义、HTML 实体、进制转换、文本处理、核心价值观编码、**智能识别** |
| 古典密码 | 3.1 | 凯撒（枚举并排序）、ROT5 / 13 / 18 / 47、Atbash、仿射（枚举 312 组密钥）、栅栏（普通型 / W 型）、简单替换、词频分析、培根（24 / 26 字母）、波利比奥斯方阵、键盘 / 九宫格 / 当铺密码、维吉尼亚（含**无密钥破解**）与博福特、希尔、Playfair |
| 哈希 | 3.4 | 哈希计算（MD5、SHA 系列、SHA-3、BLAKE2、CRC32）、HMAC、类型识别、短明文 / 字典爆破 |
| 通用 | 0.4.1 | Python 2 → 3 检查、flag 搜索 |

JSFuck（教材 1.1.11）需要 JavaScript 引擎求值，Python 中无法可靠实现，移到 Web 版 v0.2 实现。

## 测试

```bash
cd core
python3 -m unittest discover -s tests -v
```

测试包括 RFC 4648、NIST 等标准测试向量，每个工具的示例，以及全部编码工具的“编码 → 解码”往返测试。持续集成在 Python 3.8、3.13、3.14 上运行。

## 新增工具

1. 在对应模块中写一个函数，用 `@tool(...)` 登记（参考已有工具，`principle` 必须写原理讲解）；
2. 新模块要在 [ctfkit/tools.py](ctfkit/tools.py) 中导入；
3. 在 `examples` 中至少给一个示例，测试会自动运行它；
4. 运行测试。界面不需要修改。
