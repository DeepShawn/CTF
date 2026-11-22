# CTF 工具包计划稿

| 项目 | 内容 |
|---|---|
| 文档状态 | 计划稿，待确认 |
| 编写日期 | 2026-11-22 |
| 项目暂名 | CTFKit（中文名：CTF 工具包，名称待定，见第 10 节） |
| 目标平台 | Web、Android、iOS |
| 界面设计 | 仅使用 [TesseraUI](https://github.com/DeepShawn/TesseraUI) |
| 开源协议 | MIT |
| 内容范围 | 对照参考教材目录第 0～8 章（CTF 入门、安全杂项、隐写、密码学、Web、逆向、PWN、工业控制系统安全） |

本计划共五份文档：

| 文档 | 内容 |
|---|---|
| 本文 | 定位、架构、Python 环境、界面设计、版本路线、待决事项 |
| [tools.md](tools.md) | 按教材章节列出的工具清单，标明各端能否运行 |
| [explainers.md](explainers.md) | 部分内容讲解（附可运行代码，已在 Python 2.7 和 3.13 上验证） |
| [range.md](range.md) | 后续的靶场与例题规划 |
| [snippets/](snippets/) | 讲解中用到的示例脚本，可直接运行 |

---

## 1. 项目定位

### 1.1 要解决的问题

初学者刚开始做 CTF 题，常遇到下面几个问题：

1. **工具太分散**。编码转换要用一个网站，隐写要装一个软件，密码学要写脚本，这些工具各有各的安装方式，有的只能在 Windows 上用，有的已经很久没人维护。
2. **环境装不好**。网上的题解有的用 Python 2 写，有的用 Python 3 写，`gmpy2`、`pwntools` 在 Windows 上也不好装，入门的第一周常常耗在配环境上。
3. **只会用、不知道为什么**。很多在线工具点一下就出结果，用户不知道原理，题目稍微变一下就做不出来了。
4. **手机上没法用**。在通勤路上或者比赛现场只有手机时，没有趁手的工具。

### 1.2 目标

做一个**三端一致、开箱可用、讲清原理**的 CTF 工具包：

- **三端一致**：Web、Android、iOS 用同一套算法代码、同一套界面设计（TesseraUI），功能和结果一样。
- **开箱可用**：Web 打开网页就能用；App 安装后不用联网也能用（不含需要联网的功能）；电脑上用一条 Docker 命令就能得到装好 Python 2 和 Python 3 的完整环境。
- **讲清原理**：每个工具都附“原理”和“Python 代码”两部分。代码可以在 App 里直接运行、修改，也可以复制到自己电脑上运行。
- **对照教材**：工具与讲解按参考教材的章节编排，看书时可以找到对应的工具，用工具时也能找到对应的章节。

### 1.3 面向用户

| 用户 | 需求 | 主要使用的部分 |
|---|---|---|
| 刚接触 CTF 的学生 | 知道每类题怎么入手，有能直接用的工具 | 学习路径、工具 + 原理讲解 |
| 有一定基础的选手 | 工具快、手机上也能用、可以自己写脚本 | 工具、脚本运行、Docker 环境 |
| 教师、社团负责人 | 有现成的例题和靶场用于教学 | 例题库、靶场（后续） |

### 1.4 不做的事

- **不做攻击平台**。端口扫描、目录探测、密码爆破这类会对他人系统产生影响的功能，App 和 Web 版只提供原理说明与命令参考，实际运行放在用户自己电脑上的 Docker 环境中，只用于自己搭建的靶场或已获授权的目标。
- **不替代专业软件**。IDA、Ghidra、Wireshark、Burp Suite 这类软件不重做，工具包讲清楚怎么用它们，并补上它们不方便做的小功能。
- **不照搬教材**。讲解和例题全部原创，只沿用教材的章节顺序作为目录，不复制教材的正文、插图和例题。

### 1.5 使用声明

本工具包仅用于学习、CTF 比赛与已获得授权的安全测试。根据《中华人民共和国网络安全法》等法律法规，未经授权对他人计算机系统进行扫描、入侵或破坏属于违法行为。这段声明会放在 README、App 首次启动页和每个涉及网络操作的工具页中。

---

## 2. 总体架构

### 2.1 核心思路：算法只写一份 Python

工具的算法统一用 **Python 3** 编写，做成一个 Python 包 `ctfkit`，三端都内置 Python 3 运行时来执行它：

```
                  ┌───────────────────────────┐
                  │   ctfkit（Python 3 包）     │  ← 算法只写一份
                  │   + 工具描述文件（JSON）    │  ← 界面也由它生成
                  └─────────────┬─────────────┘
        ┌───────────────┬───────┴───────┬──────────────────┐
        ▼               ▼               ▼                  ▼
   Web（浏览器）    Android App       iOS App         Docker 完整环境
   Pyodide          Chaquopy          CPython 3.13     Python 3 + Python 2.7
   (WebAssembly)    (内嵌 CPython)    (官方 iOS 支持)   + pwntools 等全部工具
        │               │               │
   TesseraUI Web    TesseraUI         TesseraUI
   (CSS + JS)       (Jetpack Compose) (SwiftUI)
```

采用这一方案的原因：

1. **代码本身就是教材**。初学者在工具页里看到的 Python 代码就是实际运行的代码，不存在“界面里用 JavaScript 算、讲解里用 Python 写”的两套逻辑。
2. **结果三端一致**。同一份代码、同一组测试用例，不会出现 Web 端和 App 端解码结果不同的情况。
3. **与 CTF 生态一致**。CTF 的题解、脚本、常用库（`pycryptodome`、`gmpy2`、`pwntools`、`Pillow`）几乎都是 Python。

代价与应对：

| 代价 | 应对 |
|---|---|
| Web 端首次加载 Pyodide 约 10 MB | 放在 Web Worker 中后台加载，加载时界面可正常浏览；PWA 缓存后再次打开无需下载；常用库按需加载 |
| App 安装包增大（每个平台约 20～40 MB） | 只打包用到的标准库模块与第三方库；大型库（如 `sympy`）做成首次使用时下载的可选组件 |
| 部分 C 扩展库在移动端没有现成版本 | 以 Pyodide 与 Chaquopy 的官方包列表为准，缺的库在 `ctfkit` 中提供纯 Python 的替代实现（见 2.4 节） |

### 2.2 工具描述文件：界面也只定义一次

每个工具除了 Python 函数之外，还有一份描述文件，说明有哪些输入、哪些选项、输出是什么。三端界面根据描述文件自动生成工具页，新增一个工具不需要分别写三套界面。

```json
{
  "id": "encoding.base64",
  "title": "Base64 编码 / 解码",
  "chapter": "1.1.1",
  "category": "编码",
  "entry": "ctfkit.encoding.base64:run",
  "inputs": [
    { "id": "text", "type": "text", "label": "输入", "multiline": true }
  ],
  "options": [
    { "id": "mode", "type": "segmented", "label": "模式", "choices": ["编码", "解码"], "default": "解码" },
    { "id": "alphabet", "type": "select", "label": "码表", "choices": ["标准", "URL 安全", "自定义"], "default": "标准" },
    { "id": "custom", "type": "text", "label": "自定义码表", "visibleWhen": { "alphabet": "自定义" } }
  ],
  "outputs": [
    { "id": "result", "type": "text", "copyable": true }
  ],
  "explainer": "content/explainers/base64.md",
  "offline": true,
  "platforms": ["web", "android", "ios", "docker"]
}
```

描述文件中的字段类型（`text`、`segmented`、`select`、`file`、`number`、`switch` 等）与 TesseraUI 组件一一对应，见第 5 节。少数界面特殊的工具（如十六进制编辑器、频谱图）单独编写页面。

### 2.3 仓库结构

```
CTF/
├── core/                 Python 包 ctfkit：全部工具算法、工具描述文件、单元测试
│   ├── ctfkit/
│   │   ├── encoding/     编码（教材 1.1）
│   │   ├── traffic/      流量分析（1.2）
│   │   ├── forensics/    日志、电子取证、压缩包（1.3～1.5）
│   │   ├── stego/        隐写（第 2 章）
│   │   ├── crypto/       密码学（第 3 章）
│   │   ├── web/          Web 辅助工具（第 4 章）
│   │   ├── reverse/      逆向辅助工具（第 5 章）
│   │   ├── pwn/          PWN 辅助工具（第 6～7 章）
│   │   └── ics/          工控协议解析（第 8 章）
│   ├── manifests/        工具描述文件（JSON）
│   └── tests/
├── apps/
│   ├── web/              Web 版：TesseraUI Web + Pyodide
│   ├── android/          Android 版：Jetpack Compose + TesseraUI + Chaquopy
│   └── ios/              iOS 版：SwiftUI + TesseraUI + CPython
├── env/
│   ├── docker/           完整环境镜像：Python 3、Python 2.7、命令行工具
│   └── setup/            不使用 Docker 时的本机安装脚本（Windows / macOS / Linux）
├── content/              三端共用的内容：讲解、学习路径、例题（Markdown + YAML）
├── range/                靶场（后续，见 range.md）
├── docs/                 用户文档与开发文档
├── plan/                 本计划
├── LICENSE               MIT
└── README.md
```

### 2.4 第三方库在各端的可用性

下表为计划阶段的判断，每一项都会在 v0.1 实施时逐一验证，结果更新到本表。

| 库 | 用途 | Web（Pyodide） | Android（Chaquopy） | iOS | Docker | 缺失时的替代 |
|---|---|---|---|---|---|---|
| 标准库（`base64`、`hashlib`、`zlib`、`struct`、`zipfile` 等） | 编码、哈希、文件格式 | 有 | 有 | 有 | 有 | — |
| `pycryptodome` | AES、DES、RSA 等 | 有（官方包） | 有 | 需自行编译 | 有 | 纯 Python 的教学版实现（速度慢但结果一致） |
| `Pillow` | 图片隐写 | 有 | 有 | 需自行编译 | 有 | 无，iOS 端改用系统图像接口取像素后交给 Python |
| `numpy` | 图像、音频数值处理 | 有 | 有 | 需自行编译 | 有 | 纯 Python 循环（只用于小文件） |
| `gmpy2` | 大数运算 | 待验证 | 待验证 | 需自行编译 | 有 | Python 内置大整数 + `ctfkit.crypto.nt`（开方、模逆、CRT 等） |
| `sympy` | 分解、数论 | 有（纯 Python） | 有 | 有 | 有 | — |
| `pwntools` | PWN 交互、ROP | 无 | 无 | 无 | 有 | 移动端提供 `cyclic`、`p32/p64`、格式化字符串载荷计算等纯 Python 小功能 |
| `scapy` / `dpkt` | 流量解析 | `dpkt` 可用（纯 Python） | 同左 | 同左 | 都有 | 统一使用 `dpkt` 解析 pcap |
| `pyelftools` | ELF 解析 | 有（纯 Python） | 有 | 有 | 有 | — |
| `z3-solver` | 约束求解（逆向） | 待验证 | 无 | 无 | 有 | 只在 Docker 中提供 |

---

## 3. Python 环境（Python 2 / Python 3）

### 3.1 为什么还要 Python 2

Python 2 已于 2020 年 1 月 1 日停止维护，新代码一律使用 Python 3。但 CTF 中仍有不少 Python 2 的材料：较早的比赛题解、教材中的部分脚本、个别只支持 Python 2 的老工具。初学者照着这些材料练习时，需要一个能直接运行 Python 2 的环境，同时要知道 Python 2 和 Python 3 的区别，才能自己把旧脚本改成 Python 3。

因此本项目的做法是：**工具本身用 Python 3；讲解中的示例代码尽量写成 Python 2 和 Python 3 都能运行；另外提供真正的 Python 2.7 环境，用来运行旧脚本。**

### 3.2 各端的 Python 环境

| 环境 | Python 3 | Python 2 | 说明 |
|---|---|---|---|
| **Web** | Pyodide（CPython 编译为 WebAssembly），在浏览器中运行 | 不提供 | Pyodide 只有 Python 3。Web 端提供“Python 2 → 3 检查”：粘贴旧脚本后指出 `print` 语句、`str`/`bytes` 混用等需要修改的地方，并给出修改建议 |
| **Android** | Chaquopy（MIT 协议，内嵌 CPython 3），支持 Android 7.0（API 24）以上，与 TesseraUI 的最低版本一致 | 不提供 | 同 Web 端的检查功能 |
| **iOS** | CPython 3.13 起官方支持 iOS（PEP 730），以 XCFramework 方式内嵌 | 不提供 | 只运行用户自己输入或随 App 打包的脚本，不从网络下载可执行代码，以符合 App Store 审核要求；Pythonista、Pyto 等应用已有上架先例 |
| **Docker 完整环境** | Python 3（与 Pyodide 保持同一小版本） | Python 2.7.18 | 两个版本互相独立，命令分别为 `python3` 和 `python2`；各自装好 CTF 常用库 |
| **本机安装** | 使用 `uv` 创建虚拟环境 | 推荐使用 Docker；坚持本机安装时提供 `pyenv` 安装指引 | 适合不想用 Docker 的用户，提供 Windows / macOS / Linux 三套脚本 |

### 3.3 Docker 完整环境

一条命令启动，进入后两个 Python 版本和常用工具都已装好：

```bash
docker run -it --rm -v "$PWD:/work" ghcr.io/deepshawn/ctfkit:latest
```

镜像内容（计划）：

| 类别 | 内容 |
|---|---|
| Python 3 | `ctfkit`、`pwntools`、`pycryptodome`、`gmpy2`、`sympy`、`z3-solver`、`Pillow`、`numpy`、`scapy`、`pyelftools`、`requests` |
| Python 2.7 | `pwntools`（固定在仍支持 Python 2.7 的最后一个版本，构建时验证）、`pycryptodome`、`gmpy2`、`Pillow`、`requests` |
| 杂项与取证 | `binwalk`、`foremost`、`exiftool`、`steghide`、`tshark`、`file`、`xxd` |
| 密码与爆破 | `john`、`hashcat`（CPU 版）、`fcrackzip` |
| 逆向与 PWN | `gdb` + `pwndbg`、`radare2`、`checksec`、`ROPgadget`、`one_gadget`、多版本 `glibc`（2.23 / 2.27 / 2.29 / 2.31 / 2.35，对应教材第 7 章各节） |
| Web | `sqlmap`、`dirsearch`、`nmap`（仅用于自己的靶场或已获授权的目标） |

镜像分两个标签：`latest`（完整，约 3 GB）和 `lite`（只含两个 Python 版本与 Python 库，约 600 MB），满足不同网络条件。

### 3.4 本地运行器（可选）

有些功能在浏览器和手机上做不到，例如运行 Python 2 脚本、调用 `gdb`、使用 `z3`。为此 Docker 环境内置一个“本地运行器”：

- 在电脑上启动 Docker 环境后，运行器默认只监听本机地址 `127.0.0.1`，Web 版可以把脚本交给它，用 Python 2 或完整的 Python 3 环境运行，结果显示在网页中。
- 手机 App 需要使用时，用户在电脑上手动开启“局域网模式”，App 扫描电脑上显示的二维码完成配对（二维码中包含一次性令牌）。未配对的设备无法提交脚本。
- 运行器只执行用户主动提交的脚本，每次运行都在独立的临时容器中进行，有时间与内存上限，默认不能联网。

这一功能默认关闭，不开启时三端仍可正常使用全部离线工具。

---

## 4. 功能结构

### 4.1 五个主页面

| 页面 | 内容 |
|---|---|
| **工具** | 按教材章节分类的全部工具；顶部搜索；“智能识别”入口（粘贴一段文本，自动尝试常见编码并按可能性排序，对应教材 1.1.13 节的通用解题方法） |
| **学习** | 学习路径（按章节从易到难）；每节的原理讲解；Python 2 / 3 差异专题 |
| **脚本** | 内置 Python 3 编辑器与运行；常用脚本模板（RSA 解密、爆破 CRC、批量解码等）；可选通过本地运行器使用 Python 2 |
| **例题** | 例题库与题解（后续版本）；靶场入口（后续版本） |
| **我的** | 收藏的工具、历史记录、外观设置（三种外观、浅色 / 深色）、本地运行器配对、关于与开源许可 |

### 4.2 工具页的统一结构

每个工具页都由同样的四个部分组成，初学者用过一个工具就会用其他工具：

1. **输入**：文本框或文件上传，支持粘贴、拖入文件、从其他工具的输出直接传入。
2. **选项**：模式、码表、密钥等。
3. **输出**：结果文本或文件，可复制、可保存、可“交给下一个工具”继续处理（连续解多层编码时很常用）。
4. **讲解**（折叠）：“原理”与“Python 代码”两个标签页；代码可以一键在“脚本”页打开修改运行。

### 4.3 工具清单

完整清单按教材第 0～8 章逐节列出，并标明每个工具在各端的可用性，见 [tools.md](tools.md)。概要如下：

| 教材章节 | 工具包中的内容 | 三端离线可用 |
|---|---|---|
| 第 0 章 开启 CTF 之旅 | 学习路径、赛制介绍、环境搭建向导（虚拟机、Python、Docker） | 全部 |
| 第 1 章 安全杂项 | 18 种编码互转与智能识别、pcap 流量分析、日志分析、文件识别与恢复、ZIP 伪加密修复、CRC 碰撞、压缩包字典爆破 | 大部分；已知明文攻击、大文件取证需 Docker |
| 第 2 章 隐写术 | PNG / JPG / GIF 结构查看与修复、LSB 提取、通道与位平面浏览、像素与图片互转、音频波形与频谱、拨号音识别、零宽字符与空白隐写、二维码识别与修复 | 大部分；steghide 等需 Docker |
| 第 3 章 密码学 | 古典密码 12 种（含爆破与词频分析）、XOR、RC4、DES、AES 与分组模式、RSA 常见攻击、ECC 基础、哈希计算与长度扩展攻击 | 大部分；大数分解等耗时运算建议 Docker |
| 第 4 章 Web 渗透基础 | HTTP 请求构造与解析、编码与载荷参考、PHP 弱类型速查、JWT 解析、SQL 注入 / 文件包含 / XSS / SSRF 原理与载荷速查 | 速查与本地计算全部可用；对目标发起请求只在 Docker 中针对靶场进行 |
| 第 5 章 软件逆向工程 | 文件头识别、ELF / PE 结构查看、字符串提取、常见算法特征识别、x86 / x64 汇编速查 | 全部 |
| 第 6～7 章 PWN | checksec、偏移计算（cyclic）、打包解包、格式化字符串载荷生成、ROP 链辅助、glibc 堆结构速查 | 计算类全部可用；调试与远程交互需 Docker |
| 第 8 章 工业控制系统安全 | Modbus / S7 报文解析、梯形图与指令表速查、工控流量题解析 | 全部 |

---

## 5. 界面设计（仅使用 TesseraUI）

### 5.1 原则

- **只用 TesseraUI**：三端的全部界面控件都来自 TesseraUI，不引入 Material Components、Bootstrap 等其他界面库；颜色、字体、间距、圆角、动效全部取自 TesseraUI 的设计令牌，不在本项目中写死数值。
- **跟随 TesseraUI 的三种外观**：拼贴（默认）、圆融、流韵三种外观以及浅色 / 深色 / 增强对比度都直接沿用，用户在“我的”页中切换。
- **TesseraUI 缺少的控件**：先确认是否属于通用控件。如果是（如代码编辑器），提交到 TesseraUI 上游，由 TesseraUI 统一实现三端版本；如果是本项目专用的（如频谱图），在本项目中基于 TesseraUI 的令牌自绘，不引入第三方界面库。

### 5.2 引入方式

| 端 | 方式 |
|---|---|
| Web | 以 Git 子模块引入 TesseraUI，使用其 `platforms/web/dist` 中的 `tessera.css` 与 `tessera.js` |
| Android | 将 `platforms/android/tessera` 作为 Gradle 模块引入 |
| iOS | 通过 Swift Package Manager 引入 `platforms/apple`（最低 iOS 17） |

三端都固定使用 TesseraUI 的某个发布版本，升级时单独提交并重新跑截图测试。

### 5.3 组件使用对照

| 界面部分 | 使用的 TesseraUI 组件 |
|---|---|
| 主导航 | 手机：TabBar + NavBar；平板与桌面网页：Sidebar + SplitPane |
| 工具列表 | SearchField、Tabs（章节分类）、List、Card、Tag（“离线”“需 Docker”等标记）、Badge |
| 工具输入 | TextArea、TextField、PasswordField、NumberInput、FileUpload、Select、SegmentedControl、Switch、Slider |
| 工具输出 | CodeBlock（可复制）、Table（如词频统计、字段解析）、DescriptionList（文件结构信息）、ImageViewer（隐写结果图） |
| 讲解 | Accordion（折叠讲解）、Tabs（原理 / Python 3 / Python 2）、CodeBlock、Kbd |
| 反馈 | Toast（已复制）、Banner（使用声明、需要 Docker 的提示）、Progress / Spinner / Skeleton（Python 运行时加载）、Result、EmptyState、Dialog、BottomSheet |
| 学习路径 | Steps、Timeline、Progress |
| 例题 | Card、Tag（难度、分类）、Rating、Result（flag 正确 / 错误） |
| 设置 | List、Switch、SegmentedControl（外观）、Select |
| 智能识别 | CommandPalette（桌面网页的快捷入口）、Table（候选结果） |

### 5.4 与 TesseraUI 进度的衔接

- **Web**：TesseraUI Web 端已有全部 84 个组件，可以立即开始。
- **Android / iOS**：TesseraUI 原生端到 v0.6.0 已有约 61 个组件，已覆盖上表中的手机界面。平板布局需要的 Sidebar、SplitPane，以及 Steps、ConfirmDialog、ActionSheet，排在 TesseraUI v0.7.0。本项目原生端先做手机布局，平板布局在 TesseraUI v0.7.0 发布后再做。
- **需要向 TesseraUI 上游提出的组件**（待与 TesseraUI 的计划协调，见第 10 节）：

| 组件 | 用途 | 未实现前的过渡方案 |
|---|---|---|
| CodeEditor（代码编辑器：语法高亮、行号、缩进、Tab 键） | “脚本”页 | TextArea + 等宽字体，运行后用 CodeBlock 显示高亮版本 |
| HexView（十六进制查看：偏移、十六进制、ASCII 三栏，可选中联动） | 文件结构、隐写、逆向 | 用 CodeBlock 显示格式化好的十六进制文本，不支持联动选中 |

本项目专用、自绘的部分：音频波形图与频谱图、图片位平面浏览、二维码画图网格。它们只使用 TesseraUI 的颜色、圆角与动效令牌，外框与操作按钮仍用 TesseraUI 组件。

### 5.5 移动端注意事项

- 输入框沿用 TesseraUI 的中文输入法保护：拼音组合输入时不触发实时解码。
- 实时计算：文本类工具在输入停止 300 ms 后自动计算；超过 1 MB 的输入改为手动点击“运行”。
- 大文件（超过 50 MB 的 pcap、磁盘镜像）在手机上提示使用 Docker 环境处理。
- 所有输出都能通过系统分享菜单发送到其他 App。

---

## 6. 质量与测试

| 项目 | 要求 |
|---|---|
| 算法正确性 | `ctfkit` 每个工具都有单元测试，用公开的标准测试向量（如 RFC 4648 的 Base64 测试数据、NIST 的 AES 测试向量）；覆盖率不低于 90% |
| 三端一致性 | 同一组测试用例分别在 CPython、Pyodide、Chaquopy、iOS 上运行，结果必须完全相同（持续集成中执行） |
| 示例代码 | 讲解中标注“Python 2 / 3 通用”的代码，在持续集成中分别用 Python 2.7 和 Python 3 运行 |
| 界面 | 遵循 TesseraUI 的做法：每项交互测试截图，三种外观 × 浅色 / 深色；无障碍扫描严重与重要问题为 0 |
| 离线 | Web 端 PWA 与两个 App 在断网状态下，所有标记为“离线可用”的工具都能正常运行 |
| 隐私 | 工具处理的数据全部留在本机，不上传；App 不内置统计与广告 SDK |

---

## 7. 版本路线

周期按 1 名主要开发者估算，并行开发可以缩短。

| 版本 | 主题 | 主要内容 | 预计周期 |
|---|---|---|---|
| **v0.1** | 核心与环境 | `ctfkit` 包结构与工具描述文件格式；编码（1.1）、古典密码（3.1）、哈希（3.4）首批约 40 个工具；命令行入口；Docker 完整环境（Python 2.7 + 3）；2.4 节可用性表逐项验证 | 3 周 |
| **v0.2** | Web 版 | TesseraUI Web + Pyodide（Web Worker）；五个主页面；由描述文件生成工具页；PWA 离线；部署到 GitHub Pages | 3 周 |
| **v0.3** | Android 版 | Compose + TesseraUI + Chaquopy；手机布局；与 Web 共用工具描述文件 | 3～4 周 |
| **v0.4** | iOS 版 | SwiftUI + TesseraUI + CPython 3.13；手机布局；TestFlight 测试 | 3～4 周 |
| **v0.5** | 杂项、取证与隐写 | 教材第 1 章其余部分与第 2 章：流量、日志、取证、压缩包、图像 / 音频 / 文本隐写、二维码 | 4 周 |
| **v0.6** | 现代密码学与 Web | 第 3 章对称、非对称、哈希扩展攻击；第 4 章速查与本地工具；本地运行器 | 4 周 |
| **v0.7** | 逆向、PWN 与工控 | 第 5～8 章辅助工具；Docker 中的多版本 glibc；平板布局（依赖 TesseraUI v0.7.0） | 4 周 |
| **v0.8** | 学习内容 | 全部章节的原理讲解与学习路径；Python 2 / 3 差异专题；“脚本”页模板库 | 3 周 |
| **v0.9** | 例题库 | 每章至少 5 道原创例题与题解；离线验证 flag（见 range.md） | 3 周 |
| **v1.0** | 稳定版 | 接口与描述文件格式冻结；Google Play、App Store 上架；Docker 镜像发布到 GHCR；中英文文档 | 2 周 |
| **v1.x** | 靶场 | 基于 Docker Compose 的本地靶场，与例题对应（见 range.md） | 另行计划 |

每个版本完成后，在本表中勾选并注明实际完成情况，格式与 TesseraUI 的计划文档一致。

---

## 8. 开源协议与第三方组件

### 8.1 本项目

本项目全部代码与文档以 [MIT 协议](../LICENSE)发布，版权声明为 `Copyright (c) 2026 DeepShawn`。讲解、学习路径、例题等内容同样适用 MIT 协议。

### 8.2 第三方组件

第三方组件各自遵循其许可协议，在 App 的“关于 → 开源许可”页与仓库的 `THIRD_PARTY_NOTICES.md` 中逐一列出。

| 组件 | 协议 | 使用方式 | 注意事项 |
|---|---|---|---|
| TesseraUI | MIT | 三端界面 | 推荐字体均为 SIL OFL 1.1，需单独获取 |
| Pyodide | MPL-2.0 | Web 端 Python 运行时 | 原样分发，不修改其源码 |
| Chaquopy | MIT | Android 端 Python 运行时 | — |
| CPython | PSF License | 三端 Python 运行时 | — |
| pycryptodome | BSD / 公有领域 | 密码学 | — |
| Pillow | MIT-CMU（HPND） | 图像处理 | — |
| gmpy2 | LGPL-3.0 | Docker 环境 | 只在 Docker 镜像中以独立库形式提供，不静态链接进 App |
| pwntools | MIT（部分文件为 GPL） | Docker 环境 | 只在 Docker 镜像中提供 |
| sqlmap、gdb 等命令行工具 | GPL-2.0 / GPL-3.0 | Docker 环境 | 作为独立程序分发，不与本项目代码合并；镜像内附带各自的许可文本 |
| nmap | Nmap Public Source License | Docker 环境 | 该协议对再分发有额外限制，发布镜像前需确认条款；必要时改为由用户首次启动时自行安装 |

原则：**App 与 Web 版只包含与 MIT 兼容的宽松协议组件**；GPL 类工具只放在 Docker 镜像中，以独立程序方式提供。

---

## 9. 风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| App Store 审核对“执行代码”的限制 | iOS 版无法上架 | 不从网络下载代码；脚本只来自用户输入与 App 内置模板；审核说明中注明为教育用途；提前用 TestFlight 外部测试走一遍审核 |
| 应用商店将安全工具视为恶意软件 | 下架 | App 内不含主动攻击网络的功能；所有涉及网络的内容都是原理说明或只在用户自己的 Docker 中执行 |
| Pyodide / Chaquopy 缺少某些库 | 部分工具只能在 Docker 中用 | v0.1 先逐项验证（2.4 节）；提供纯 Python 替代实现；工具页明确标出“需 Docker” |
| 安装包过大 | 用户不愿下载 | 按需下载大型库；Web 端分包加载 |
| TesseraUI 原生端进度 | 平板布局推迟 | 先做手机布局；平板布局放在 v0.7 |
| Python 2 镜像不再更新 | 旧库无法安装 | 镜像构建时把 Python 2 的依赖固定到已验证版本并缓存安装包 |

---

## 10. 待决事项

需要项目负责人确认，越早确定返工越少：

- [ ] **项目名称**：暂名 CTFKit；仓库名沿用 `CTF`，还是改为独立名称
- [ ] **算法统一用 Python**（第 2.1 节）这一方案是否认可；另一种做法是用 Rust 写核心、编译到 WebAssembly 和移动端，速度更快，但初学者看不懂，也无法在 App 中直接修改
- [ ] **三端开发顺序**：建议 Web → Android → iOS（Web 最快验证，Android 上架门槛较低）
- [ ] **CodeEditor、HexView 两个组件**是否加入 TesseraUI 的计划（建议加入 v0.8.0 之前）
- [ ] **Docker 镜像发布位置**：GitHub Container Registry；国内用户访问较慢，是否同时发布到国内镜像源
- [ ] **参考教材的书名、作者**是否在文档中注明（目前只按章节编号对照，不引用正文）
- [ ] **内容语言**：先做中文，v1.0 加英文，是否认可
- [ ] **例题与靶场**是否接受社区投稿，以及投稿题目的版权要求（建议投稿同样以 MIT 协议授权）
