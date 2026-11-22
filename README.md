<h1 align="center">CTFKit（暂名）</h1>

<p align="center">面向 Web、Android 与 iOS 的 CTF 工具包：开箱可用，讲清原理，适合初学者</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-0F6B63.svg"></a>
  <img alt="Status" src="https://img.shields.io/badge/status-计划中-B7862B.svg">
  <img alt="Platforms" src="https://img.shields.io/badge/platforms-Web%20%7C%20Android%20%7C%20iOS-1F1B16.svg">
  <img alt="Python" src="https://img.shields.io/badge/python-2.7%20%7C%203-3D6B1C.svg">
</p>

---

> 本项目目前处于**计划阶段**，尚无可用代码。计划稿见 [plan/README.md](plan/README.md)。

## 简介

CTFKit 是一个 CTF（夺旗赛）工具包。它按参考教材的章节编排，覆盖安全杂项、隐写术、密码学、Web、逆向、PWN 与工业控制系统安全等方向：

- **三端一致**：Web、Android、iOS 使用同一份 Python 算法代码与同一套 [TesseraUI](https://github.com/DeepShawn/TesseraUI) 界面设计；
- **开箱可用**：Web 版打开即用，App 离线可用；电脑上用一条 Docker 命令即可获得装好 Python 2.7 与 Python 3 的完整环境；
- **讲清原理**：每个工具附原理讲解与可运行、可修改的 Python 代码。

## 计划文档

| 文档 | 内容 |
|---|---|
| [计划总览](plan/README.md) | 定位、架构、Python 环境、界面设计、版本路线、待决事项 |
| [工具清单](plan/tools.md) | 按教材第 0～8 章逐节列出的工具与各端可用性 |
| [部分内容讲解](plan/explainers.md) | 九个知识点的讲解示范，附可运行代码 |
| [靶场与例题](plan/range.md) | 例题格式、离线验证 flag、本地靶场的安全要求 |
| [示例脚本](plan/snippets/) | 讲解中的代码，Python 2.7 / 3 通用 |

## 使用声明

本项目仅用于学习、CTF 比赛与已获得授权的安全测试。未经授权对他人计算机系统进行扫描、入侵或破坏，违反《中华人民共和国网络安全法》等法律法规。使用者须自行承担因不当使用产生的一切后果。

## 许可协议

本项目以 [MIT 许可协议](LICENSE)发布。第三方组件遵循其各自的许可协议，详见[计划总览第 8 节](plan/README.md#8-开源协议与第三方组件)。

Copyright © 2026 DeepShawn
