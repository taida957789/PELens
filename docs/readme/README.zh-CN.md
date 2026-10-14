<p align="center">
  <img src="../../assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">看清 Portable Executable 的镜头 — 用 Rust 重新打造的 Windows 可执行文件静态恶意软件初步评估工具。</p>

<p align="center">
  [![CI](https://github.com/taida957789/PELens/actions/workflows/ci.yml/badge.svg)](https://github.com/taida957789/PELens/actions/workflows/ci.yml)
</p>

<p align="center">
  <a href="../../README.md">English</a> ·
  <a href="README.zh-TW.md">繁體中文</a> ·
  <b>简体中文</b> ·
  <a href="README.ja.md">日本語</a> ·
  <a href="README.ko.md">한국어</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.de.md">Deutsch</a> ·
  <a href="README.fr.md">Français</a>
</p>

---

PELens **不运行**文件，直接查看 `.exe`、`.dll`、`.sys` 的头部、导入、资源、证书、.NET 元数据和字符串，并生成映射到 MITRE ATT&CK 的指标。它是 **pestudio 9.61** 的 Rust 全新重制版，兼容 pestudio 的 XML 知识库和 `pestudiox` 命令行。

![指标（深色模式）](../screenshots/indicators-dark.png)

## 截图

| | |
|---|---|
| ![imports-dark](../screenshots/imports-dark.png) | ![strings-dark](../screenshots/strings-dark.png) |
| 导入：分组、MITRE 技术和标记 | 字符串：标签、位置分布图和分组 |
| ![sections-light](../screenshots/sections-light.png) | ![certificate-light](../screenshots/certificate-light.png) |
| 节区（浅色模式）与展开的树视图 | Authenticode 证书链与 WinVerifyTrust 结果 |
| ![dotnet-dark](../screenshots/dotnet-dark.png) | |
| .NET header、metadata streams、tables 和 namespaces | |

## 界面语言

| | |
|---|---|
| ![繁體中文](../screenshots/strings-zh-TW.png) | ![日本語](../screenshots/indicators-ja.png) |
| 繁體中文 | 日本語 |

界面默认跟随 Windows 的显示语言；可在“视图 > 语言”或设置对话框中切换，或用 `-lang:<代码>` 启动（`en`、`zh-TW`、`zh-CN`、`ja`、`ko`、`es`、`de`、`fr`）。分析结果（表格内容、指标、报告）保持英文，与报告及搜索一致。翻译文件位于 `crates/pelens-gui/i18n/`。

## 功能

- **27 个视图**（与 pestudio 相同）：image、footprints、groups、indicators、MITRE、VirusTotal 分数、DOS stub／header、Rich header、file／optional header、directories、sections、libraries、imports、exports、exceptions、certificate、relocations、TLS、.NET、resources、version、debug、strings、manifest、overlay。
- **150 个指标**，映射到 MITRE ATT&CK 战术与技术，严重度可调整。
- **签名引擎**：入口点签名（PEiD 风格，支持半字节通配符）、文本签名，以及在 resources、sections、overlay、base64 中检测嵌入文件。
- **不会崩溃的解析器**：imports（INT/IAT、延迟加载、bound）、exports（转发、匿名、空缺）、resources（version、manifest、字符串／消息表、对话框、菜单、图标）、debug（RSDS、POGO、REPRO、CET）、带 RFC 3161 时间戳的 Authenticode PKCS#7，以及 .NET 元数据（全部 45 张表）。
- **威胁狩猎辅助**：MD5/SHA-1/SHA-256 指纹、imphash（与 pefile 一致），并可跳转到 VirusTotal、Google、Microsoft Learn 和 MITRE。
- **文件修改**：DLL ⇄ EXE 切换、设置入口点、切换 characteristics、删除 overlay、导出任意项目、在新分析中打开嵌入文件。
- **报告**：XML、JSON、纯文本，内容与 GUI 显示的表格一致。
- **GUI**：树视图、深色／浅色主题、可排序和筛选的表格、右键菜单、拖放、快捷键（Ctrl+O、S、E、R、X；Tab 在树中移动）。
- **8 种界面语言**：English、繁體中文、简体中文、日本語、한국어、Español、Deutsch、Français，默认跟随 Windows 显示语言。

## 安装／构建

**下载**：从 [Releases](https://github.com/taida957789/PELens/releases/latest) 下载 `PELens-<版本>-windows-x64.zip`，解压后运行 `pelens.exe`，无需安装。附带 `.sha256` 可校验文件。从源码构建：

```bash
cargo build --release
# target/release/pelens.exe      (GUI)
# target/release/pelens-cli.exe  (CLI)
```

需要 Rust 1.88 或更高版本（edition 2024），在 Windows 11 x64 上开发和测试。

## 使用方法

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-lang:zh-TW] [-expand] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir]
```

CLI 默认在样本旁输出 `<input>.xml`，与 pestudio 相同。

### 知识库

PELens 从你自己安装的 pestudio 读取其 XML 文件（`settings.xml`、`indicators.xml`、`functions.xml`、`signatures.xml`…）：用 `-xml:<dir>` 指定，或在可执行文件旁放一个 `xml` 文件夹。**这些文件不随 PELens 分发**，它们属于 pestudio 的作者。没有它们时，PELens 仍会使用内置默认值运行。

### VirusTotal

只发送**哈希值**，从不上传样本。在设置对话框或 `VT_API_KEY` 环境变量中填入你自己的 API key。默认使用 API v3，也可选 v2。

## 项目结构

| crate | 用途 |
|---|---|
| `pe-parser` | PE 解析（边界检查、不会 panic）与修改 |
| `pe-db` | pestudio XML 知识库，读写时保留原格式 |
| `pe-analysis` | 指标、签名、字符串、视图、报告、操作 |
| `pe-online` | VirusTotal、搜索链接、更新检查 |
| `pelens-cli` | 命令行（兼容 pestudiox） |
| `pelens-gui` | eframe/egui 图形界面 |

设计文档：[功能清单](../FEATURE_INVENTORY.md)（212 项，每项附对照）· [开发计划](../DEVELOPMENT_PLAN.md) · [任务清单](../TASKLIST.md)。

## 质量

```bash
cargo test --workspace                       # 87 个测试
cargo llvm-cov --workspace --summary-only    # 约 97% 行覆盖率
python tools/crossval.py 250                 # 与 pefile 交叉验证
```

## 免责声明

PELens 是独立项目，与 Winitor 及 pestudio 作者无关，也未获其认可。请仅分析你有权分析的文件。
