<p align="center">
  <img src="../../assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">看清 Portable Executable 的镜头 — 用 Rust 重新打造的 Windows 可执行文件静态恶意软件初步评估工具。</p>

<p align="center">
  <a href="https://github.com/taida957789/PELens/actions/workflows/ci.yml"><img src="https://github.com/taida957789/PELens/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  · <a href="https://taida957789.github.io/PELens/">Website</a>
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

PELens **不运行**文件，直接查看 `.exe`、`.dll`、`.sys` 的头部、导入、资源、证书、.NET 元数据和字符串，并生成映射到 MITRE ATT&CK 的指标。以 Rust 从零打造，由可扩展或替换的 XML 知识库驱动。

![指标（深色模式）](../screenshots/indicators-dark.png)

## 截图

| | |
|---|---|
| ![imports-dark](../screenshots/imports-dark.png) | ![strings-dark](../screenshots/strings-dark.png) |
| 导入：分组、MITRE 技术和标记 | 字符串：标签、位置分布图和分组 |
| ![sections-light](../screenshots/sections-light.png) | ![certificate-light](../screenshots/certificate-light.png) |
| 节区（浅色模式）与展开的树视图 | Authenticode 证书链与 WinVerifyTrust 结果 |
| ![dotnet-dark](../screenshots/dotnet-dark.png) | ![disassembly](../screenshots/disassembly-hex-dark.png) |
| .NET header、metadata streams、tables 和 namespaces | 反汇编（通过 IAT 的调用显示函数名）与十六进制视图 |

## 界面语言

| | |
|---|---|
| ![繁體中文](../screenshots/strings-zh-TW.png) | ![日本語](../screenshots/indicators-ja.png) |
| 繁體中文 | 日本語 |

界面默认跟随系统语言（Windows 显示语言、macOS 首选语言、Linux 的 `LANG`）；可在“视图 > 语言”或设置对话框中切换，或用 `-lang:<代码>` 启动（`en`、`zh-TW`、`zh-CN`、`ja`、`ko`、`es`、`de`、`fr`）。分析结果（表格内容、指标、报告）保持英文，与报告及搜索一致。翻译文件位于 `crates/pelens-gui/i18n/`。

## 功能

- **27 个视图**：image、footprints、groups、indicators、MITRE、VirusTotal 分数、DOS stub／header、Rich header、file／optional header、directories、sections、libraries、imports、exports、exceptions、certificate、relocations、TLS、.NET、resources、version、debug、strings、manifest、overlay。
- **150 个指标**，映射到 MITRE ATT&CK 战术与技术，严重度可调整。
- **签名引擎**：入口点签名（PEiD 风格，支持半字节通配符）、文本签名，以及在 resources、sections、overlay、base64 中检测嵌入文件。
- **不会崩溃的解析器**：imports（INT/IAT、延迟加载、bound）、exports（转发、匿名、空缺）、resources（version、manifest、字符串／消息表、对话框、菜单、图标）、debug（RSDS、POGO、REPRO、CET）、带 RFC 3161 时间戳的 Authenticode PKCS#7，以及 .NET 元数据（全部 45 张表）。
- **威胁狩猎辅助**：MD5/SHA-1/SHA-256 指纹、imphash（与 pefile 一致），并可跳转到 VirusTotal、Google、Microsoft Learn 和 MITRE。
- **文件修改**：DLL ⇄ EXE 切换、设置入口点、切换 characteristics、删除 overlay、导出任意项目、在新分析中打开嵌入文件。
- **报告**：XML、JSON、纯文本，内容与 GUI 显示的表格一致。
- **GUI**：树视图、深色／浅色主题、可排序和筛选的表格、右键菜单、拖放、快捷键（Ctrl+O、S、E、R、X；Tab 在树中移动）。
- **8 种界面语言**：English、繁體中文、简体中文、日本語、한국어、Español、Deutsch、Français，默认跟随系统语言。
- **十六进制视图**（Ctrl+H）：只绘制可见的行，大文件也流畅；各视图中带位置信息的项目可右键“在十六进制视图中显示”，并可转到偏移或 RVA、复制为十六进制或文本。
- **YARA 扫描**（YARA-X）：在设置 > YARA 或 `-yara:<dir>` 指定规则文件夹；每条命中的规则产生指标（严重性取自规则的 `severity` metadata），匹配位置可直接在十六进制视图中查看，也会写入报告。
- **反汇编**（x86／x64，iced-x86）：从入口点、导出函数或 TLS callback 开始；通过 IAT 调用的函数会显示名称，可跟随跳转目标，并可在十六进制视图中查看。
- **跨平台**：Windows、Linux、macOS 功能相同 — Authenticode 验证在非 Windows 平台使用内置的纯 Rust 验证器（Microsoft 根证书＋系统根证书）、VirusTotal key 存在系统凭据库（Windows 凭据管理器、macOS 钥匙串、Linux Secret Service）、网络／可移动磁盘与 ACL 检查、系统 CJK 字体，macOS 快捷键使用 ⌘。

## 安装／构建

**下载**：从 [Releases](https://github.com/taida957789/PELens/releases/latest) 下载对应平台的文件（`windows-x64.zip`, `linux-x86_64.tar.gz`, `macos-universal.zip`），各附 `.sha256` 可校验。Windows：解压后运行 `pelens.exe`。Linux：解压后运行 `./pelens`，或运行 `./install.sh` 安装到 `~/.local`（含桌面快捷方式和图标）。macOS（Apple silicon 与 Intel）：解压后将 `PELens.app` 拖入“应用程序”；首次打开请右键 > 打开（未经 Apple 公证）。从源码构建：

```bash
cargo build --release
# target/release/pelens      (GUI; pelens.exe on Windows)
# target/release/pelens-cli  (CLI; pelens-cli.exe on Windows)
```

需要 Rust 1.88 或更高版本（edition 2024）。CI 在 Windows、Linux、macOS 上构建并运行全部测试。

## 使用方法

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-lang:zh-TW] [-expand] [-hex] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir] [-yara:dir]
```

CLI 默认在样本旁输出 `<input>.xml`。

### 知识库

PELens 内置自己的**开放知识库**（`kb/`，CC0）：142 个指标定义、约 2,500 个 Windows API 函数、约 900 个可疑字符串、约 100 个签名，以及 MITRE ATT&CK 映射。它由 `tools/build_kb.py` 从 `kb/src` 生成，每一条数据都来自公开资料（见 [kb/SOURCES.md](../../kb/SOURCES.md)），没有复制任何第三方知识库。也可以用 `-xml:<dir>` 改用其他相同格式的 XML 知识库文件；第三方的知识库文件不随 PELens 分发。

### VirusTotal

只发送**哈希值**，从不上传样本。在设置对话框或 `VT_API_KEY` 环境变量中填入你自己的 API key。默认使用 API v3，也可选 v2。

## 项目结构

| crate | 用途 |
|---|---|
| `pe-parser` | PE 解析（边界检查、不会 panic）与修改 |
| `pe-db` | XML 知识库，读写时保留原格式 |
| `pe-analysis` | 指标、签名、字符串、视图、报告、操作 |
| `pe-online` | VirusTotal、搜索链接、更新检查 |
| `pelens-cli` | 命令行 |
| `pelens-gui` | eframe/egui 图形界面 |

设计文档：[功能清单](../FEATURE_INVENTORY.md)（212 项，每项附对照）· [开发计划](../DEVELOPMENT_PLAN.md) · [任务清单](../TASKLIST.md)。

## 质量

```bash
cargo test --workspace                       # 107 个测试
cargo llvm-cov --workspace --summary-only    # 约 97% 行覆盖率
python tools/crossval.py 250                 # 与 pefile 交叉验证
```

## 免责声明

PELens 是独立项目。请仅分析你有权分析的文件。
