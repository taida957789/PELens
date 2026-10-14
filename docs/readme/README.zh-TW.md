<p align="center">
  <img src="../../assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">看清 Portable Executable 的鏡頭 — 以 Rust 重新打造的 Windows 執行檔靜態惡意程式初步評估工具。</p>

<p align="center">
  <a href="https://github.com/taida957789/PELens/actions/workflows/ci.yml"><img src="https://github.com/taida957789/PELens/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  · <a href="https://taida957789.github.io/PELens/">Website</a>
</p>

<p align="center">
  <a href="../../README.md">English</a> ·
  <b>繁體中文</b> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ja.md">日本語</a> ·
  <a href="README.ko.md">한국어</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.de.md">Deutsch</a> ·
  <a href="README.fr.md">Français</a>
</p>

---

PELens **不執行**檔案，直接檢視 `.exe`、`.dll`、`.sys` 的標頭、匯入、資源、憑證、.NET metadata 與字串，並產生對應 MITRE ATT&CK 的指標。它是 **pestudio 9.61** 的 Rust 全新重製版，相容 pestudio 的 XML 知識庫與 `pestudiox` 命令列。

![指標（暗色模式）](../screenshots/indicators-dark.png)

## 截圖

| | |
|---|---|
| ![imports-dark](../screenshots/imports-dark.png) | ![strings-dark](../screenshots/strings-dark.png) |
| 匯入：群組、MITRE 技術與旗標 | 字串：標籤、位置分佈圖與群組 |
| ![sections-light](../screenshots/sections-light.png) | ![certificate-light](../screenshots/certificate-light.png) |
| 區段（亮色模式）與展開的 tree-view | Authenticode 憑證鏈與 WinVerifyTrust 結果 |
| ![dotnet-dark](../screenshots/dotnet-dark.png) | ![disassembly](../screenshots/disassembly-hex-dark.png) |
| .NET header、metadata streams、tables 與 namespaces | 反組譯（經由 IAT 的呼叫顯示函式名稱）與十六進位檢視 |

## 介面語言

| | |
|---|---|
| ![繁體中文](../screenshots/strings-zh-TW.png) | ![日本語](../screenshots/indicators-ja.png) |
| 繁體中文 | 日本語 |

介面預設跟隨 Windows 的顯示語言；可在「檢視 > 語言」或設定對話框中切換，或用 `-lang:<代碼>` 啟動（`en`、`zh-TW`、`zh-CN`、`ja`、`ko`、`es`、`de`、`fr`）。分析結果（表格內容、指標、報告）維持英文，與報告及搜尋一致。翻譯檔位於 `crates/pelens-gui/i18n/`。

## 功能

- **27 個檢視**（與 pestudio 相同）：image、footprints、groups、indicators、MITRE、VirusTotal 分數、DOS stub／header、Rich header、file／optional header、directories、sections、libraries、imports、exports、exceptions、certificate、relocations、TLS、.NET、resources、version、debug、strings、manifest、overlay。
- **150 個指標**，對應 MITRE ATT&CK 戰術與技術，嚴重度可調整。
- **簽章引擎**：entry-point 簽章（PEiD 風格，支援半位元組 wildcard）、文字簽章，以及 resources、sections、overlay、base64 中的嵌入檔偵測。
- **不會崩潰的解析器**：imports（INT/IAT、delay-load、bound）、exports（forwarded、anonymous、gaps）、resources（version、manifest、字串／訊息表、對話框、選單、圖示）、debug（RSDS、POGO、REPRO、CET）、含 RFC 3161 時間戳記的 Authenticode PKCS#7，以及 .NET metadata（全部 45 種表）。
- **威脅獵捕輔助**：MD5/SHA-1/SHA-256 指紋、imphash（與 pefile 相同），並可連結到 VirusTotal、Google、Microsoft Learn 與 MITRE。
- **檔案修改**：DLL ⇄ EXE 切換、設定 entry-point、切換 characteristics、刪除 overlay、匯出任何項目、在新分析中開啟嵌入檔。
- **報告**：XML、JSON、純文字，內容與 GUI 顯示的表格相同。
- **GUI**：tree-view、暗色／亮色主題、可排序與篩選的表格、右鍵選單、拖放、快捷鍵（Ctrl+O、S、E、R、X；Tab 在樹狀中移動）。
- **8 種介面語言**：English、繁體中文、简体中文、日本語、한국어、Español、Deutsch、Français，預設跟隨 Windows 顯示語言。
- **十六進位檢視**（Ctrl+H）：只繪製可見的列，大檔案也流暢；各檢視中有位置資訊的項目可右鍵「在十六進位檢視中顯示」，並可前往位移或 RVA、複製為十六進位或文字。
- **YARA 掃描**（YARA-X）：在設定 > YARA 或 `-yara:<dir>` 指定規則資料夾；每條命中的規則產生指標（嚴重度取自規則的 `severity` metadata），比對位置可直接在十六進位檢視中查看，也會寫入報告。
- **反組譯**（x86／x64，iced-x86）：從進入點、匯出函式或 TLS callback 開始；經由 IAT 呼叫的函式會顯示名稱，可跟隨跳躍目標，並可在十六進位檢視中查看。

## 安裝／建置

**下載**：到 [Releases](https://github.com/taida957789/PELens/releases/latest) 下載 `PELens-<版本>-windows-x64.zip`，解壓縮後執行 `pelens.exe`，不需安裝。附有 `.sha256` 可驗證檔案。從原始碼建置：

```bash
cargo build --release
# target/release/pelens.exe      (GUI)
# target/release/pelens-cli.exe  (CLI)
```

需要 Rust 1.88 以上（edition 2024），於 Windows 11 x64 開發與測試。

## 使用方式

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-lang:zh-TW] [-expand] [-hex] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir] [-yara:dir]
```

CLI 預設在樣本旁輸出 `<input>.xml`，與 pestudio 相同。

### 知識庫

PELens 內建自己的**開放知識庫**（`kb/`，CC0）：142 個指標定義、約 2,500 個 Windows API 函式、約 900 個可疑字串、約 100 個簽章，以及 MITRE ATT&CK 對應。它由 `tools/build_kb.py` 從 `kb/src` 產生，每一筆資料都來自公開資料（見 [kb/SOURCES.md](../../kb/SOURCES.md)），沒有複製 pestudio 的 XML。也可以用 `-xml:<dir>` 改用你自己安裝的 pestudio XML 檔；這些檔案屬於 pestudio 的作者，不隨 PELens 散佈。

### VirusTotal

只送出**雜湊值**，從不上傳樣本。在設定對話框或 `VT_API_KEY` 環境變數中填入你自己的 API key。預設使用 API v3，也可選 v2。

## 專案結構

| crate | 用途 |
|---|---|
| `pe-parser` | PE 解析（邊界檢查、不會 panic）與修改 |
| `pe-db` | pestudio XML 知識庫，讀寫時保留原格式 |
| `pe-analysis` | 指標、簽章、字串、檢視、報告、動作 |
| `pe-online` | VirusTotal、搜尋連結、更新檢查 |
| `pelens-cli` | 命令列（相容 pestudiox） |
| `pelens-gui` | eframe/egui 圖形介面 |

設計文件：[功能盤點](../FEATURE_INVENTORY.md)（212 項，每項附對照）· [開發計畫](../DEVELOPMENT_PLAN.md) · [Tasklist](../TASKLIST.md)。

## 品質

```bash
cargo test --workspace                       # 107 個測試
cargo llvm-cov --workspace --summary-only    # 約 97% 行覆蓋率
python tools/crossval.py 250                 # 與 pefile 交叉驗證
```

## 免責聲明

PELens 是獨立專案，與 Winitor 及 pestudio 作者無關，也未獲其背書。請僅分析你有權限分析的檔案。
