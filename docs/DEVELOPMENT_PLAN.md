# PELens — PEStudio Remake（Rust）開發計畫

> 依據：`FEATURE_INVENTORY.md`（功能編號 F-x-xx）
> 追蹤：`TASKLIST.md`
> 語言：Rust（stable 1.97, x86_64-pc-windows-msvc）

## 1. 目標

以 Rust 重製 pestudio 9.61 的完整功能：
1. 靜態分析引擎（取代 `peparser.dll`）。
2. 命令列工具 `pestudiox`（相容 `-file:` / `-report:` / `-banner` 語法，輸出 XML 報告）。
3. GUI `pestudio`（Tree + List 視圖、context menu、設定對話框、拖放、VT 查詢、檔案修改）。
4. 相容原 XML 知識庫格式（settings / indicators / thresholds / functions / strings / signatures / mitre / namespaces / rich / languages / translations）。

## 2. 重要約束

| 約束 | 處理方式 |
|---|---|
| 原 XML 檔聲明「於 pestudio 之外使用需作者授權」 | 重製版**不複製、不內嵌、不散佈**這些 XML。程式於執行時從使用者指定的資料夾讀取（預設 `./xml`，可用 `--xml-dir` 或 settings 指定）。測試只在本機讀取使用者自有的副本。另提供最小化內建預設（僅結構所需的列舉，如 machine/subsystem 名稱），讓沒有 XML 時仍可運作。 |
| peparser.dll 內嵌廠商 VT API key | **不使用**。重製版僅使用使用者提供的 key（settings `<score key>` 或環境變數 `VT_API_KEY`）。 |
| 「絕不上傳樣本」 | VT 只送 hash；不實作 `/file/scan`。 |
| 授權（standard/pro） | 重製版無授權機制，全部功能開放；保留 `pestudio.lic` 欄位僅作相容顯示。 |
| 分析對象可能是惡意程式 | 純靜態解析，不執行、不載入樣本；所有解析需 bounds-check，禁止 panic（fuzz 測試）。 |

## 3. 架構

```
remake/
├─ Cargo.toml                (workspace)
├─ crates/
│  ├─ pe-parser/             PE 結構解析（無 I/O 依賴，&[u8] in → model out）
│  ├─ pe-db/                 XML 知識庫載入/回寫（quick-xml）
│  ├─ pe-analysis/           分析管線：hash/entropy/strings/signatures/indicators/mitre/groups/footprints/report
│  ├─ pe-online/             VirusTotal / 更新檢查 / URL 產生（ureq）
│  ├─ pelens-cli/             CLI（bin: pestudiox）
│  └─ pelens-gui/          GUI（eframe/egui, bin: pestudio）
├─ docs/                     盤點、計畫、tasklist
└─ tests/ (各 crate 內)       單元 + 整合測試（以系統內建 PE 為樣本）
```

### 3.1 資料流

```
file bytes ──► pe-parser::PeFile (headers, dirs, sections, imports, …)
                 │
                 ▼
          pe-analysis::Analyzer (+ pe-db::Knowledge, Settings)
                 │  ├─ footprints / hashes / entropy
                 │  ├─ signatures (EP / file / embedded)
                 │  ├─ strings + hints
                 │  ├─ groups / mitre mapping
                 │  └─ indicators (+ thresholds)
                 ▼
          Analysis (serializable model)
           ├─► pestudiox → XML report
           └─► pestudio-gui → Tree/List views, context actions, edits
```

### 3.2 主要依賴

| 用途 | crate |
|---|---|
| XML | `quick-xml` |
| 雜湊 | `md-5`, `sha1`, `sha2` |
| 憑證 / PKCS7 | 自寫 DER 解析器（tolerant），抽取 signer/issuer/serial/時間/演算法；Windows 上以 `windows` crate 呼叫 `WinVerifyTrust` 驗證 |
| C++ undecorate | `msvc-demangler` |
| 時間 | `chrono` |
| HTTP | `ureq`（rustls） |
| GUI | `eframe` / `egui`、`egui_extras`(表格)、`rfd`(檔案對話框)、`arboard`(剪貼簿)、`open`(瀏覽器) |
| CLI | 自寫參數解析（相容 `-file:` 形式） |

## 4. 模組設計重點

### 4.1 pe-parser
- `PeFile::parse(&[u8]) -> Result<PeFile, Error>`；非 PE 回傳 `NotPe`，仍可做字串擷取。
- 每個結構保留 `offset/size`（供 location、file-ratio、dump、jump）。
- RVA→offset 轉換容忍畸形（virtual section、對齊、header 內 RVA）。
- 子模組：dos, rich, file_header, optional_header, directories, sections, imports（含 delay/bound/INT-IAT）、exports、resources（樹 + 型別解析：version/manifest/string-table/message-table/dialog/menu/icon…）、debug（CodeView/POGO/REPRO/ExDllChar）、tls、relocations、exceptions、load_config、certificate、dotnet（CLR header, metadata streams, tables）、overlay、checksum。
- 寫入：`patch` 模組（toggle characteristics、set EP、toggle DLL、remove overlay、重算 checksum 可選）。

### 4.2 pe-db
- 每個 XML 一個 struct；寬鬆解析（原檔有些不合法，如 `AddDelBackupEntry>`、`<xml version=...>` 非標準根）。
- 回寫：只改動目標屬性（字串層級替換），保留原格式/註解。
- 缺檔時使用內建最小預設。

### 4.3 pe-analysis：thresholds 語意對應（重製版定義）
| id | 用途 |
|---|---|
| 001 | DOS header 大小（期望 64） |
| 002 | DOS stub 大小範圍 |
| 003 | file-header 大小（20） |
| 005 | data directories 數（16） |
| 006 | sections 數範圍 |
| 009 | 字串最大長度（suspicious long string） |
| 011 | imports 數上限（過多） |
| 012 | exports 數上限 |
| 015 | 每 library imports 下限（過少可疑） |
| 017 | 重複 imports 上限 |
| 018 | 資源大小上限 |
| 021 | overlay 最小大小 |
| 022 | certificate 大小上限 |
| 023 | compiler stamp 年份下限 |
| 024 | 字串 label 長度範圍 |
| 025 | 最少 sections |
| 026 | file-ratio 百分比範圍 |
| 027 | 異常 section 數上限 |
| 030 | compiler stamp 年份上限 |

### 4.4 報告格式
XML，根 `<image>`，子節點依 ItemTypes 順序；每節點的 item 以 `<item name="" value="" .../>` 表示，indicators 含 `id`/`severity`/`ti`。

### 4.5 GUI
- 左側 Tree（27 節點，含數量徽章，被 flag 的節點上色），右側 egui_extras Table（可排序、欄位顯示切換、搜尋過濾）。
- Context menu 依節點類型提供附錄 2 全部動作。
- 選單/快速鍵：Ctrl+O/S/E/R/X、Settings、About（含更新檢查）。
- 拖放開檔、標題顯示樣本名、狀態列、tooltip、顏色依 settings palette。
- 分析在背景執行緒，避免卡 UI。

## 5. 里程碑

| 階段 | 內容 | 交付 | 完成判準 |
|---|---|---|---|
| M0 ✅ | 盤點 + 計畫 + tasklist | docs/ | 本文件 |
| M1 ✅ | Workspace 骨架 + pe-db | XML 全部可載入 | 單元測試讀取 12 個 XML 成功、數量符合盤點 |
| M2 ✅ | pe-parser 核心 | headers/sections/dirs/imports/exports/resources/version/manifest/debug/tls/reloc/exceptions/loadconfig/rich/overlay/checksum | 對 System32 樣本（notepad, kernel32, ntdll, drivers）解析不 panic，數值與 pefile 對照一致 |
| M3 ✅ | pe-parser 進階 | certificate、.NET metadata | 對已簽章與 .NET 樣本解析正確 |
| M4 ✅ | pe-analysis | hashes/entropy/imphash/strings/hints/signatures/groups/mitre/footprints/indicators/thresholds | 所有 150 指標皆有評估邏輯 |
| M5 ✅ | 報告 + CLI | pestudiox | `pestudiox -file:x` 產生 XML |
| M6 ✅ | pe-online | VT / Google / MITRE / 更新檢查 | 無 key 時 graceful；有 key 時查詢 |
| M7 ✅ | 檔案修改 | patch + save | 修改後重新解析驗證 |
| M8 ✅ | GUI | pestudio | 所有節點、選單、context 動作、設定對話框、拖放 |
| M9 ✅ | 驗收 | 全 tasklist 勾選 | 回歸測試全綠、功能對照表無遺漏 |

## 6. 測試策略
- **覆蓋率目標：整個 workspace 行覆蓋率 ≥ 90%**（`cargo llvm-cov --workspace`），每個 crate 個別也需 ≥ 90%。
- GUI 拆成 `model`（純邏輯：節點、表格列、排序、篩選、context 動作、設定編輯）與 `ui`（egui 繪製）；`ui` 以 headless `egui::Context::run()` 在測試中實際繪製每個節點/對話框，使繪製程式碼也被覆蓋。
- 網路功能以可注入的 `HttpClient` trait 測試（mock 回應），不打真實 API。
- 測試樣本：內建合成 PE 產生器（`pe-parser::testutil`）構造各種結構（imports/exports/resources/TLS/.NET/certificate/overlay/畸形），使測試不依賴系統檔；另有以 System32 檔案的整合測試（存在才執行）。
- 單元測試：各解析器以手工構造 bytes 測邊界。
- 整合測試：`C:\Windows\System32` 中的 notepad.exe、kernel32.dll、ntdll.dll、`drivers\*.sys`、.NET Framework 組件（`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\*.dll`）、已簽章檔。
- 交叉驗證：以 Python `pefile`（已安裝）比對 imports/exports/sections/imphash/checksum。
- 健壯性：截斷/亂數破壞樣本的不 panic 測試。

## 7. 風險
| 風險 | 對策 |
|---|---|
| pestudio 內部判斷邏輯為閉源 | 依指標名稱、changes.log 與業界慣例實作；以 indicators.xml 的 id/severity/detail 輸出相容 |
| 原 XML 有非標準語法 | 寬鬆 parser + 測試 |
| GUI 依賴大 | egui 單一執行檔、無外部 runtime |
