# PELens (PEStudio Remake) — Tasklist

狀態：`[ ]` 未開始　`[~]` 進行中　`[x]` 完成（已測試）
對應功能編號見 `FEATURE_INVENTORY.md`。

## M0 盤點與規劃
- [x] T0.1 盤點全部功能（FEATURE_INVENTORY.md）
- [x] T0.2 開發計畫（DEVELOPMENT_PLAN.md）
- [x] T0.3 Tasklist（本檔）

## M1 Workspace + 知識庫（pe-db）
- [x] T1.1 Cargo workspace 骨架（6 crates）
- [x] T1.2 寬鬆 XML 讀取工具（非標準根、壞 tag 容錯）— F-F-*
- [x] T1.3 settings.xml（files/setting/colors/sections/streams/tables/tips）— F-F-10, F-H-*
- [x] T1.4 indicators.xml / thresholds.xml — F-F-04
- [x] T1.5 functions.xml（libs/fcts 全屬性）— F-F-01
- [x] T1.6 strings.xml（11 類）— F-F-02
- [x] T1.7 signatures.xml（pattern 編譯含 byte/nibble wildcard + 文字 pattern）— F-F-03, F-D-01b
- [x] T1.8 mitre.xml — F-F-05
- [x] T1.9 namespaces.xml — F-F-06
- [x] T1.10 rich.xml — F-F-07
- [x] T1.11 languages.xml — F-F-08
- [x] T1.12 translations.xml（text + 27 列舉）— F-F-09, F-F-11
- [x] T1.13 屬性回寫（flag/severity/settings）保留格式 — F-A-07
- [x] T1.14 內建最小預設（無 XML 時）

## M2 PE 解析核心（pe-parser）
- [x] T2.1 Reader（bounds-safe）、RVA↔offset、錯誤模型 — F-B-09
- [x] T2.2 DOS header + stub（訊息擷取）— F-C7, F-C8
- [x] T2.3 Rich header（解碼、checksum 驗證）— F-C9
- [x] T2.4 File header + characteristics — F-C10
- [x] T2.5 Optional header PE/PE+ + DllCharacteristics — F-C11
- [x] T2.6 Data directories（invalid/missing/empty）— F-C12
- [x] T2.7 Sections（旗標、entropy、caves）— F-C13
- [x] T2.8 Imports：INT/IAT/hint/ordinal、bound、delay-load — F-C14, F-C15
- [x] T2.9 Exports：forward/anonymous/dup/gaps — F-C16
- [x] T2.10 Resources 樹 + 語言/code-page — F-C22
- [x] T2.11 Version info 解析 — F-C23
- [x] T2.12 Manifest 解析 — F-C26
- [x] T2.13 Resource 內容：string-table / message-table / dialog / menu / icon / cursor / bitmap — F-C22-04
- [x] T2.14 Debug directory（RSDS/NB10/POGO/REPRO/ExDllChar…）— F-C24
- [x] T2.15 TLS + callbacks — F-C20
- [x] T2.16 Relocations — F-C19
- [x] T2.17 Exceptions (.pdata) — F-C17
- [x] T2.18 Load-config（GS/SEH/CFG/CET）— F-C12-04, F-C11-05
- [x] T2.19 Overlay — F-C27
- [x] T2.20 Checksum（實算）— F-C11-01
- [x] T2.21 Entry-point 分析（位置/first bytes/異常）— F-C1-10, F-C11-04

## M3 PE 解析進階
- [x] T3.1 WIN_CERTIFICATE + PKCS7/DER 解析 — F-C18-01/02
- [x] T3.2 憑證異常（tail、NULL padding、stamp 範圍）— F-C18-04
- [x] T3.3 WinVerifyTrust 驗證（Windows）— F-C18-03
- [x] T3.4 .NET CLR header — F-C21-01
- [x] T3.5 .NET metadata streams — F-C21-02
- [x] T3.6 .NET tables（45 種 row 數與主要表內容）— F-C21-03
- [x] T3.7 .NET module/assembly/GUID/strong-name/p/Invoke — F-C21-04
- [x] T3.8 .NET namespaces/#Strings/#US — F-C21-05/06

## M4 分析引擎（pe-analysis）
- [x] T4.1 雜湊（md5/sha1/sha256，含/不含 overlay）、大小寫 — F-C1-06, F-M-01
- [x] T4.2 Entropy — F-M-02
- [x] T4.3 imphash — F-C1-07
- [x] T4.4 Footprints（全部項目 + 類型）— F-C2
- [x] T4.5 Signatures：EP 比對、檔案開頭、嵌入檔（resources/sections/overlay/base64）— F-D
- [x] T4.6 Strings 擷取（ASCII/UTF-8/UTF-16、location、offset）— F-C25-01/02
- [x] T4.7 Strings hints/labels（30 類 + 知識庫比對 + 白名單）— F-C25-03/04/05
- [x] T4.8 Imports 分類（group/flag/MITRE/deprecated/undoc/callback/map/ordinal 映射）— F-C15-02
- [x] T4.9 Libraries 分類（type/desc/flag/missing/dup/spoof/CPU mismatch）— F-C14
- [x] T4.10 Imports 異常（INT/IAT 不一致、spoof/hook、invalid IAT）— F-C15-03
- [x] T4.11 Groups 匯總 — F-C3
- [x] T4.12 MITRE 映射 — F-C5
- [x] T4.13 Rich → tooling/IDE — F-C9-02
- [x] T4.14 Resources 分析（signature、語言 flag、severity）— F-C22-02/03
- [x] T4.15 Stamps 匯總（UTC + Epoch）— F-C1-09, F-M-03
- [x] T4.16 .NET 分析（obfuscator、namespace flag、stream flag）— F-C21
- [x] T4.17 Indicators 全 150 條評估 + thresholds — F-C4, F-E
- [x] T4.18 Overview（image 節點）— F-C1
- [x] T4.19 C++ undecorate — F-M-04

## M5 報告與 CLI
- [x] T5.1 XML 報告（全部 27 區段）— F-I
- [x] T5.2 pestudiox CLI（-file: -report: -banner、banner/免責）— F-A-03
- [x] T5.3 CLI 額外：--xml-dir、--json（可選）

## M6 線上（pe-online）
- [x] T6.1 VT file report（v2 API, 只送 hash）— F-C6-01..06
- [x] T6.2 VT URL report、overlay/resources 分數 — F-C6-08
- [x] T6.3 搜尋 URL 產生（VT gui/hash/imphash/content/netguid、Google、MITRE、MSDN）— F-C6-09, F-J-03/04
- [x] T6.4 更新檢查 — F-J-05
- [x] T6.5 Proxy/User-Agent、網路狀態 — F-C6-10, F-J-07

## M7 檔案修改
- [x] T7.1 Toggle DLL⇄EXE — F-K-01
- [x] T7.2 Set entry-point — F-K-02
- [x] T7.3 Toggle file-header characteristics — F-K-03
- [x] T7.4 Toggle DllCharacteristics — F-K-04
- [x] T7.5 Delete overlay — F-K-05
- [x] T7.6 Save / 覆寫確認 / 唯讀 — F-K-06, F-B-04/05
- [x] T7.7 Dump：section/resource/overlay/cert/tail/PKCS7/debug/.NET stream/manifest/indicators — F-L

## M8 GUI（pestudio-gui）
- [x] T8.1 主視窗：選單 + 快速鍵 + 標題 + 狀態列 — F-G-01, F-B-06, F-G-08
- [x] T8.2 開檔對話框 / 拖放 / 關閉 / 背景分析 + 進度 — F-B-01/02/03/12
- [x] T8.3 Tree 27 節點 + Tab 導覽 + 節點上色 — F-G-02/03
- [x] T8.4 各節點 List 視圖（排序、欄位選擇、show duplicates、篩選）— F-G-04
- [x] T8.5 顏色/labels/flags/jumps/tooltips — F-G-05/06/07
- [x] T8.6 Context menus（附錄 2 全部動作）— F-G-09/11/12
- [x] T8.7 設定對話框（General/Footprints/First-bytes/Virustotal）+ 存檔 — F-H
- [x] T8.8 About + 更新檢查 — F-G-10
- [x] T8.9 VT 分數視圖 + watchdog — F-C6-07
- [x] T8.10 修改動作 UI（toggle/set EP/delete overlay/save）— F-K
- [x] T8.11 Severity / flag / language flag 調整並回寫 XML — F-C4-03, F-C14-03, F-C22-03
- [x] T8.12 Create report (Ctrl+R) — F-I
- [x] T8.13 Open in pestudio（嵌入檔）— F-B-13

## M9 驗收
- [x] T9.0 覆蓋率 ≥ 90%（cargo llvm-cov，workspace 與各 crate）
- [x] T9.0a 合成 PE 產生器 testutil（imports/exports/resources/TLS/.NET/cert/overlay/畸形）
- [x] T9.0b GUI headless 繪製測試（所有節點、對話框、選單）
- [x] T9.1 整合測試：System32 樣本集不 panic
- [x] T9.2 與 pefile 交叉驗證
- [x] T9.3 Fuzz / 截斷檔測試
- [x] T9.4 功能對照表逐項確認（FEATURE_INVENTORY 每個 F-ID 皆對應已完成 task）
- [x] T9.5 README（建置、使用、XML 授權說明）

## 驗收結果（2026-10-13）

| 項目 | 結果 |
|---|---|
| 自動化測試 | 69 個測試全數通過（`cargo test --workspace`） |
| 行覆蓋率（`cargo llvm-cov --workspace`） | **97.13%**（region 96.65%、function 97.36%） |
| 各 crate 行覆蓋率 | pe-parser 97.27%、pe-db 97.61%、pe-analysis 97.78%、pe-online 99.56%、pestudiox 95.37%、pestudio-gui 93.77% |
| 與 pefile 交叉驗證（T9.2） | System32/SysWOW64 抽樣 250 檔：sections/imports/delay-imports/exports/resources 0 差異（pefile 的 8192 exports 上限除外）；imphash 與 pefile 完全一致 |
| System32 掃描（T9.1） | 60 檔完整分析＋XML 報告無 panic |
| 畸形檔（T9.3） | 截斷 + 隨機位元組破壞（600 變體）無 panic |
| 功能對照（T9.4） | FEATURE_INVENTORY 附錄 4：212 項中 208 項已實作、4 項 N/A（附理由） |
| GUI 實機 | Windows 11 實際開啟 notepad.exe / kernel32.dll 截圖驗證；headless 測試涵蓋選單、樹狀、表格、右鍵選單、對話框、快捷鍵、拖放 |

### 開發中發現並修正的問題
- Authenticode `[0] certificates` 內的非 X.509（attribute certificate）被誤解析 → 僅解析 SEQUENCE。
- 憑證前的小 overlay 被當成 padding → 改為「全零才視為 padding」。
- signatures.xml 含半位元組 wildcard 與文字型 pattern（盤點時新增 F-D-01b）。
- 字串分類在大型 .NET 檔（5 萬字串）耗時 14 秒 → 建索引後 0.4 秒。
- UTF-16 擷取黏上雜訊 CJK 字元、版本號被誤判為 IP、OID 被誤判為 IP。
- 指標 1223 與 1496 條件重疊 → 重新定義。
- 憑證內 URL 與硬編碼 URL 未區分（changes.log: "Differentiate URLs referenced in the certificate"）。
- GUI：欄位切換索引越界 panic、Tab 導覽被 egui 焦點機制吃掉、可選取 label 吃掉列點擊。

## M10 UI 改善與品牌（2026-10-13 追加需求）
- [x] T10.1 暗色模式（預設）＋亮色模式切換，設定持久化 `<theme dark>`（pe-db 支援自動新增設定元素）
- [x] T10.2 字體：Segoe UI / Consolas（雜湊、位址、hex 欄位）/ 微軟正黑體 CJK fallback，保留 emoji 圖示字型
- [x] T10.3 流暢度：可見表格與旗標計數快取（Arc）、tooltip 僅 hover 時組字串、位置圖與資源內容快取、url_encode/group 名稱優化
  - 實測 System.Web.dll（16 萬字串）：Strings 檢視每幀 134 ms → 0.7 ms；首次建表 986 ms → 167 ms
- [x] T10.4 左側改為 tree-view（根節點＝檔案、樹狀連接線、+/− 展開鈕；indicators/sections/libraries/resources 可展開至子項並篩選）
- [x] T10.5 排版：工具列、麵包屑標題、表頭底色與 ▲▼ 排序標記、欄寬依內容估算、狀態列分段、設定對話框 Grid 版面
- [x] T10.6 命名為 PELens（crate/執行檔 `pelens`、`pelens-cli`）
- [x] T10.7 App icon（`tools/make_icon.py` 產生 PNG/ICO 7 種尺寸；嵌入 exe 資源並作為視窗圖示）
