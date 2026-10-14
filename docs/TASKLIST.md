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

## M11 Code review 修正（2026-10-13）
- [x] T11.1 Authenticode 巢狀副署簽章遞迴深度上限（防堆疊溢位，含小堆疊回歸測試）
- [x] T11.2 匯入函式全域上限 `MAX_TOTAL_FUNCTIONS` 與 `Imports.truncated`
- [x] T11.3 表格排序改為嚴格全序（數字 < 文字，NaN/inf 視為文字）
- [x] T11.4 字串定位改用排序索引＋二分搜尋；資源 blob 雜湊依 (offset,size) 快取
- [x] T11.5 .NET 未知表不再中止解析，記錄於 `unknown_tables` 並觸發 1290
- [x] T11.6 簽章驗證針對實際分析的位元組；重新分析保留磁碟/ACL/分數並重算指標
- [x] T11.7 GUI 參數偵測不再吞掉 `expand.exe`、`/expanded/...` 等檔名
- [x] T11.8 CLI `-stdout` 時 banner 改寫 stderr
- [x] T11.9 XML 回寫比對屬性時先 unescape（`&amp;` 等）
- [x] T11.10 Resources first-bytes 依設定（16/32/64）
- [x] T11.11 次要：函式查詢不索引空名稱、1023 不重複、JSON 不重複 key、proxy 無 port、footprints 不複製 PeFile
- 結果：82 個測試全過，行覆蓋率 96.97%

## M12 多國語言介面（2026-10-14）
- [x] T12.1 `i18n` 模組：8 種語言（en、zh-TW、zh-CN、ja、ko、es、de、fr），英文原文為 key，翻譯檔 `crates/pelens-gui/i18n/*.tsv`
- [x] T12.2 語言選擇：settings.xml `<language code>`（預設 auto＝Windows 顯示語言）、「檢視 > 語言」選單、設定對話框下拉選單、`-lang:<code>`
- [x] T12.3 翻譯範圍：選單、工具列、tree-view、表頭、欄位選單、右鍵選單、狀態列與訊息、對話框、設定、檔案對話框；分析資料（表格內容、指標、報告）維持英文
- [x] T12.4 英文時 translations.xml 仍優先（pestudio 相容）；其他語言以內建翻譯為準
- [x] T12.5 CJK 字型依語言排序（zh-CN 微軟雅黑、ja Yu Gothic、ko Malgun Gothic），並依字型 metrics 校正後備字型基線
- [x] T12.6 測試：各語言 key 一致、placeholder 一致、介面字串與所有表頭皆有翻譯、語言切換（model＋UI）
- 結果：87 個測試全過，行覆蓋率 96.93%

---

# v0.2 增強（計畫：`ENHANCEMENT_PLAN.md`）

## M13 CI 與 Release
- [x] T13.1 新增 `LICENSE`（MIT）
- [x] T13.2 清除 clippy 的 15 個警告，改以 `-D warnings` 執行（stable 1.99 新增的 lint 也已修正；最低版本改為 Rust 1.88）
- [x] T13.3 `.github/workflows/ci.yml`：rustfmt、clippy、test、llvm-cov（< 90% 失敗）；CI 綠燈
- [x] T13.4 確認測試在 CI 中不依賴本機（pestudio XML、字型、語系）；`.gitattributes` 統一 LF
- [ ] T13.5 `.github/workflows/release.yml`：`v*` tag → zip（pelens.exe、pelens-cli.exe、README、LICENSE、知識庫授權與來源）＋ SHA-256 → GitHub Releases
- [x] T13.6 README（8 種語言）加入下載說明與 CI badge

## M14 Fuzzing
- [x] T14.1 `fuzz/` crate 與 5 個目標：parse_pe、certificate、dotnet、resources、analyze（Windows 需把 MSVC 的 ASan DLL 加入 PATH）
- [x] T14.2 種子語料：`tools/fuzz_seeds.py`（testkit 樣本＋本機系統 PE，不提交）
- [x] T14.3 `tests/mutation.rs`：固定種子變異（每次 12,000 次解析＋800 次完整分析，`PELENS_MUTATIONS` 可放大），檢查不 panic、不超時、輸出量與輸入成正比；本機以 200 倍跑過
- [x] T14.4 每個目標本機各跑 30 分鐘無 crash（parse_pe 3.4 萬次、certificate 104 萬次、dotnet 308 萬次、resources 110 萬次、analyze 每次約 1 秒）；過程中找到並修正 3 個輸出放大問題（exports、resources、imports，見下）
- [x] T14.5 `tests/corpus/`（僅放 testkit 衍生的輸入；系統 PE 衍生的另寫合成測試）

- 修正：fuzzing 與變異測試找到兩個放大問題
  - exports：損毀的 NumberOfFunctions 讓 17 KB 輸入產生 100 萬列、40 MB 報告 → 依檔案中實際容得下的陣列大小限制，並在檢視中註明 truncated
  - resources：重疊的目錄讓 118 KB 輸入產生 64,048 列 → 目錄項目不得重疊（每 8 位元組最多一項），重疊資料的雜湊另設位元組預算
  - imports：多個描述元共用同一個 thunk 陣列讓 89 KB 輸入產生 118,729 列 → 每個 thunk 位置只讀一次
  - imports 截斷也會在檢視中註明

## M15 大檔效能
- [x] T15.1 `examples/big_sample.rs`（50 / 200 / 500 MB）、`examples/profile.rs`（各階段時間）、GUI `examples/bench.rs`
- [x] T15.2 記錄基準結果（見下表）
- [x] T15.3 改善：整檔雜湊／熵／checksum／overlay 平行且只算一次；「不含 overlay」與整檔雜湊共用同一趟；footprints、overlay 與 optional-header 檢視重用結果；報告逃逸字元不再逐格配置字串。不採用 memmap2：GUI 需要可修改的副本，節省的只有私有記憶體，且映射期間檔案被改寫的風險較高
- [x] T15.4 改善前後比較（release，Knowledge::builtin）

  | 樣本 | 分析（前 → 後） | JSON 報告（前 → 後） | XML 報告（前 → 後） | overlay 檢視 |
  |---|---|---|---|---|
  | 50 MB | 1,738 → 645 ms | 1,514 → 約 300 ms | 936 → 231 ms | 171 → 2 ms |
  | 200 MB | 5,668 → 1,678 ms | 2,210 → 313 ms | 1,616 → 268 ms | 574 → 2 ms |
  | 500 MB | — → 4,023 ms | — → 約 310 ms | — → 256 ms | — |

  CLI 尖峰記憶體：50 MB 樣本 243 MB、200 MB 樣本 393 MB、500 MB 樣本 693 MB（約為檔案大小＋200 MB）。GUI：各檢視穩定時每幀 < 1.5 ms；字串檢視（20 萬列）第一次顯示約 200 ms

## M16 VirusTotal 金鑰保護
- [x] T16.1 Windows 認證管理員讀寫（`PELens/VirusTotal`，`pe_online::secret`）
- [x] T16.2 自動搬移 settings.xml 中的明文金鑰（GUI 與 CLI 啟動時；認證管理員寫入失敗時保留原處）
- [x] T16.3 讀取順序：`VT_API_KEY` → 認證管理員 → settings.xml；CLI 與 GUI 共用；設定對話框只寫入認證管理員
- [x] T16.4 v0.2.0 未單獨發佈：M13–M16 完成時版本號仍是 0.1.0，為避免發佈檔顯示錯誤版本，併入 v0.3.0 一起發佈

## M17 開放知識庫
- [x] T17.1 `kb/` 目錄、授權（CC0；MITRE 名稱依其使用條款）與 `kb/SOURCES.md`
- [x] T17.2 `functions.xml`：74 個函式庫、2,515 個函式（774 個標為可疑）、MITRE 技術
- [x] T17.3 `indicators.xml`：引擎實際評估的 142 個指標，名稱、說明、嚴重度與技術皆自行撰寫
- [x] T17.4 `strings.xml`：935 筆（SID、權限、user agent、副檔名、registry、資料夾、Office、LOLBins、DOS stub、可疑字串、.NET 混淆器）
- [x] T17.5 `signatures.xml`：97 個（56 種檔案格式、加殼／保護器、安裝程式、編譯器）
- [x] T17.6 `mitre.xml`（14 戰術、125 技術）、`rich.xml`（Visual Studio 版本，新增 min/max 範圍語法）、`languages.xml`（427 個 LCID）、`namespaces.xml`（134 個）
- [x] T17.7 `tools/build_kb.py` 驗證來源（群組、技術、函式庫必須存在）並產生 XML；CI 以 `--check` 確認同步
- [x] T17.8 內嵌為內建知識庫（壓縮後內嵌：明文的勒索訊息等字串曾讓 Defender 把 PELens 誤判為 Ransom:MSIL/Cryptolocker）；指定 `-xml:` 時以使用者 XML 為準；移除引擎內建的 27 項指標表與 testkit 中與 pestudio 相同的指標文字
- [x] T17.9 本機比較（4,577 個檔案：System32、Git 工具、demo 樣本；`examples/kb_compare.rs`）

  | 項目 | 開放知識庫／pestudio XML |
  |---|---|
  | high 指標 | 110%（目標 ≥ 80%） |
  | 有 high 指標的檔案 | 94% |
  | 全部指標 | 137% |
  | 簽章命中 | 157% |
  | 標為可疑的匯入 | 43%（pestudio 標記的 API 較多） |

- 修正：比較時發現 pestudio 的 functions.xml 有重複的函式庫名稱，會讓函式查詢索引越界而崩潰（v0.1.0 即有的錯誤），已修正並加測試

## M18 YARA 掃描
- [x] T18.1 加入 `yara-x` 1.21（feature `yara`，預設開啟）。量測：GUI 20 → 44 MB、CLI 3.9 → 28 MB，release 全新建置約 4.5 分鐘；LTO＋單一 codegen unit 只省 3 MB 卻多 2 分鐘，不採用。改為 GUI／CLI 的可選 feature：`cargo build --release --no-default-features` 得到約 20 MB／4 MB 的版本，CI 也會確認這個版本可編譯
- [x] T18.2 規則載入：設定 > YARA（`<yara enable dir>`）、`-yara:<dir>`；子資料夾、每個檔案一個 namespace；無法編譯的檔案列出錯誤（含檔名與行號）並略過，其他規則照常使用；每檔掃描上限 30 秒
- [x] T18.3 第 28 個檢視 `yara`（加在最後，既有的檢視代碼不變）：規則、命名空間、tags、嚴重度、比對字串、偏移、長度、metadata；每條規則最多列 64 個比對，可在十六進位檢視中顯示
- [x] T18.4 指標 1600（每條命中的規則，嚴重度取自 `severity` metadata：1/2/3、high/medium/low、critical）與 1601（掃描失敗）
- [x] T18.5 報告 XML / JSON / text 自動包含 yara 區段
- [x] T18.6 tree-view、`-view:yara`、設定頁 YARA、關於視窗（規則檔數與錯誤）、8 種語言翻譯

## M19 Hex 檢視器
- [x] T19.1 hex 面板（位移 / hex / ASCII，只繪製可見列；Ctrl+H、檢視選單、`-hex`）
- [x] T19.2 前往位移（十進位或 0x）、複製為 hex／文字（上限 1 MB）、檔案位移與 RVA 切換
- [x] T19.3 以位元組為單位標示選取範圍
- [x] T19.4 有位置資訊的列（sections、resources、directories、debug、.NET streams、strings、overlay、certificate…）右鍵「在十六進位檢視中顯示」

## M20 進入點反組譯
- [x] T20.1 加入 `iced-x86` 1.21（只啟用 decoder、Intel 格式）；x86 / x64，其他架構（如 ARM64）在檢視中註明不支援
- [x] T20.2 第 29 個檢視 `disassembly`：從進入點或任意 RVA 線性反組譯，N 條指令（設定 `<disassembly count>`，預設 64，上限 4096）；每條指令可在十六進位檢視中顯示
- [x] T20.3 經由 IAT 的呼叫顯示「函式庫!函式」（可疑的匯入標紅）；跳躍目標顯示 RVA 與區段，右鍵「跟隨跳躍目標」；進入點不在第一個可執行區段時於檢視註明
- [x] T20.4 TLS callback、匯出函式、進入點皆可右鍵「從這裡反組譯」
- [ ] T20.5 發佈 v0.3.0

## 待辦（未排程）
- 模糊雜湊（TLSH / ssdeep）、Authentihash、Rich header hash
- 混淆字串解碼（stack strings、單位元組 XOR）
- 兩個檔案比對
- CLI 批次掃描資料夾，輸出 JSON / CSV
- 介面：最近開啟的檔案、記住視窗與欄寬、多檔分頁、正規表示式搜尋、匯出 CSV、複製單一儲存格
- 翻譯請母語人士校對（ko、es、de、fr）
- 發佈檔的程式碼簽章（需要憑證）
