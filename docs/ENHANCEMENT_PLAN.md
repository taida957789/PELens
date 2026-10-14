# PELens 增強計畫（v0.2）

> 起點：v0.1.0（commit `a194a5d`）：pestudio 9.61 功能完整、8 種介面語言、87 個測試、行覆蓋率 96.93%
> 追蹤：`TASKLIST.md` 的 M13–M20
> 原則：每個里程碑結束時，測試全過、行覆蓋率 ≥ 90%，然後 commit 並 push。

## 1. 目標與優先順序

| 階段 | 里程碑 | 目標 | 為什麼先做 |
|---|---|---|---|
| A 品質與發佈 | M13 CI 與 Release | 每次 push 自動測試；打 tag 自動產生可下載的 zip | 成本低；讓沒有 Rust 環境的人也能使用 |
| | M14 Fuzzing | 證明「解析器不會崩潰、不會卡住」 | 分析對象就是惡意的畸形檔，這是工具的可信度基礎 |
| | M15 大檔效能 | 量測並改善大型檔案（≥ 100 MB）的分析時間與記憶體 | 先量測再決定，避免盲目最佳化 |
| | M16 金鑰保護 | VirusTotal 金鑰改存 Windows 認證管理員 | 目前明文存在 settings.xml |
| B 知識庫 | M17 開放知識庫 | 自建可散佈的知識庫，沒有 pestudio XML 也能完整分析 | 目前最大的結構性限制 |
| C 分析功能 | M18 YARA | 以 YARA 規則掃描樣本 | 業界標準，可直接使用社群規則 |
| | M19 Hex 檢視器 | 在 GUI 中檢視任何範圍的原始位元組 | 分析時最常需要 |
| | M20 進入點反組譯 | 顯示進入點附近的指令 | 判斷加殼與可疑起始碼 |

階段 D（本計畫不排程，列在 TASKLIST 的待辦區）：模糊雜湊（TLSH/ssdeep）、混淆字串解碼、兩檔比對、CLI 批次掃描、介面細節、翻譯校對。

## 2. 各里程碑設計

### M13 CI 與 Release
- 新增 `LICENSE`（MIT，與 `Cargo.toml` 的 `license = "MIT"` 一致；目前缺少這個檔案）。
- 先清掉 clippy 剩下的 15 個警告，CI 才能以 `-D warnings` 執行。
- 新增 `.github/workflows/ci.yml`（windows-latest）：
  - 執行 `cargo test --workspace`、`cargo clippy --workspace --all-targets -- -D warnings`。
  - 執行 `cargo llvm-cov`，行覆蓋率低於 90% 時失敗。
- 新增 `.github/workflows/release.yml`：push `v*` tag 時建置 release，產生 `PELens-<版本>-windows-x64.zip`（內含 `pelens.exe`、`pelens-cli.exe`、README、LICENSE），附上 SHA-256，發佈到 GitHub Releases。
- CI 環境沒有 pestudio XML，也沒有 Yu Gothic 等字型：測試已改用 testkit 的知識庫，字型測試遇到缺檔會跳過。需要在 CI 上確認實際執行結果。
- 程式碼簽章（Authenticode）本階段不做，需要憑證，列為待辦。

### M14 Fuzzing
- 新增 `fuzz/` crate（cargo-fuzz，需要 nightly toolchain 與 MSVC AddressSanitizer）。目標如下：
  - `parse_pe`：整個 PE 解析。
  - `certificate`：DER / PKCS#7 / RFC 3161。
  - `dotnet`：metadata 與 tables。
  - `resources`：版本、對話框、選單、字串表。
  - `analyze`：完整分析管線，包含指標、字串與報告輸出。
- 種子語料：testkit 樣本，以及 `C:\Windows\System32` 中挑選的少量 PE（只放在本機，不提交）。
- **穩定版回歸測試**（CI 也跑）：
  - 以固定亂數種子對 testkit 樣本做位元翻轉、截斷、欄位竄改，執行數萬次，確認不會 panic。
  - 每個輸入設時間上限，確認不會卡住。
- 找到的 crash 輸入存入 `crates/*/tests/corpus/`，作為永久回歸測試。
- 驗收：每個 fuzz 目標在本機各跑至少 30 分鐘沒有 crash；CI 的穩定版回歸測試通過。

### M15 大檔效能
- 新增基準測試：
  - 合成 50 / 200 / 500 MB 的 PE（大型 overlay、大型資源、大量字串）。
  - 量測分析時間、尖峰記憶體與 GUI 首次顯示時間。
- 依量測結果決定改善項目，候選如下：
  - 以 `memmap2` 讀檔，取代整檔讀入。
  - 字串擷取設上限並分段處理。
  - 雜湊與熵值計算平行化。
  - GUI 表格只建立可見的列。
- 驗收：200 MB 樣本的分析時間與記憶體寫入 TASKLIST，並與改善前比較。

### M16 VirusTotal 金鑰保護
- 金鑰改存 Windows 認證管理員（`CredWriteW` / `CredReadW`，目標名稱 `PELens/VirusTotal`）。
- 第一次啟動時，若 settings.xml 有明文金鑰，搬到認證管理員並清空 settings.xml 中的值。
- 讀取順序：環境變數 `VT_API_KEY`、認證管理員、settings.xml（相容舊設定）。
- CLI 與 GUI 共用 `pe-online` 中的同一段程式碼。

### M17 開放知識庫
- **原則**：不複製、不改寫 pestudio 的 XML；每一筆資料都要有可追溯、授權允許的來源，並記錄在 `kb/SOURCES.md`。
- 格式沿用 pe-db 已支援的 XML 結構，現有的載入與回寫程式不必改。
- 新增 `kb/` 目錄（授權 CC0 或 MIT），內容如下：

  | 檔案 | 內容 | 來源 |
  |---|---|---|
  | `functions.xml` | Windows API → 群組（network、execution、memory、registry…）、可疑旗標、MITRE 技術 | Microsoft Learn 文件，由我們自行分類；MITRE ATT&CK |
  | `indicators.xml` | 150 個指標的說明文字與嚴重度（判斷邏輯已在程式中） | 自行撰寫 |
  | `strings.xml` | 可疑字串：工具名稱、指令、registry 路徑、URL 樣式等 | 自行整理 |
  | `signatures.xml` | 加殼／安裝程式特徵：UPX、ASPack、MPRESS、Themida、VMProtect、NSIS、Inno Setup… | 各工具公開的格式與原始碼，自行撰寫 |
  | `mitre.xml` | 戰術與技術名稱 | MITRE ATT&CK（允許使用，需標示出處） |
  | `rich.xml`、`languages.xml` | Rich header 產品 ID、語言代碼 | 公開文件；語言代碼來自 Windows LCID |

- 以 `tools/build_kb.py` 從來源資料產生 XML，可重現。
- 編譯時嵌入（`include_str!`），作為沒有 `-xml:` 時的內建知識庫，取代目前的最小預設值。
- 有指定 pestudio XML 時，以使用者的 XML 為準（行為不變）。
- 驗收：
  - 在本機樣本集上，比較內建知識庫與 pestudio XML 的指標命中數，結果寫入 TASKLIST；目標是 high 指標命中數達 pestudio 的 80% 以上。這項比較只在本機進行，不提交 pestudio 的資料。
  - 測試全部改用內建知識庫也能通過。

### M18 YARA 掃描
- 使用 `yara-x`（VirusTotal 官方 Rust 實作，BSD-3），以 Cargo feature `yara` 控制，預設開啟。
- 規則來源：設定中的 `<yara dir>`、CLI 的 `-yara:<dir>`；載入資料夾內所有 `.yar` / `.yara`。編譯錯誤會列出檔名與行號，不會中斷分析。
- 新增第 28 個檢視 `yara`：規則名稱、命名空間、tags、metadata、比對到的字串與偏移（可跳到 Hex 檢視器）。
- 新增指標：比對到規則時觸發，嚴重度取自規則 metadata 的 `severity`，沒有時預設 medium。
- 報告（XML / JSON / text）加入 yara 區段。
- 新增檢視需要同步更新：`ItemType::ALL`、tree-view、報告、翻譯檔、`-view:` 參數。
- 風險：yara-x 編譯時間與執行檔大小會增加，需要量測。若增加過多，改為選用 feature。

### M19 Hex 檢視器
- GUI 中央區域下方新增可切換的 hex 面板，或改用分頁：位移、16 位元組 hex、ASCII。只繪製可見的列，大檔也流暢。
- 功能：
  - 前往位移。
  - 選取範圍並複製為 hex 或文字。
  - 標示目前選取的結構範圍，例如區段、資源、overlay、字串。
  - 以檔案位移或 RVA 顯示。
- 各檢視的列加入「在 Hex 中顯示」：sections、resources、overlay、strings、directories、debug、certificate。
- 唯讀，不提供編輯（檔案修改仍走現有的修改功能）。

### M20 進入點反組譯
- 使用 `iced-x86`（MIT）；支援 x86 / x64。ARM64 / ARM64EC 顯示「不支援的架構」。
- 新增檢視 `disassembly`：從進入點線性反組譯 N 條指令（設定 `<disassembly count>`，預設 64），也可從任意 RVA 開始。
- 標示：
  - 呼叫匯入函式的位址顯示為函式名稱（透過 IAT 對應）。
  - 進入點不在第一個可執行區段時加上提示。
- TLS callback 也可反組譯（從 TLS 檢視跳過去）。
- 不做控制流程分析或反編譯，那是 IDA / Ghidra 的工作。

## 3. 需要確認的事項

1. **Fuzzing 需要安裝 nightly toolchain**（`rustup toolchain install nightly`），只在本機用於 fuzzing，正式建置仍用 stable。
2. **開放知識庫的授權**：建議 `kb/` 使用 CC0；MITRE 資料依其授權標示出處。
3. **YARA 預設開啟**：會讓執行檔變大（預估增加 5–10 MB，需實測）。
4. **版本號**：完成 M13–M16 後發佈 v0.2.0，完成 M17–M20 後發佈 v0.3.0。

## 4. 風險

| 風險 | 對策 |
|---|---|
| Windows 上的 cargo-fuzz（ASan）不穩定 | 改在 WSL / Linux 執行 fuzzing；CI 中的穩定版回歸測試不受影響 |
| 開放知識庫的品質不如 pestudio | 以指標命中率量化差距，逐步補足；使用者仍可指定 pestudio XML |
| 新增檢視影響既有測試與報告格式 | 報告只新增區段，不更動既有欄位；在 TASKLIST 註記格式變更 |
| CI 環境與本機不同（字型、語系、路徑） | 測試不依賴本機檔案；缺少時跳過並註明 |
