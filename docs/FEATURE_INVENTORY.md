# PEStudio 9.61 功能盤點（Feature Inventory）

> 盤點對象：pestudio 安裝資料夾（pestudio 9.61, 2025-03-28, x64）
> 盤點日期：2026-10-13
> 盤點來源（全部已逐一檢視）：
>
> | 來源 | 內容 | 取得方式 |
> |---|---|---|
> | `changes.log` | 1.0 → 9.61 全部版本更新紀錄 | 全文閱讀 |
> | `pestudio.exe` (865 KB, MFC GUI) | 選單 57 組、對話框 2 個（About / Settings）、字串表、快速鍵 | PE 資源解析 |
> | `peparser.dll` (1.3 MB, 分析引擎, export `create`/`package`) | 內部字串表 551 筆（URL、CLI 語法、XML tag、API 動態載入清單） | 字串以 `byte-0x20` 編碼，已解碼 |
> | `xml/settings.xml` | 所有設定開關、顏色、標準 section 名稱、.NET streams/tables、tooltips | 全文閱讀 |
> | `xml/indicators.xml` | 150 個指標定義 | 全文閱讀 |
> | `xml/thresholds.xml` | 19 個門檻值 | 全文閱讀 |
> | `xml/translations.xml` | 620 個 UI 字串 + 27 個列舉表 | 全文閱讀 |
> | `xml/functions.xml` | 372 個 library、6,315 個 function 分類 | 結構與屬性全量統計 |
> | `xml/signatures.xml` | 379 個簽章、1,508 個 byte pattern | 結構與屬性全量統計 |
> | `xml/strings.xml` | 11 類字串知識庫（SID/特權/副檔名/登錄檔/工具…） | 全文閱讀 |
> | `xml/mitre.xml` / `mitre-test.xml` | 12 Tactics、249 Techniques | 全文閱讀 |
> | `xml/namespaces.xml` | .NET system 25 個 / custom 89 個 namespace | 全文閱讀 |
> | `xml/rich.xml` | Rich header prodId 270+、IDE 24、build→版本 470+ | 結構閱讀 |
> | `xml/languages.xml` | 204 語系（含 flag）、152 code page | 結構閱讀 |
> | `remake/` | 空資料夾 → 重製目標位置 | — |

功能編號規則：`F-<區塊>-<序號>`，後續 `TASKLIST.md` 以此編號追蹤。

---

## A. 產品組成與版本差異

| ID | 功能 | 說明 / 證據 |
|---|---|---|
| F-A-01 | GUI 主程式 `pestudio.exe` | MFC、TreeView + ListView、標題列顯示檔名 |
| F-A-02 | 分析引擎 `peparser.dll` | export `create`/`package`；GUI 與 CLI 共用 |
| F-A-03 | CLI `pestudiox.exe`（pro） | 語法 `pestudiox -file:input [-banner]`；`-report:` 指定報告；預設報告檔名 = 輸入檔名 + `.xml`；`-banner` 隱藏 banner；使用 `AttachConsole`/`WriteConsoleW` |
| F-A-04 | 報告輸出模組 `pereport.dll` | 字串表引用（XML report） |
| F-A-05 | standard / pro 版本區分 | `pestudio.lic` 授權檔；`License not found/not valid/expired`；`(BETA)` 標記 |
| F-A-06 | XML 知識庫外部化 | `settings.xml <files>` 指定 10 個 DB 檔名，可替換 |
| F-A-07 | 執行時回寫 XML | 所有 DB 標註「can be modified when running pestudio」（UI 改 flag/severity 會寫回） |
| F-A-08 | Banner / 版權 / 免責聲明 | CLI 與 About 顯示；聲明「VT 只送 hash 不送檔案」 |

## B. 檔案輸入與處理

| ID | 功能 | 說明 |
|---|---|---|
| F-B-01 | 開啟檔案 (Ctrl+O) | 篩選器：`*.exe` / `*.dll` / `*.sys` / `*.*` |
| F-B-02 | 拖放開檔 | `DragAcceptFiles`；提示「drag-and-drop a file to analyse...」 |
| F-B-03 | 關閉檔案 (Ctrl+E) | |
| F-B-04 | 儲存修改後的檔案 (Ctrl+S) | 「save changes ?」「overwrite the file?」確認 |
| F-B-05 | 唯讀模式 | `<read-only enable>`；「sample is read-only」 |
| F-B-06 | 標題列顯示樣本名 | `<caption enable>` |
| F-B-07 | 支援 32/64-bit、PE/PE+、EFI、Driver、ARM、.NET、MUI、resource-only、section-less、code-less 映像 | changes.log |
| F-B-08 | 非 PE 檔仍擷取字串 | 「Add detection of strings embedded in non-PE files」 |
| F-B-09 | 畸形檔案容錯 | 畸形 section/debug/relocation/manifest/resources 無限迴圈修正等 |
| F-B-10 | 大檔處理：字串停用門檻 | 設定「Disable strings when file size exceeds: 256/378/512/1024 KB/no-limit」 |
| F-B-11 | 檔案位於網路磁碟 / 卸除式媒體偵測 | indicator 1051/1052 |
| F-B-12 | 分析進度提示 | 「please wait while analyzing the file...」 |
| F-B-13 | 從嵌入項目「open in pestudio」 | 對嵌入檔開新分析 |

## C. 分析視圖（Tree 節點，依 `ItemTypes` 共 27 個）

### C1. image（總覽 / overview）
| ID | 欄位 |
|---|---|
| F-C1-01 | file > name / size / entropy（1000, 1022） |
| F-C1-02 | file > type（CPU 32/64、subsystem、EXE/DLL/Driver）（1001） |
| F-C1-03 | file > description（version FileDescription）（1002） |
| F-C1-04 | file > signature（檔案簽章 / 編譯器 / 打包器）（1490） |
| F-C1-05 | file > first N bytes hex / text（N=16/32/64，設定 `bytes`）（1003/1004） |
| F-C1-06 | MD5 / SHA1 / SHA256（整檔、去除 overlay 後） |
| F-C1-07 | imphash（MD5）（1271） |
| F-C1-08 | file > version、original-file-name、internal name（1009/1424/1487） |
| F-C1-09 | 所有時間戳摘要（compiler/debug/resource/export/import/certificate/directory），UTC 與可選 Epoch |
| F-C1-10 | entry-point 位置、所在 section、first bytes（1024/1224） |
| F-C1-11 | CPU、subsystem、magic、tooling（rich→IDE） |
| F-C1-12 | file-ratio：resources / sections / overlay / dos-stub / certificate / debug |

### C2. footprints（指紋）
| ID | 功能 |
|---|---|
| F-C2-01 | 類型可選 md5 / sha1 / sha256（`footprints type`） |
| F-C2-02 | 項目開關：dos-stub、dos-header、debug、version、manifest、string-tables(st)、menu、dialog(dlg)、icon、cursor(cur)、bitmap(bmp)、rich、acl |
| F-C2-03 | 另含 image、overlay、imphash、sections、resources、.NET streams、certificate 的雜湊 |
| F-C2-04 | 每個指紋可 Google 搜尋 / VT 搜尋（hunting） |

### C3. groups（函式群組）
| ID | 功能 |
|---|---|
| F-C3-01 | 33 個群組（timer, registry, execution, network, crypto, memory, file, synchro, desktop, services, obfuscation, resource, windowing, compression, hooking, sharing, diagnostic, administration, exception, reconnaissance, console, dynamic-library, io, COM, shell, setup, power, directory-service, security, device…），各有 RGB 顏色與 level（level 3 不上色） |
| F-C3-02 | 匯總 imports / strings / .NET namespace / functions 到群組（count） |
| F-C3-03 | `<groups enable color>` 顯示開關、群組上色 |

### C4. indicators（指標）
| ID | 功能 |
|---|---|
| F-C4-01 | 150 個指標（ID 1000–1497），屬性：enable(0/1/2)、severity(1 high/2 medium/3 low)、type（類別，對應 ItemType）、ti（MITRE）、detail 格式字串 |
| F-C4-02 | 排序、flag 顯示、section/label/level 欄、jump 連結（`<indicators sort flag sec label level jump rich separator bytes>`） |
| F-C4-03 | 可由 UI 調整 severity（+++/++/+）並回寫 |
| F-C4-04 | 匯出 XML 含 indicator id |
| F-C4-05 | 「dump indicators」複製 / 存檔 |
| F-C4-06 | 指標分類（完整清單見附錄 1） |

### C5. mitre（ATT&CK）
| ID | 功能 |
|---|---|
| F-C5-01 | 12 Tactics + 249 Techniques（id、tactic、flag、level、enable） |
| F-C5-02 | 由 functions / strings / namespaces / indicators 的 `ti` 對應出技術 |
| F-C5-03 | short / long view 切換；顯示 tactic（`ta`）、technique（`ti`）、去重（`dup`） |
| F-C5-04 | 連結 attack.mitre.org/techniques/Txxxx |
| F-C5-05 | XML report 中的 mitre 區段與前端同步 |

### C6. score（VirusTotal）
| ID | 功能 |
|---|---|
| F-C6-01 | 以 MD5 查詢 VT（**絕不上傳檔案**） |
| F-C6-02 | VT API v2：`/vtapi/v2/file/report?apikey=&resource=`、`/vtapi/v2/url/report`、`/vtapi/v2/file/scan`(不使用)、`/latest-report.html` |
| F-C6-03 | 顯示 positives/total、scan-id、scan-date、permalink、response-code、engines 表（vendor/result/detection/date/age days） |
| F-C6-04 | favorite-engine、排序、「verbose」細節 |
| F-C6-05 | 使用者自訂 VT key（tooltip 000）；未提供時用內建 key（重製版不得內建廠商 key） |
| F-C6-06 | VT 開關（`<score enable flag all key>`）、離線狀態「offline」、quota 錯誤、403 訊息 |
| F-C6-07 | Network Watchdog：網路恢復時自動更新分數（`IsNetworkAlive`） |
| F-C6-08 | Overlay / Resources / 硬編碼 URL 的 VT 分數（`score-resources`, `score-urls`） |
| F-C6-09 | 開啟 VT 網頁（`/gui/file/<hash>/detection`）、VT 搜尋 imphash / hash / content(strings) / netguid |
| F-C6-10 | Proxy 設定（address / port / proxy）、User-Agent |

### C7. dos-stub
| F-C7-01 | stub 訊息、大小、location、雜湊（md5/sha1/sha256）、file-ratio、first bytes |
|---|---|
| F-C7-02 | 異常 stub 訊息比對 `strings.xml <stubs>`（36 條，flag）（1260/1274） |
| F-C7-03 | stub 大小異常（1489） |

### C8. dos-header
| F-C8-01 | 全部 `IMAGE_DOS_HEADER` 欄位（e_magic…e_lfanew） |
|---|---|
| F-C8-02 | e_lfanew 異常偏移（1062）、header 大小異常（1488） |

### C9. rich-header
| F-C9-01 | 解碼 Rich entries：prodId、build、count；prodId→名稱（rich.xml prodId 0x00–0x10F+） |
|---|---|
| F-C9-02 | build→IDE/版本對應（Visual Studio 5.0 … 2019 / .NET） → tooling |
| F-C9-03 | checksum（計算 vs 儲存）、location/offset、md5 |
| F-C9-04 | 設定 `<rich fn count>` |

### C10. file-header
| F-C10-01 | Machine（31 種）、NumberOfSections、TimeDateStamp(compiler)、PointerToSymbolTable、NumberOfSymbols、SizeOfOptionalHeader、Characteristics |
|---|---|
| F-C10-02 | Characteristics 15 旗標（relocation-stripped, executable, line/local-symbols-stripped, aggressive-ws, large-address-aware, bytes-reversed-lo/hi, 32-bit, debug-stripped, removable-run-from-swap, net-run-from-swap, system, dll, uniprocessor） |
| F-C10-03 | **切換 DLL ⇄ EXE**、切換 characteristics（寫入） |
| F-C10-04 | file-header offset（1070）、size（1006）、compiler stamp 合理性（thresholds） |

### C11. optional-header
| F-C11-01 | magic PE/PE+、linker version、SizeOfCode/InitData/UninitData、AddressOfEntryPoint、BaseOfCode/BaseOfData（含所屬 section 名）、ImageBase、Section/FileAlignment、OS version（友善名稱 Win NT4–Win11）、Image version、Subsystem version、Win32VersionValue、SizeOfImage、SizeOfHeaders、CheckSum（內建 vs 實算 `CheckSumMappedFile`）、Subsystem（14 種）、DllCharacteristics、Stack/Heap Reserve/Commit、LoaderFlags、NumberOfRvaAndSizes |
|---|---|
| F-C11-02 | DllCharacteristics：High-Entropy VA、ASLR、Force Integrity (CI)、DEP/NX、No-Isolation、No-SEH、No-Bind、AppContainer、WDM、CFG、TSA |
| F-C11-03 | **切換 DllCharacteristics**、**指定新 entry-point**（寫入） |
| F-C11-04 | 異常：size-of-code、size-of-headers、file-alignment、size-of-image、base-of-code（1081–1085）、entry-point invalid / 在第一個 section 外 / 在檔案開頭（MZ 指令抵消）/ 在 export 中（1034/1045） |
| F-C11-05 | security > protection 摘要（ASLR/DEP/CFG/SEH/GS/CET/CI…）（1056） |

### C12. directories
| F-C12-01 | 16 個 data directory（export….NET、reserved）：RVA、size、所在 section、file offset |
|---|---|
| F-C12-02 | invalid / missing / empty 判定與計數（1301/1302/1306），設定 `<directories invalid missing empty>` |
| F-C12-03 | 各目錄時間戳（1320） |
| F-C12-04 | load-config：GS cookie、SEH table、CFG、CET (CETCOMPACT) |
| F-C12-05 | bound-import directory（BoundImports、BoundImportDate） |

### C13. sections
| F-C13-01 | name、md5、entropy、file-ratio、raw-address/size、virtual-address(begin/end)/size、characteristics（含 PointerToRelocations/Linenumbers…） |
|---|---|
| F-C13-02 | 旗標：read/write/execute/share、code/initialized/uninitialized、discardable/cachable/pageable、self-modifying(W+X)、virtualized(raw=0)、unreadable、nameless、shared |
| F-C13-03 | 非標準 section 名稱（對照 settings.xml 44 個標準名）、重複名稱 |
| F-C13-04 | 包含 entry-point / directories / 嵌入檔（signature） |
| F-C13-05 | file caves（偏移、大小、總 bytes） |
| F-C13-06 | **dump section**、section items、internal/external jumps |
| F-C13-07 | 第一/最後 section 特定指標、section-less 映像 |
| F-C13-08 | 設定：characteristics、items、initial、uninitial、cache、page、read、jmp |

### C14. libraries
| F-C14-01 | 名稱、imports 數、type（implicit / delay-loaded / bound / forward / p/Invoke）、description（functions.xml）、group、flag |
|---|---|
| F-C14-02 | 缺少的 library、重複 library、spoofed library、bound library、CPU mismatch、missing INT |
| F-C14-03 | context menu 切換 library flag（回寫 functions.xml） |
| F-C14-04 | 設定 `<libraries type gp dup flag bound tip>` |

### C15. imports
| F-C15-01 | 名稱、ordinal（含 ordinal→名稱映射，od 屬性 1,602 筆）、library、hint、First-Thunk (IAT)、First-Thunk-Original (INT) |
|---|---|
| F-C15-02 | group、MITRE technique、flag、deprecated、undocumented(un)、anti-debug、callback(cb)、alias map（如 SystemFunction001→RtlEncryptDES…）、hide(.ctor)、ad |
| F-C15-03 | INT vs IAT 不一致、spoofed / hooked imports、invalid IAT entries |
| F-C15-04 | delay-loaded imports、.NET 函式（namespace 分組）、p/Invoke |
| F-C15-05 | MSDN / Google 搜尋、複製 import 名 |
| F-C15-06 | 匯總計數（1262/1264/1266/1268/1273） |

### C16. exports
| F-C16-01 | ordinal、name、RVA、function-index、name RVA、所在位置、decorated / undecorated（`UnDecorateSymbolName`） |
|---|---|
| F-C16-02 | forwarded、anonymous(無名)、duplicates、gaps、entry-point export、flagged |
| F-C16-03 | export DLL 名稱、stamp |
| F-C16-04 | 處理大量 exports 效能、n/a 與 empty 區分 |

### C17. exceptions
| F-C17-01 | .pdata RUNTIME_FUNCTION：begin/end/unwind address；計數；`<exceptions enable>` |

### C18. certificate（Authenticode）
| F-C18-01 | WIN_CERTIFICATE：revision、type、size、offset、file-ratio |
|---|---|
| F-C18-02 | PKCS7：signer、counter-signer、issued-to/by、serial-number、thumbprint、hash/sig 演算法、valid-from/to、signing time、program-name、more-info-url、CRL distribution point、purposes、email/dns |
| F-C18-03 | 驗證：WinVerifyTrust signature-info、revocation、chain policy、expired |
| F-C18-04 | 異常：tail（簽章後多餘資料）、PKCS7 NULL padding、compiler stamp 不在憑證有效期內（1012） |
| F-C18-05 | 憑證中的 URL 區分、雜湊（hunting） |
| F-C18-06 | **dump certificate / dump tail / dump PKCS7** 至檔 |

### C19. relocations
| F-C19-01 | blocks（page RVA）、entries、type（absolute/high/low/high-low/high-adjust/mips-jmp/ia64/dir64）；`<relocations enable>` |

### C20. thread-local-storage
| F-C20-01 | TLS directory、data begin/end、index、callbacks（32/64-bit）→ 指標 1033 |

### C21. .NET（dotnet）
| F-C21-01 | CLR header：runtime version、flags（IL-only、32-bit required/preferred、IL-library、strong-name signed、native entry-point、track-debug-data）、entry-point token/address、resources、strong-name sig、vtable fixups、EAT jumps |
|---|---|
| F-C21-02 | Metadata (BSJB)：version、streams #~ #- #Strings #US #GUID #Blob（size、file-ratio、threshold、md5、flag、**dump**） |
| F-C21-03 | Tables 45 種（Module…GenericParamConstraint）row 數；TypeRef/TypeDef/Method/MemberRef/ModuleRef/ImplMap(p/Invoke)/Field/Assembly/AssemblyRef/ManifestResource |
| F-C21-04 | module name、assembly GUID、typelibid、strongly-named、obfuscated 判定（Eazfuscator 等） |
| F-C21-05 | Namespaces：system / custom 分類，flag、group、MITRE（namespaces.xml） |
| F-C21-06 | #Strings / #US 字串收集 |
| F-C21-07 | .NET resources |
| F-C21-08 | 設定 `<dotnet header tables streams>`、`<namespaces flag>`、streams/tables enable/flag |

### C22. resources
| F-C22-01 | type（24 builtin + custom + 偵測型別）、name/id、language、code-page、size、offset、file-ratio、entropy、md5、signature、first bytes hex/text、stamp |
|---|---|
| F-C22-02 | 嵌入檔偵測（executable、archive、script、XML…）、severity |
| F-C22-03 | 語言 flag（languages.xml 21 個 flagged）、切換語言 flag、切換 signature severity |
| F-C22-04 | string-tables、message-tables、dialogs、menus、icons、cursors、bitmaps、MUI、HTML、.NET resources 內容解析 |
| F-C22-05 | tree / list 檢視、排序、**dump to file**、VT/Google 搜尋 |
| F-C22-06 | 設定 `<resources sort sig type loc flag hash ent ratio lang size hex txt>` |

### C23. version
| F-C23-01 | VS_FIXEDFILEINFO（File/Product version、flags、OS、type、subtype(driver)）、StringFileInfo（CompanyName、FileDescription、FileVersion、InternalName、LegalCopyright、LegalTrademarks、OriginalFilename、ProductName、ProductVersion、Comments、CompanyWebsite、OLESelfRegister、CompiledScript…）、VarFileInfo Translation |
|---|---|
| F-C23-02 | version blob 雜湊（Google 搜尋）、size 異常（1486）、first bytes |

### C24. debug
| F-C24-01 | debug entries：type（21 種：COFF…embedded portable PDB）、stamp、size、file-ratio |
|---|---|
| F-C24-02 | CodeView RSDS（GUID、age、pdb path）、NB09/NB10/NB11、POGO、REPRO、VC feature、Ex-DllCharacteristics（CETCOMPACT） |
| F-C24-03 | debug stamp vs compiler stamp（1074）、**dump debug stream** |

### C25. strings
| F-C25-01 | ASCII / UTF-8 / UTF-16LE 擷取，最小長度（預設 4）、極長字串 |
|---|---|
| F-C25-02 | 欄位：type、size、file-offset、location（section/resource/overlay…依顏色）、flag、label(hint)、group、MITRE technique、value |
| F-C25-03 | hint 偵測 30 類：rich-header、privilege、registry、user-agent、rtti、utility、mutex、query、sid、file(ext 647)、regex、url-pattern、security、size、base64、import、export、format-string、dotnet-namespace、library、debug、GUID、OID、pipe、IP/URL… |
| F-C25-04 | 白名單字串（wl）、flagged 字串、strings.xml 比對（case-sensitive / substring 設定） |
| F-C25-05 | 字串對應 imports（hint）、重複計數 |
| F-C25-06 | 位置分佈圖（string location map with colors） |
| F-C25-07 | VT content 搜尋、Google 搜尋、複製 |
| F-C25-08 | 設定 `<strings flag offset label gp utf8 utf16 sort wl type>` |

### C26. manifest
| F-C26-01 | 原始 XML、assemblyIdentity（type/name/version/arch/publicKeyToken/language）、requestedExecutionLevel（asInvoker/highestAvailable/requireAdministrator）、uiAccess、autoElevate、dependentAssembly、description、trustInfo |
|---|---|
| F-C26-02 | 指標：privilege（1400/1401）、UAC（1402）、malformed manifest；**dump manifest** |

### C27. overlay
| F-C27-01 | offset、size、file-ratio、entropy、signature（嵌入檔偵測）、first bytes hex/text、md5/sha1/sha256、strings 數 |
|---|---|
| F-C27-02 | VT 分數、**刪除 overlay**、dump |
| F-C27-03 | 設定 `<overlay flag score>` |

## D. 偵測引擎（signatures.xml）

| ID | 功能 |
|---|---|
| F-D-01 | 379 個簽章、1,508 pattern：hex bytes，支援整 byte wildcard `xx` 與**半位元組 wildcard**（`0x`、`x3`、`xD`、`5x`） |
| F-D-01b | **文字型 pattern**（`ep="0"`）：如 `.vmp0`/`.MPRESS1`（section 名）、`Go build ID:`、`_NimMainModule`、`Confuser`、`Costura`、`LordPE`、`flat assembler`（檔案內容搜尋） |
| F-D-02 | `ep="1"`：entry-point 比對（PEiD 風格，1,412）；`ep="0"`：檔案/資料開頭比對（96） |
| F-D-03 | 屬性：name、more、flag、file（嵌入檔類型 35）、tool（packer/compiler/installer）、severity、url、id |
| F-D-04 | 涵蓋：packers（UPX、ASPack、Themida、VMProtect…）、compilers（MSVC、Delphi、Go、Nim、FASM…）、installers（NSIS、Inno、InstallShield…）、檔案格式（CAB、7z、RAR、ZIP、PDF、RTF、MS-Office CFB、LNK、SWF、ELF、CHM、MOF、TLB、SQL、HTA、Python、JAR、AutoIt…）、.NET obfuscators（Confuser、Costura、SmartAssembly…） |
| F-D-05 | 嵌入檔偵測範圍：resources、所有 sections、overlay、base64 編碼 executable |
| F-D-06 | MD5 黑名單（file/resources/overlay）（舊版功能） |

## E. 指標與規則引擎

| ID | 功能 |
|---|---|
| F-E-01 | 指標評估（附錄 1 全部 150 條） |
| F-E-02 | thresholds.xml 19 條（min/max/level/enable） |
| F-E-03 | severity 1–6（high/medium/low/info/unknown/none） |
| F-E-04 | indicator enable=2（條件式/預設隱藏） |
| F-E-05 | 指標 → MITRE technique 對應 |
| F-E-06 | detail 格式字串 printf 樣式 |

## F. 知識庫（XML DB）

| ID | 檔案 | 內容 |
|---|---|---|
| F-F-01 | functions.xml | libs（name、flag、gp/group、desc）、fcts（gp、od、flag、cb、un、ti、map、hint、cd、hide、ad） |
| F-F-02 | strings.xml | settings（minimum-size、case-sensitive、substring）、sids 75、privs 36、agents 3、exts 647、regs 56、folders 31、offices 12、utils 263、stubs 36、strings 217 |
| F-F-03 | signatures.xml | sigs/sig/pattern |
| F-F-04 | indicators.xml、thresholds.xml | 指標與門檻 |
| F-F-05 | mitre.xml | tactics、techniques |
| F-F-06 | namespaces.xml | nsp_system、nsp_custom（flag、gp、ti、sig） |
| F-F-07 | rich.xml | prodId、ide、version |
| F-F-08 | languages.xml | langs、cps |
| F-F-09 | translations.xml | text（620）、tooltips、version(os/file/driver)、locations、footprints、relocations、jmps、cert_*、hashes、ItemTypes、groups、dirs、resources、subsystems、machines、executionlevels、ops、debuggers、characters、severities、dependencies、manifest、magics、hints |
| F-F-10 | settings.xml | files、setting、colors(23)、sections(44)、streams、tables(45)、tips |
| F-F-11 | 多語系介面（translations 可替換） | |

## G. 使用者介面

| ID | 功能 |
|---|---|
| F-G-01 | 主選單 file：open (Ctrl+O)、save (Ctrl+S)、close (Ctrl+E)、create report (Ctrl+R)、exit (Ctrl+X)、settings、about |
| F-G-02 | 左側 Tree（27 節點）、右側 ListView，節點間互相連結（jump） |
| F-G-03 | Tab 鍵在 Tree 中導覽 |
| F-G-04 | 欄位排序、欄位顯示選擇（column 選單）、show duplicates |
| F-G-05 | 顏色：groups 色、labels（color_text/back）、flags（color_text/back）、jumps（ext/int）、locations 色、23 色 palette、XML 自訂前景色 |
| F-G-06 | tooltips（flag/group/technique/tactic/namespace/label/size/language/file-ratio/location/signature/url/type） |
| F-G-07 | 底線表示可點擊 URL（Google/VT/MITRE/MSDN），double-click > jump / url / save file |
| F-G-08 | 狀態列 |
| F-G-09 | Context menus（57 組，附錄 2） |
| F-G-10 | About：版本、版權、www.winitor.com、**線上檢查更新**（`tools/pestudio/version.txt`） |
| F-G-11 | 剪貼簿複製（line/value/detail/property/item/indicator/name/description/namespace/technique/import name/query/file name） |
| F-G-12 | 外部瀏覽器開啟（ShellExecute） |

## H. 設定對話框（Settings）

| ID | 分頁 / 欄位 |
|---|---|
| F-H-01 | General：show groups color、show Mitre Tactics、show Relocations、show Exceptions、show Epoch stamps、sample is read-only、show sample in caption、show strings、report format、disable strings when size exceeds |
| F-H-02 | Footprints：類型 md5/sha1/sha256 與各項開關 |
| F-H-03 | First-bytes (hex\|text)：16/32/64 bytes |
| F-H-04 | Virustotal：enable query、自訂 key |
| F-H-05 | 存回 settings.xml；「open > pestudio > settings」 |

## I. 報告

| ID | 功能 |
|---|---|
| F-I-01 | XML 報告（create report、CLI），`<?xml version='1.0' encoding='utf-8'?>`，區段：image/footprints/indicators/mitre/score/dos-stub/dos-header/rich/file-header/optional-header/directories/sections/libraries/imports/exports/exceptions/certificate/relocations/tls/dotnet/resources/version/debug/strings/manifest/overlay |
| F-I-02 | 非可列印字元處理、與 GUI 內容同步 |
| F-I-03 | `<report enable type>`、separator「\|」 |
| F-I-04 | 「Cannot create Report file!」錯誤處理 |

## J. 線上服務

| ID | 功能 |
|---|---|
| F-J-01 | WinHTTP 連線（proxy/port/User-Agent） |
| F-J-02 | VT API（見 C6） |
| F-J-03 | Google 搜尋 `https://www.google.com/search?q=` |
| F-J-04 | MITRE 連結、MSDN 搜尋 |
| F-J-05 | 更新檢查（winitor.com/tools/pestudio/version.txt）「The newest version of pestudio is:」 |
| F-J-06 | mailto 回報 |
| F-J-07 | 網路狀態偵測（IsNetworkAlive） |

## K. 檔案修改功能

| ID | 功能 |
|---|---|
| F-K-01 | 切換 DLL ⇄ EXE |
| F-K-02 | 設定新 entry-point |
| F-K-03 | 切換 file-header characteristics |
| F-K-04 | 切換 optional-header DllCharacteristics |
| F-K-05 | 刪除 overlay |
| F-K-06 | 儲存（覆寫確認）、唯讀保護 |

## L. 匯出（dump）

| ID | 功能 |
|---|---|
| F-L-01 | dump section、resource、overlay、certificate、certificate tail、PKCS7、debug stream、.NET stream、manifest、indicators；預設副檔名 `*.dump` |

## M. 其他

| ID | 功能 |
|---|---|
| F-M-01 | 雜湊計算 MD5/SHA1/SHA256、大小寫切換 |
| F-M-02 | Shannon entropy |
| F-M-03 | 時間戳格式 `dd.mm.yyyy hh:mm:ss (UTC)` + Epoch |
| F-M-04 | C++ 名稱 undecorate |
| F-M-05 | `yara` 字串引用（未確認功能，列為可選） |
| F-M-06 | Windows 內建服務偵測、Firefox API 參照、pipes、OID、useragent、regex 偵測 |

---

## 附錄 1：指標（indicators.xml）完整清單

| id | sev | 名稱 | id | sev | 名稱 |
|---|---|---|---|---|---|
| 1000 | 3 | file > info | 1001 | 3 | file > type |
| 1002 | 3 | file > description | 1003 | 3 | file > first bytes (hex) |
| 1004 | 3 | file > first bytes (text) | 1005 | 1 | optional-header > size |
| 1006 | 1 | file-header > size | 1007 | 3 | sections > alignment (off) |
| 1008 | 3 | file | 1009 | 3 | file > version |
| 1010 | 3 | file > alignment (off) | 1011 | 3 | certificate > info |
| 1012 | 1 | stamp-compiler > stamp-certificate | 1013 | 3 | rich-header > footprint |
| 1014 | 3 | file > image-base (off) | 1015 | 3 | overlay > first bytes (hex) |
| 1016 | 3 | overlay > first bytes (text) | 1017 | 1 | overlay > info |
| 1019 | 3 | rich-header > checksum | 1020 | 3 | resource > first bytes (hex) |
| 1021 | 3 | resource > first bytes (text) | 1022 | 3 | file > name |
| 1023 | 2 | libraries > duplicate (off) | 1024 | 3 | entry-point > first bytes (hex) |
| 1025 | 1 | injection > technique | 1026 | 3 | libraries > bound |
| 1027 | 3 | file > code-less | 1028 | 1 | resource > file |
| 1029 | 1 | section > file | 1033 | 3 | thread-local-storage > callback |
| 1034 | 1 | entry-point > invalid | 1035 | 2 | overlay > entropy |
| 1036 | 2 | file > checksum (off) | 1037 | 1 | certificate > tail |
| 1038 | 3 | certificate > serial-number | 1040 | 3 | certificate > type (off) |
| 1042 | 2 | certificate > stamp > valid-from | 1043 | 3 | certificate > PKCS7 > size |
| 1044 | 3 | certificate > PKCS7 > NULL-padding | 1045 | 2 | entry-point > export |
| 1046 | 1 | certificate > signature-info | 1047 | 3 | certificate |
| 1048 | 2 | certificate > issued-to > error (off) | 1049 | 3 | certificate > stamp > signing |
| 1050 | 3 | certificate > stamp > valid-to | 1051 | 2 | file > network |
| 1052 | 2 | file > removable | 1053 | 2 | certificate > stamp (expired) |
| 1054 | 3 | certificate > first bytes (hex) | 1055 | 3 | certificate |
| 1056 | 3 | security > protection | 1057 | 3 | version > first bytes (hex) |
| 1058 | 3 | version > first bytes (text) | 1059 | 3 | (debug) first bytes (hex) |
| 1060 | 3 | (debug) first bytes (text) | 1061 | 3 | exception handler > count (off) |
| 1062 | 1 | dos-header > offset > unusual | 1063 | 3 | virustotal > score |
| 1064 | 1 | virustotal > score (n/m) | 1065 | 3 | virustotal > score |
| 1066 | 3 | virustotal > permalink | 1067 | 3 | virustotal > scan-date |
| 1068 | 2 | mitre > technique | 1069 | 3 | mitre > tactic |
| 1070 | 3 | file-header > offset | 1071 | 3 | debug > file-name |
| 1072 | 2 | section > virtualized | 1073 | 2 | debug > GUID |
| 1074 | 2 | stamp > debug | 1075 | 3 | debug > age |
| 1076 | 3 | debug > stream | 1077 | 3 | first bytes (hex) |
| 1078 | 3 | first bytes (text) | 1079 | 3 | overlay |
| 1080 | 3 | resource | 1081 | 2 | optional-header > size-of-code |
| 1082 | 2 | base-of-code > suspicious (off) | 1083 | 2 | file-alignment > suspicious (off) |
| 1084 | 2 | size-of-image > suspicious (off) | 1085 | 2 | size-of-headers > suspicious |
| 1210 | 3 | directories > count | 1211 | 2 | optional-header > directories |
| 1215 | 3 | sections > file-ratio (off) | 1221 | 3 | resources > info |
| 1222 | 1 | sections > executable (off) | 1223 | 2 | section > writable |
| 1224 | 3 | entry-point > location | 1234 | 3 | resources > instances > dotnet (off) |
| 1236 | 3 | languages > names | 1245 | 2 | sections > flag |
| 1250 | 3 | exports | 1251 | 3 | exports > names |
| 1252 | 2 | exports > duplicates | 1253 | 3 | exports > count |
| 1254 | 2 | exports > forwarded (T1574) | 1256 | 2 | exports > anonymous |
| 1257 | 2 | exports > gaps | 1259 | 3 | exports > file-name |
| 1260 | 2 | dos-stub > message | 1261 | 1 | symbols > flag |
| 1262 | 3 | imports > count | 1264 | 3 | imports > ordinal > count |
| 1266 | 1 | imports > flag | 1267 | 2 | string > suspicious |
| 1268 | 2 | imports > spoofing | 1269 | 2 | libraries > flag |
| 1270 | 1 | libraries > spoofing | 1271 | 3 | imphash > md5 |
| 1272 | 2 | imports > callback (off) | 1273 | 2 | imports |
| 1274 | 1 | dos-stub > suspicious | 1288 | 3 | .NET > property > missing |
| 1290 | 2 | .NET > stream > suspicious | 1291 | 1 | .NET > stream > flag |
| 1292 | 3 | .NET > module > name | 1293 | 3 | .NET > file > strongly-named |
| 1294 | 3 | .NET > methods > managed (off) | 1296 | 3 | libraries > p/invoke |
| 1297 | 1 | .NET > file > obfuscated | 1298 | 1 | .NET > namespace > flag |
| 1300 | 3 | .NET > stream | 1301 | 1 | directory > missing |
| 1302 | 3 | directory > invalid (off) | 1304 | 3 | .NET > assembly > GUID |
| 1306 | 1 | directories > empty > count | 1320 | 2 | stamp > directory |
| 1321 | 3 | stamp > compiler | 1400 | 1 | manifest > privilege |
| 1401 | 2 | manifest > privilege | 1402 | 1 | manifest > UAC |
| 1404 | 3 | manifest > general | 1423 | 3 | file > target (off) |
| 1424 | 3 | file > internal > name | 1429 | 3 | strings > ignore > count (off) |
| 1430 | 2 | strings > flag > count (off) | 1431 | 3 | strings > status |
| 1434 | 2 | string > url-pattern | 1484 | 2 | libraries |
| 1486 | 1 | version > size | 1487 | 3 | file-name > version |
| 1488 | 2 | dos-header > unusual | 1489 | 2 | dos-stub > size > unusual |
| 1490 | 3 | file > signature | 1491 | 2 | label > %s |
| 1492 | 3 | group > types | 1494 | 1 | sections > unreadable (enable=2) |
| 1495 | 2 | sections > shared (enable=2) | 1496 | 1 | sections > self-modifying |
| 1497 | 2 | sections > nameless (enable=2) | 1018 | 3 | (entry-point, 空名稱, off) |

（off = enable="0"，仍須實作，可由設定啟用）

## 附錄 2：Context menu 動作（來自 translations 577–616 與 RT_MENU）

copy line / copy value / copy detail / copy property / copy item / copy indicator / copy name / copy description / copy import name / copy namespace / copy technique / copy query / copy file name / copy to clipboard / search Virustotal / search Google (www.google.com) / lookup in Browser / open Virustotal in a Browser / attack.mitre.org / dump stream / dump to file / save to file / save certificate to file / save certificate tail to file / Dump PKCS7 / dump debug stream to file / bytes-hex / bytes-text / open in pestudio / delete (overlay) / set entry-point / friendly name / close file / severity +++ / ++ / + / toggle flag / toggle language flag / signature severity / instance / group / characteristics (toggle) / items / column / show duplicates / remove

## 附錄 3：Thresholds（thresholds.xml）

001(64–64)、002(20–368)、003(20–20)、005(16–16)、006(3–1024)、009(≥256)、011(≤1024)、012(0–2048)、015(≥10)、017(0–16)、018(0–4096)、021(0–512)、022(≥8192)、023(compiler 年 ≥2004)、024(15–17)、025(≥2)、026(1–100)、027(0–25)、030(compiler 年 ≤2025)

> 備註：thresholds id 的語意未在 XML 中命名；重製版依合理對應定義（見 DEVELOPMENT_PLAN.md §4.3），並允許使用者調整。

## 附錄 4：實作對照（Traceability）

每個功能編號對應的 Rust 實作位置。✅ 表示已實作且有自動化測試涵蓋（見 `crates/*/tests`）；N/A 為刻意不重製並註明理由。

| 功能 | crate | 實作 | 狀態 |
|---|---|---|---|
| F-A-01 | pelens-gui | ui.rs / main.rs | ✅ |
| F-A-02 | pe-analysis | analyze.rs | ✅ |
| F-A-03 | pelens-cli | lib.rs（-file/-report/-banner） | ✅ |
| F-A-04 | pe-analysis | report.rs | ✅ |
| F-A-05 | — | N/A：重製版不做授權/版本限制，所有功能開放（設計決策，見 DEVELOPMENT_PLAN §2） | N/A |
| F-A-06 | pe-db | lib.rs Knowledge::load（settings <files>） | ✅ |
| F-A-07 | pe-db | edit.rs + lib.rs set_* | ✅ |
| F-A-08 | pelens-cli/pelens-gui | banner()/About | ✅ |
| F-B-01 | pelens-gui | RfdHost.pick_open（exe/dll/sys/*） | ✅ |
| F-B-02 | pelens-gui | ui.rs draw() dropped_files | ✅ |
| F-B-03 | pelens-gui | Action::Close | ✅ |
| F-B-04 | pelens-gui | Action::Save + ConfirmOverwrite/ConfirmDiscard | ✅ |
| F-B-05 | pelens-gui | State::read_only → Save As | ✅ |
| F-B-06 | pelens-gui | State::title() | ✅ |
| F-B-07 | pe-parser | headers.rs machine/subsystem/PE32+ | ✅ |
| F-B-08 | pe-analysis | strings.rs（非 PE） | ✅ |
| F-B-09 | pe-parser | reader.rs bounds-safe + malformed_never_panics | ✅ |
| F-B-10 | pe-analysis | Options.strings_limit（settings strings limit） | ✅ |
| F-B-11 | pe-analysis | analyze.rs drive_type → 1051/1052 | ✅ |
| F-B-12 | pelens-gui | status「please wait…」+ spinner（背景執行緒） | ✅ |
| F-B-13 | pelens-gui | Action::OpenEmbedded | ✅ |
| F-C1-01 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C1-02 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C1-03 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C1-04 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C1-05 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C1-06 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C1-07 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C1-08 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C1-09 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C1-10 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C1-11 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C1-12 | pe-analysis | view.rs image() + indicators 1000–1004/1022/1490 | ✅ |
| F-C10-01 | pe-parser/pe-analysis | headers.rs FileHeader；patch.rs set_dll/toggle | ✅ |
| F-C10-02 | pe-parser/pe-analysis | headers.rs FileHeader；patch.rs set_dll/toggle | ✅ |
| F-C10-03 | pe-parser/pe-analysis | headers.rs FileHeader；patch.rs set_dll/toggle | ✅ |
| F-C10-04 | pe-parser/pe-analysis | headers.rs FileHeader；patch.rs set_dll/toggle | ✅ |
| F-C11-01 | pe-parser/pe-analysis | headers.rs OptionalHeader；patch.rs entry-point/DllCharacteristics；1056 | ✅ |
| F-C11-02 | pe-parser/pe-analysis | headers.rs OptionalHeader；patch.rs entry-point/DllCharacteristics；1056 | ✅ |
| F-C11-03 | pe-parser/pe-analysis | headers.rs OptionalHeader；patch.rs entry-point/DllCharacteristics；1056 | ✅ |
| F-C11-04 | pe-parser/pe-analysis | headers.rs OptionalHeader；patch.rs entry-point/DllCharacteristics；1056 | ✅ |
| F-C11-05 | pe-parser/pe-analysis | headers.rs OptionalHeader；patch.rs entry-point/DllCharacteristics；1056 | ✅ |
| F-C12-01 | pe-parser/pe-analysis | view directories（invalid/missing/empty/stamp）；misc_dirs LoadConfig；imports bound | ✅ |
| F-C12-02 | pe-parser/pe-analysis | view directories（invalid/missing/empty/stamp）；misc_dirs LoadConfig；imports bound | ✅ |
| F-C12-03 | pe-parser/pe-analysis | view directories（invalid/missing/empty/stamp）；misc_dirs LoadConfig；imports bound | ✅ |
| F-C12-04 | pe-parser/pe-analysis | view directories（invalid/missing/empty/stamp）；misc_dirs LoadConfig；imports bound | ✅ |
| F-C12-05 | pe-parser/pe-analysis | view directories（invalid/missing/empty/stamp）；misc_dirs LoadConfig；imports bound | ✅ |
| F-C13-01 | pe-analysis | analyze.rs build_sections + view sections（dump/caves/embedded） | ✅ |
| F-C13-02 | pe-analysis | analyze.rs build_sections + view sections（dump/caves/embedded） | ✅ |
| F-C13-03 | pe-analysis | analyze.rs build_sections + view sections（dump/caves/embedded） | ✅ |
| F-C13-04 | pe-analysis | analyze.rs build_sections + view sections（dump/caves/embedded） | ✅ |
| F-C13-05 | pe-analysis | analyze.rs build_sections + view sections（dump/caves/embedded） | ✅ |
| F-C13-06 | pe-analysis | analyze.rs build_sections + view sections（dump/caves/embedded） | ✅ |
| F-C13-07 | pe-analysis | analyze.rs build_sections + view sections（dump/caves/embedded） | ✅ |
| F-C13-08 | pe-analysis | analyze.rs build_sections + view sections（dump/caves/embedded） | ✅ |
| F-C14-01 | pe-analysis | analyze.rs build_libraries_imports + view libraries | ✅ |
| F-C14-02 | pe-analysis | analyze.rs build_libraries_imports + view libraries | ✅ |
| F-C14-03 | pe-analysis | analyze.rs build_libraries_imports + view libraries | ✅ |
| F-C14-04 | pe-analysis | analyze.rs build_libraries_imports + view libraries | ✅ |
| F-C15-01 | pe-parser/pe-analysis | imports.rs INT/IAT/hint/bound/delay + 分類 | ✅ |
| F-C15-02 | pe-parser/pe-analysis | imports.rs INT/IAT/hint/bound/delay + 分類 | ✅ |
| F-C15-03 | pe-parser/pe-analysis | imports.rs INT/IAT/hint/bound/delay + 分類 | ✅ |
| F-C15-04 | pe-parser/pe-analysis | imports.rs INT/IAT/hint/bound/delay + 分類 | ✅ |
| F-C15-05 | pe-parser/pe-analysis | imports.rs INT/IAT/hint/bound/delay + 分類 | ✅ |
| F-C15-06 | pe-parser/pe-analysis | imports.rs INT/IAT/hint/bound/delay + 分類 | ✅ |
| F-C16-01 | pe-parser/pe-analysis | exports.rs + undecorate | ✅ |
| F-C16-02 | pe-parser/pe-analysis | exports.rs + undecorate | ✅ |
| F-C16-03 | pe-parser/pe-analysis | exports.rs + undecorate | ✅ |
| F-C16-04 | pe-parser/pe-analysis | exports.rs + undecorate | ✅ |
| F-C17-01 | pe-parser | misc_dirs.rs parse_exceptions + view exceptions | ✅ |
| F-C18-01 | pe-parser/pe-analysis | certificate.rs + der.rs + verify.rs（WinVerifyTrust） | ✅ |
| F-C18-02 | pe-parser/pe-analysis | certificate.rs + der.rs + verify.rs（WinVerifyTrust） | ✅ |
| F-C18-03 | pe-parser/pe-analysis | certificate.rs + der.rs + verify.rs（WinVerifyTrust） | ✅ |
| F-C18-04 | pe-parser/pe-analysis | certificate.rs + der.rs + verify.rs（WinVerifyTrust） | ✅ |
| F-C18-05 | pe-parser/pe-analysis | certificate.rs + der.rs + verify.rs（WinVerifyTrust） | ✅ |
| F-C18-06 | pe-parser/pe-analysis | certificate.rs + der.rs + verify.rs（WinVerifyTrust） | ✅ |
| F-C19-01 | pe-parser | misc_dirs.rs parse_relocations + view relocations | ✅ |
| F-C2-01 | pe-analysis | analyze.rs build_footprints（含 acl）+ view footprints | ✅ |
| F-C2-02 | pe-analysis | analyze.rs build_footprints（含 acl）+ view footprints | ✅ |
| F-C2-03 | pe-analysis | analyze.rs build_footprints（含 acl）+ view footprints | ✅ |
| F-C2-04 | pe-analysis | analyze.rs build_footprints（含 acl）+ view footprints | ✅ |
| F-C20-01 | pe-parser | misc_dirs.rs Tls + 1033 | ✅ |
| F-C21-01 | pe-parser/pe-analysis | dotnet.rs（CLR/streams/45 tables/GUID）+ 1288–1304 | ✅ |
| F-C21-02 | pe-parser/pe-analysis | dotnet.rs（CLR/streams/45 tables/GUID）+ 1288–1304 | ✅ |
| F-C21-03 | pe-parser/pe-analysis | dotnet.rs（CLR/streams/45 tables/GUID）+ 1288–1304 | ✅ |
| F-C21-04 | pe-parser/pe-analysis | dotnet.rs（CLR/streams/45 tables/GUID）+ 1288–1304 | ✅ |
| F-C21-05 | pe-parser/pe-analysis | dotnet.rs（CLR/streams/45 tables/GUID）+ 1288–1304 | ✅ |
| F-C21-06 | pe-parser/pe-analysis | dotnet.rs（CLR/streams/45 tables/GUID）+ 1288–1304 | ✅ |
| F-C21-07 | pe-parser/pe-analysis | dotnet.rs（CLR/streams/45 tables/GUID）+ 1288–1304 | ✅ |
| F-C21-08 | pe-parser/pe-analysis | dotnet.rs（CLR/streams/45 tables/GUID）+ 1288–1304 | ✅ |
| F-C22-01 | pe-parser/pe-analysis | resources.rs + resource_content.rs + view resources/resource_content | ✅ |
| F-C22-02 | pe-parser/pe-analysis | resources.rs + resource_content.rs + view resources/resource_content | ✅ |
| F-C22-03 | pe-parser/pe-analysis | resources.rs + resource_content.rs + view resources/resource_content | ✅ |
| F-C22-04 | pe-parser/pe-analysis | resources.rs + resource_content.rs + view resources/resource_content | ✅ |
| F-C22-05 | pe-parser/pe-analysis | resources.rs + resource_content.rs + view resources/resource_content | ✅ |
| F-C22-06 | pe-parser/pe-analysis | resources.rs + resource_content.rs + view resources/resource_content | ✅ |
| F-C23-01 | pe-parser | resource_content.rs VersionInfo + view version | ✅ |
| F-C23-02 | pe-parser | resource_content.rs VersionInfo + view version | ✅ |
| F-C24-01 | pe-parser | debug.rs（RSDS/NB10/POGO/REPRO/ExDllChar…）+ view debug | ✅ |
| F-C24-02 | pe-parser | debug.rs（RSDS/NB10/POGO/REPRO/ExDllChar…）+ view debug | ✅ |
| F-C24-03 | pe-parser | debug.rs（RSDS/NB10/POGO/REPRO/ExDllChar…）+ view debug | ✅ |
| F-C25-01 | pe-analysis | strings.rs extract/Classifier/heuristic_hint + view strings/location_map | ✅ |
| F-C25-02 | pe-analysis | strings.rs extract/Classifier/heuristic_hint + view strings/location_map | ✅ |
| F-C25-03 | pe-analysis | strings.rs extract/Classifier/heuristic_hint + view strings/location_map | ✅ |
| F-C25-04 | pe-analysis | strings.rs extract/Classifier/heuristic_hint + view strings/location_map | ✅ |
| F-C25-05 | pe-analysis | strings.rs extract/Classifier/heuristic_hint + view strings/location_map | ✅ |
| F-C25-06 | pe-analysis | strings.rs extract/Classifier/heuristic_hint + view strings/location_map | ✅ |
| F-C25-07 | pe-analysis | strings.rs extract/Classifier/heuristic_hint + view strings/location_map | ✅ |
| F-C25-08 | pe-analysis | strings.rs extract/Classifier/heuristic_hint + view strings/location_map | ✅ |
| F-C26-01 | pe-parser | resource_content.rs Manifest + 1400–1404 | ✅ |
| F-C26-02 | pe-parser | resource_content.rs Manifest + 1400–1404 | ✅ |
| F-C27-01 | pe-parser/pe-analysis | lib.rs compute_overlay + view overlay + patch remove_overlay | ✅ |
| F-C27-02 | pe-parser/pe-analysis | lib.rs compute_overlay + view overlay + patch remove_overlay | ✅ |
| F-C27-03 | pe-parser/pe-analysis | lib.rs compute_overlay + view overlay + patch remove_overlay | ✅ |
| F-C3-01 | pe-analysis | analyze.rs build_groups + view groups | ✅ |
| F-C3-02 | pe-analysis | analyze.rs build_groups + view groups | ✅ |
| F-C3-03 | pe-analysis | analyze.rs build_groups + view groups | ✅ |
| F-C4-01 | pe-analysis | indicators.rs evaluate()（150 ids）+ view indicators；GUI 嚴重度調整/匯出 | ✅ |
| F-C4-02 | pe-analysis | indicators.rs evaluate()（150 ids）+ view indicators；GUI 嚴重度調整/匯出 | ✅ |
| F-C4-03 | pe-analysis | indicators.rs evaluate()（150 ids）+ view indicators；GUI 嚴重度調整/匯出 | ✅ |
| F-C4-04 | pe-analysis | indicators.rs evaluate()（150 ids）+ view indicators；GUI 嚴重度調整/匯出 | ✅ |
| F-C4-05 | pe-analysis | indicators.rs evaluate()（150 ids）+ view indicators；GUI 嚴重度調整/匯出 | ✅ |
| F-C4-06 | pe-analysis | indicators.rs evaluate()（150 ids）+ view indicators；GUI 嚴重度調整/匯出 | ✅ |
| F-C5-01 | pe-analysis | analyze.rs build_mitre + mitre_indicators；view mitre（ta/dup） | ✅ |
| F-C5-02 | pe-analysis | analyze.rs build_mitre + mitre_indicators；view mitre（ta/dup） | ✅ |
| F-C5-03 | pe-analysis | analyze.rs build_mitre + mitre_indicators；view mitre（ta/dup） | ✅ |
| F-C5-04 | pe-analysis | analyze.rs build_mitre + mitre_indicators；view mitre（ta/dup） | ✅ |
| F-C5-05 | pe-analysis | analyze.rs build_mitre + mitre_indicators；view mitre（ta/dup） | ✅ |
| F-C6-01 | pe-online | vt_file_report v3/v2、vt_url_report、attach_score；GUI score view/watchdog/item score | ✅ |
| F-C6-02 | pe-online | vt_file_report v3/v2、vt_url_report、attach_score；GUI score view/watchdog/item score | ✅ |
| F-C6-03 | pe-online | vt_file_report v3/v2、vt_url_report、attach_score；GUI score view/watchdog/item score | ✅ |
| F-C6-04 | pe-online | vt_file_report v3/v2、vt_url_report、attach_score；GUI score view/watchdog/item score | ✅ |
| F-C6-05 | pe-online | vt_file_report v3/v2、vt_url_report、attach_score；GUI score view/watchdog/item score | ✅ |
| F-C6-06 | pe-online | vt_file_report v3/v2、vt_url_report、attach_score；GUI score view/watchdog/item score | ✅ |
| F-C6-07 | pe-online | vt_file_report v3/v2、vt_url_report、attach_score；GUI score view/watchdog/item score | ✅ |
| F-C6-08 | pe-online | vt_file_report v3/v2、vt_url_report、attach_score；GUI score view/watchdog/item score | ✅ |
| F-C6-09 | pe-online | vt_file_report v3/v2、vt_url_report、attach_score；GUI score view/watchdog/item score | ✅ |
| F-C6-10 | pe-online | vt_file_report v3/v2、vt_url_report、attach_score；GUI score view/watchdog/item score | ✅ |
| F-C7-01 | pe-parser/pe-analysis | headers.rs DosStub + 1260/1274/1489 | ✅ |
| F-C7-02 | pe-parser/pe-analysis | headers.rs DosStub + 1260/1274/1489 | ✅ |
| F-C7-03 | pe-parser/pe-analysis | headers.rs DosStub + 1260/1274/1489 | ✅ |
| F-C8-01 | pe-parser/pe-analysis | headers.rs DosHeader + 1062/1488 | ✅ |
| F-C8-02 | pe-parser/pe-analysis | headers.rs DosHeader + 1062/1488 | ✅ |
| F-C9-01 | pe-parser/pe-analysis | headers.rs RichHeader（checksum）+ rich.xml tooling | ✅ |
| F-C9-02 | pe-parser/pe-analysis | headers.rs RichHeader（checksum）+ rich.xml tooling | ✅ |
| F-C9-03 | pe-parser/pe-analysis | headers.rs RichHeader（checksum）+ rich.xml tooling | ✅ |
| F-C9-04 | pe-parser/pe-analysis | headers.rs RichHeader（checksum）+ rich.xml tooling | ✅ |
| F-D-01 | pe-analysis | sigscan.rs（EP/檔頭/文字/嵌入檔/base64）+ pe-db Pattern（nibble wildcard） | ✅ |
| F-D-01b | pe-analysis | sigscan.rs（EP/檔頭/文字/嵌入檔/base64）+ pe-db Pattern（nibble wildcard） | ✅ |
| F-D-02 | pe-analysis | sigscan.rs（EP/檔頭/文字/嵌入檔/base64）+ pe-db Pattern（nibble wildcard） | ✅ |
| F-D-03 | pe-analysis | sigscan.rs（EP/檔頭/文字/嵌入檔/base64）+ pe-db Pattern（nibble wildcard） | ✅ |
| F-D-04 | pe-analysis | sigscan.rs（EP/檔頭/文字/嵌入檔/base64）+ pe-db Pattern（nibble wildcard） | ✅ |
| F-D-05 | pe-analysis | sigscan.rs（EP/檔頭/文字/嵌入檔/base64）+ pe-db Pattern（nibble wildcard） | ✅ |
| F-D-06 | — | N/A：8.x 舊版 MD5 黑名單，9.61 的 XML 已無此資料 | N/A |
| F-E-01 | pe-analysis/pe-db | indicators.rs + thresholds | ✅ |
| F-E-02 | pe-analysis/pe-db | indicators.rs + thresholds | ✅ |
| F-E-03 | pe-analysis/pe-db | indicators.rs + thresholds | ✅ |
| F-E-04 | pe-analysis/pe-db | indicators.rs + thresholds | ✅ |
| F-E-05 | pe-analysis/pe-db | indicators.rs + thresholds | ✅ |
| F-E-06 | pe-analysis/pe-db | indicators.rs + thresholds | ✅ |
| F-F-01 | pe-db | model.rs（各 XML typed loader） | ✅ |
| F-F-02 | pe-db | model.rs（各 XML typed loader） | ✅ |
| F-F-03 | pe-db | model.rs（各 XML typed loader） | ✅ |
| F-F-04 | pe-db | model.rs（各 XML typed loader） | ✅ |
| F-F-05 | pe-db | model.rs（各 XML typed loader） | ✅ |
| F-F-06 | pe-db | model.rs（各 XML typed loader） | ✅ |
| F-F-07 | pe-db | model.rs（各 XML typed loader） | ✅ |
| F-F-08 | pe-db | model.rs（各 XML typed loader） | ✅ |
| F-F-09 | pe-db | model.rs（各 XML typed loader） | ✅ |
| F-F-10 | pe-db | model.rs（各 XML typed loader） | ✅ |
| F-F-11 | pe-db | model.rs（各 XML typed loader） | ✅ |
| F-G-01 | pelens-gui | ui.rs / model.rs | ✅ |
| F-G-02 | pelens-gui | ui.rs / model.rs | ✅ |
| F-G-03 | pelens-gui | ui.rs / model.rs | ✅ |
| F-G-04 | pelens-gui | ui.rs / model.rs | ✅ |
| F-G-05 | pelens-gui | ui.rs / model.rs | ✅ |
| F-G-06 | pelens-gui | ui.rs / model.rs | ✅ |
| F-G-07 | pelens-gui | ui.rs / model.rs | ✅ |
| F-G-08 | pelens-gui | ui.rs / model.rs | ✅ |
| F-G-09 | pelens-gui | ui.rs / model.rs | ✅ |
| F-G-10 | pelens-gui | ui.rs / model.rs | ✅ |
| F-G-11 | pelens-gui | ui.rs / model.rs | ✅ |
| F-G-12 | pelens-gui | ui.rs / model.rs | ✅ |
| F-H-01 | pelens-gui | model.rs SETTING_FIELDS + ui.rs settings_window | ✅ |
| F-H-02 | pelens-gui | model.rs SETTING_FIELDS + ui.rs settings_window | ✅ |
| F-H-03 | pelens-gui | model.rs SETTING_FIELDS + ui.rs settings_window | ✅ |
| F-H-04 | pelens-gui | model.rs SETTING_FIELDS + ui.rs settings_window | ✅ |
| F-H-05 | pelens-gui | model.rs SETTING_FIELDS + ui.rs settings_window | ✅ |
| F-I-01 | pe-analysis | report.rs（XML/JSON/text） | ✅ |
| F-I-02 | pe-analysis | report.rs（XML/JSON/text） | ✅ |
| F-I-03 | pe-analysis | report.rs（XML/JSON/text） | ✅ |
| F-I-04 | pe-analysis | report.rs（XML/JSON/text） | ✅ |
| F-J-01 | pe-online | lib.rs（UreqClient/links/check_update/network_alive） | ✅ |
| F-J-02 | pe-online | lib.rs（UreqClient/links/check_update/network_alive） | ✅ |
| F-J-03 | pe-online | lib.rs（UreqClient/links/check_update/network_alive） | ✅ |
| F-J-04 | pe-online | lib.rs（UreqClient/links/check_update/network_alive） | ✅ |
| F-J-05 | pe-online | lib.rs（UreqClient/links/check_update/network_alive） | ✅ |
| F-J-06 | — | N/A：原廠 mailto 回報管道不適用於重製版 | N/A |
| F-J-07 | pe-online | lib.rs（UreqClient/links/check_update/network_alive） | ✅ |
| F-K-01 | pe-parser/pe-analysis | patch.rs + actions.rs Modification | ✅ |
| F-K-02 | pe-parser/pe-analysis | patch.rs + actions.rs Modification | ✅ |
| F-K-03 | pe-parser/pe-analysis | patch.rs + actions.rs Modification | ✅ |
| F-K-04 | pe-parser/pe-analysis | patch.rs + actions.rs Modification | ✅ |
| F-K-05 | pe-parser/pe-analysis | patch.rs + actions.rs Modification | ✅ |
| F-K-06 | pe-parser/pe-analysis | patch.rs + actions.rs Modification | ✅ |
| F-L-01 | pe-analysis/pestudio-gui | actions.rs dump + Action::Dump/SaveText | ✅ |
| F-M-01 | pe-analysis | util.rs hashes + ViewOptions.uppercase_hashes | ✅ |
| F-M-02 | pe-analysis | util.rs entropy | ✅ |
| F-M-03 | pe-analysis | util.rs format_stamp（UTC + Epoch） | ✅ |
| F-M-04 | pe-analysis | util.rs undecorate（msvc-demangler） | ✅ |
| F-M-05 | — | N/A：僅在字串表出現 "yara"，9.61 無可觀察的 yara 功能或規則檔 | N/A |
| F-M-06 | pe-analysis | strings.rs heuristic_hint（pipe/OID/regex/user-agent…）+ strings.xml 類別 | ✅ |

統計：共 212 項，✅ 208 項，N/A 4 項。
