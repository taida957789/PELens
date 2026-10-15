"""Generate docs/readme/README.<lang>.md from one template (keeps links/images in sync).

usage: python tools/make_readme_i18n.py
"""
import os

LANGS = [
    ('en', 'English', '../../README.md'),
    ('zh-TW', '繁體中文', 'README.zh-TW.md'),
    ('zh-CN', '简体中文', 'README.zh-CN.md'),
    ('ja', '日本語', 'README.ja.md'),
    ('ko', '한국어', 'README.ko.md'),
    ('es', 'Español', 'README.es.md'),
    ('de', 'Deutsch', 'README.de.md'),
    ('fr', 'Français', 'README.fr.md'),
]

T = {
'zh-TW': dict(
 tagline='看清 Portable Executable 的鏡頭 — 以 Rust 重新打造的 Windows 執行檔靜態惡意程式初步評估工具。',
 intro='PELens **不執行**檔案，直接檢視 `.exe`、`.dll`、`.sys` 的標頭、匯入、資源、憑證、.NET metadata 與字串，並產生對應 MITRE ATT&CK 的指標。以 Rust 從零打造，由可擴充或替換的 XML 知識庫驅動。',
 h_shots='截圖', h_feat='功能', h_build='安裝／建置', h_usage='使用方式', h_kb='知識庫', h_vt='VirusTotal', h_layout='專案結構', h_quality='品質', h_disc='免責聲明',
 cap=['匯入：群組、MITRE 技術與旗標', '字串：標籤、位置分佈圖與群組', '區段（亮色模式）與展開的 tree-view', 'Authenticode 憑證鏈與 WinVerifyTrust 結果', '.NET header、metadata streams、tables 與 namespaces', '指標（暗色模式）'],
 feat=[
  '**27 個檢視**：image、footprints、groups、indicators、MITRE、VirusTotal 分數、DOS stub／header、Rich header、file／optional header、directories、sections、libraries、imports、exports、exceptions、certificate、relocations、TLS、.NET、resources、version、debug、strings、manifest、overlay。',
  '**150 個指標**，對應 MITRE ATT&CK 戰術與技術，嚴重度可調整。',
  '**簽章引擎**：entry-point 簽章（PEiD 風格，支援半位元組 wildcard）、文字簽章，以及 resources、sections、overlay、base64 中的嵌入檔偵測。',
  '**不會崩潰的解析器**：imports（INT/IAT、delay-load、bound）、exports（forwarded、anonymous、gaps）、resources（version、manifest、字串／訊息表、對話框、選單、圖示）、debug（RSDS、POGO、REPRO、CET）、含 RFC 3161 時間戳記的 Authenticode PKCS#7，以及 .NET metadata（全部 45 種表）。',
  '**威脅獵捕輔助**：MD5/SHA-1/SHA-256 指紋、imphash（與 pefile 相同），並可連結到 VirusTotal、Google、Microsoft Learn 與 MITRE。',
  '**檔案修改**：DLL ⇄ EXE 切換、設定 entry-point、切換 characteristics、刪除 overlay、匯出任何項目、在新分析中開啟嵌入檔。',
  '**報告**：XML、JSON、純文字，內容與 GUI 顯示的表格相同。',
  '**GUI**：tree-view、暗色／亮色主題、可排序與篩選的表格、右鍵選單、拖放、快捷鍵（Ctrl+O、S、E、R、X；Tab 在樹狀中移動）。',
  '**8 種介面語言**：English、繁體中文、简体中文、日本語、한국어、Español、Deutsch、Français，預設跟隨系統語言。'],
 dl='**下載**：到 [Releases](https://github.com/taida957789/PELens/releases/latest) 下載對應平台的檔案（`windows-x64.zip`, `linux-x86_64.tar.gz`, `macos-universal.zip`），各附 `.sha256` 可驗證。Windows：解壓縮後執行 `pelens.exe`。Linux：解壓縮後執行 `./pelens`，或執行 `./install.sh` 安裝到 `~/.local`（含桌面捷徑與圖示）。macOS（Apple silicon 與 Intel）：解壓縮後把 `PELens.app` 拖到「應用程式」；第一次開啟請按右鍵 > 開啟（未經 Apple 公證）。從原始碼建置：',
 build_note='需要 Rust 1.88 以上（edition 2024）。CI 在 Windows、Linux、macOS 上建置並執行全部測試。',
 plat_feat='**跨平台**：Windows、Linux、macOS 功能相同 — Authenticode 驗證在非 Windows 平台使用內建的純 Rust 驗證器（Microsoft 根憑證＋系統根憑證）、VirusTotal key 存在系統憑證庫（Windows 認證管理員、macOS 鑰匙圈、Linux Secret Service）、網路／卸除式磁碟與 ACL 檢查、系統 CJK 字型，macOS 快捷鍵使用 ⌘。',
 usage_note='CLI 預設在樣本旁輸出 `<input>.xml`。',
 kb='PELens 內建自己的**開放知識庫**（`kb/`，CC0）：142 個指標定義、約 2,500 個 Windows API 函式、約 900 個可疑字串、約 100 個簽章，以及 MITRE ATT&CK 對應。它由 `tools/build_kb.py` 從 `kb/src` 產生，每一筆資料都來自公開資料（見 [kb/SOURCES.md](../../kb/SOURCES.md)），沒有複製任何第三方知識庫。也可以用 `-xml:<dir>` 改用其他相同格式的 XML 知識庫檔案；第三方的知識庫檔案不隨 PELens 散佈。',
 vt='只送出**雜湊值**，從不上傳樣本。在設定對話框或 `VT_API_KEY` 環境變數中填入你自己的 API key。預設使用 API v3，也可選 v2。',
 roles=['PE 解析（邊界檢查、不會 panic）與修改', 'XML 知識庫，讀寫時保留原格式', '指標、簽章、字串、檢視、報告、動作', 'VirusTotal、搜尋連結、更新檢查', '命令列', 'eframe/egui 圖形介面'],
 docs='設計文件：[功能盤點](../FEATURE_INVENTORY.md)（212 項，每項附對照）· [開發計畫](../DEVELOPMENT_PLAN.md) · [Tasklist](../TASKLIST.md)。',
 cap_dis='反組譯（經由 IAT 的呼叫顯示函式名稱）與十六進位檢視',
 dis_feat='**反組譯**（x86／x64，iced-x86）：從進入點、匯出函式或 TLS callback 開始；經由 IAT 呼叫的函式會顯示名稱，可跟隨跳躍目標，並可在十六進位檢視中查看。',
 yara_feat='**YARA 掃描**（YARA-X）：在設定 > YARA 或 `-yara:<dir>` 指定規則資料夾；每條命中的規則產生指標（嚴重度取自規則的 `severity` metadata），比對位置可直接在十六進位檢視中查看，也會寫入報告。',
 hex_feat='**十六進位檢視**（Ctrl+H）：只繪製可見的列，大檔案也流暢；各檢視中有位置資訊的項目可右鍵「在十六進位檢視中顯示」，並可前往位移或 RVA、複製為十六進位或文字。',
 h_lang='介面語言',
 lang_note='介面預設跟隨系統語言（Windows 顯示語言、macOS 偏好語言、Linux 的 `LANG`）；可在「檢視 > 語言」或設定對話框中切換，或用 `-lang:<代碼>` 啟動（`en`、`zh-TW`、`zh-CN`、`ja`、`ko`、`es`、`de`、`fr`）。分析結果（表格內容、指標、報告）維持英文，與報告及搜尋一致。翻譯檔位於 `crates/pelens-gui/i18n/`。',
 lang_caps=['繁體中文', '日本語'],
 q=['107 個測試', '約 97% 行覆蓋率', '與 pefile 交叉驗證'],
 disc='PELens 是獨立專案。請僅分析你有權限分析的檔案。',
 crate='crate', role='用途'),
'zh-CN': dict(
 tagline='看清 Portable Executable 的镜头 — 用 Rust 重新打造的 Windows 可执行文件静态恶意软件初步评估工具。',
 intro='PELens **不运行**文件，直接查看 `.exe`、`.dll`、`.sys` 的头部、导入、资源、证书、.NET 元数据和字符串，并生成映射到 MITRE ATT&CK 的指标。以 Rust 从零打造，由可扩展或替换的 XML 知识库驱动。',
 h_shots='截图', h_feat='功能', h_build='安装／构建', h_usage='使用方法', h_kb='知识库', h_vt='VirusTotal', h_layout='项目结构', h_quality='质量', h_disc='免责声明',
 cap=['导入：分组、MITRE 技术和标记', '字符串：标签、位置分布图和分组', '节区（浅色模式）与展开的树视图', 'Authenticode 证书链与 WinVerifyTrust 结果', '.NET header、metadata streams、tables 和 namespaces', '指标（深色模式）'],
 feat=[
  '**27 个视图**：image、footprints、groups、indicators、MITRE、VirusTotal 分数、DOS stub／header、Rich header、file／optional header、directories、sections、libraries、imports、exports、exceptions、certificate、relocations、TLS、.NET、resources、version、debug、strings、manifest、overlay。',
  '**150 个指标**，映射到 MITRE ATT&CK 战术与技术，严重度可调整。',
  '**签名引擎**：入口点签名（PEiD 风格，支持半字节通配符）、文本签名，以及在 resources、sections、overlay、base64 中检测嵌入文件。',
  '**不会崩溃的解析器**：imports（INT/IAT、延迟加载、bound）、exports（转发、匿名、空缺）、resources（version、manifest、字符串／消息表、对话框、菜单、图标）、debug（RSDS、POGO、REPRO、CET）、带 RFC 3161 时间戳的 Authenticode PKCS#7，以及 .NET 元数据（全部 45 张表）。',
  '**威胁狩猎辅助**：MD5/SHA-1/SHA-256 指纹、imphash（与 pefile 一致），并可跳转到 VirusTotal、Google、Microsoft Learn 和 MITRE。',
  '**文件修改**：DLL ⇄ EXE 切换、设置入口点、切换 characteristics、删除 overlay、导出任意项目、在新分析中打开嵌入文件。',
  '**报告**：XML、JSON、纯文本，内容与 GUI 显示的表格一致。',
  '**GUI**：树视图、深色／浅色主题、可排序和筛选的表格、右键菜单、拖放、快捷键（Ctrl+O、S、E、R、X；Tab 在树中移动）。',
  '**8 种界面语言**：English、繁體中文、简体中文、日本語、한국어、Español、Deutsch、Français，默认跟随系统语言。'],
 dl='**下载**：从 [Releases](https://github.com/taida957789/PELens/releases/latest) 下载对应平台的文件（`windows-x64.zip`, `linux-x86_64.tar.gz`, `macos-universal.zip`），各附 `.sha256` 可校验。Windows：解压后运行 `pelens.exe`。Linux：解压后运行 `./pelens`，或运行 `./install.sh` 安装到 `~/.local`（含桌面快捷方式和图标）。macOS（Apple silicon 与 Intel）：解压后将 `PELens.app` 拖入“应用程序”；首次打开请右键 > 打开（未经 Apple 公证）。从源码构建：',
 build_note='需要 Rust 1.88 或更高版本（edition 2024）。CI 在 Windows、Linux、macOS 上构建并运行全部测试。',
 plat_feat='**跨平台**：Windows、Linux、macOS 功能相同 — Authenticode 验证在非 Windows 平台使用内置的纯 Rust 验证器（Microsoft 根证书＋系统根证书）、VirusTotal key 存在系统凭据库（Windows 凭据管理器、macOS 钥匙串、Linux Secret Service）、网络／可移动磁盘与 ACL 检查、系统 CJK 字体，macOS 快捷键使用 ⌘。',
 usage_note='CLI 默认在样本旁输出 `<input>.xml`。',
 kb='PELens 内置自己的**开放知识库**（`kb/`，CC0）：142 个指标定义、约 2,500 个 Windows API 函数、约 900 个可疑字符串、约 100 个签名，以及 MITRE ATT&CK 映射。它由 `tools/build_kb.py` 从 `kb/src` 生成，每一条数据都来自公开资料（见 [kb/SOURCES.md](../../kb/SOURCES.md)），没有复制任何第三方知识库。也可以用 `-xml:<dir>` 改用其他相同格式的 XML 知识库文件；第三方的知识库文件不随 PELens 分发。',
 vt='只发送**哈希值**，从不上传样本。在设置对话框或 `VT_API_KEY` 环境变量中填入你自己的 API key。默认使用 API v3，也可选 v2。',
 roles=['PE 解析（边界检查、不会 panic）与修改', 'XML 知识库，读写时保留原格式', '指标、签名、字符串、视图、报告、操作', 'VirusTotal、搜索链接、更新检查', '命令行', 'eframe/egui 图形界面'],
 docs='设计文档：[功能清单](../FEATURE_INVENTORY.md)（212 项，每项附对照）· [开发计划](../DEVELOPMENT_PLAN.md) · [任务清单](../TASKLIST.md)。',
 cap_dis='反汇编（通过 IAT 的调用显示函数名）与十六进制视图',
 dis_feat='**反汇编**（x86／x64，iced-x86）：从入口点、导出函数或 TLS callback 开始；通过 IAT 调用的函数会显示名称，可跟随跳转目标，并可在十六进制视图中查看。',
 yara_feat='**YARA 扫描**（YARA-X）：在设置 > YARA 或 `-yara:<dir>` 指定规则文件夹；每条命中的规则产生指标（严重性取自规则的 `severity` metadata），匹配位置可直接在十六进制视图中查看，也会写入报告。',
 hex_feat='**十六进制视图**（Ctrl+H）：只绘制可见的行，大文件也流畅；各视图中带位置信息的项目可右键“在十六进制视图中显示”，并可转到偏移或 RVA、复制为十六进制或文本。',
 h_lang='界面语言',
 lang_note='界面默认跟随系统语言（Windows 显示语言、macOS 首选语言、Linux 的 `LANG`）；可在“视图 > 语言”或设置对话框中切换，或用 `-lang:<代码>` 启动（`en`、`zh-TW`、`zh-CN`、`ja`、`ko`、`es`、`de`、`fr`）。分析结果（表格内容、指标、报告）保持英文，与报告及搜索一致。翻译文件位于 `crates/pelens-gui/i18n/`。',
 lang_caps=['繁體中文', '日本語'],
 q=['107 个测试', '约 97% 行覆盖率', '与 pefile 交叉验证'],
 disc='PELens 是独立项目。请仅分析你有权分析的文件。',
 crate='crate', role='用途'),
'ja': dict(
 tagline='Portable Executable のためのレンズ — Rust で作り直した、Windows バイナリ向けの静的マルウェア初期評価ツール。',
 intro='PELens は `.exe`・`.dll`・`.sys` を**実行せずに**調べます。ヘッダー、インポート、リソース、証明書、.NET メタデータ、文字列を表示し、MITRE ATT&CK に対応したインジケーターを出します。Rust でゼロから実装され、拡張や置き換えのできる XML ナレッジベースで動作します。',
 h_shots='スクリーンショット', h_feat='機能', h_build='インストール／ビルド', h_usage='使い方', h_kb='ナレッジベース', h_vt='VirusTotal', h_layout='プロジェクト構成', h_quality='品質', h_disc='免責事項',
 cap=['インポート：グループ、MITRE テクニック、フラグ', '文字列：ラベル、位置マップ、グループ', 'セクション（ライトモード）と展開したツリービュー', 'Authenticode 証明書チェーンと WinVerifyTrust の結果', '.NET ヘッダー、メタデータストリーム、テーブル、名前空間', 'インジケーター（ダークモード）'],
 feat=[
  '**27 のビュー**：image、footprints、groups、indicators、MITRE、VirusTotal スコア、DOS stub／header、Rich header、file／optional header、directories、sections、libraries、imports、exports、exceptions、certificate、relocations、TLS、.NET、resources、version、debug、strings、manifest、overlay。',
  'MITRE ATT&CK の戦術・テクニックに対応した **150 のインジケーター**。重大度は編集できます。',
  '**シグネチャエンジン**：エントリポイントシグネチャ（PEiD 形式、ニブル単位のワイルドカード対応）、テキストシグネチャ、resources・sections・overlay・base64 内の埋め込みファイル検出。',
  '**パニックしないパーサー**：imports（INT/IAT、遅延ロード、bound）、exports（forwarded、anonymous、gaps）、resources（version、manifest、文字列／メッセージテーブル、ダイアログ、メニュー、アイコン）、debug（RSDS、POGO、REPRO、CET）、RFC 3161 タイムスタンプ付き Authenticode PKCS#7、.NET メタデータ（全 45 テーブル）。',
  '**ハンティング支援**：MD5/SHA-1/SHA-256 フットプリント、imphash（pefile と同一）、VirusTotal・Google・Microsoft Learn・MITRE へのリンク。',
  '**ファイル変更**：DLL ⇄ EXE の切り替え、エントリポイントの設定、characteristics の切り替え、overlay の削除、任意の項目のダンプ、埋め込みファイルを新しい解析で開く。',
  '**レポート**：XML・JSON・テキスト。GUI と同じテーブルから生成します。',
  '**GUI**：ツリービュー、ダーク／ライトテーマ、並べ替え・絞り込みできるテーブル、右クリックメニュー、ドラッグ＆ドロップ、ショートカット（Ctrl+O・S・E・R・X、Tab でツリーを移動）。',
  '**8 つの表示言語**：English、繁體中文、简体中文、日本語、한국어、Español、Deutsch、Français。既定ではシステムの言語に合わせます。'],
 dl='**ダウンロード**：[Releases](https://github.com/taida957789/PELens/releases/latest) から各プラットフォーム用のファイル（`windows-x64.zip`, `linux-x86_64.tar.gz`, `macos-universal.zip`）を入手してください。それぞれ検証用の `.sha256` が付いています。Windows：展開して `pelens.exe` を実行。Linux：展開して `./pelens` を実行するか、`./install.sh` で `~/.local` にインストール（デスクトップエントリとアイコン付き）。macOS（Apple silicon と Intel）：展開して `PELens.app` を「アプリケーション」へ。初回は右クリック > 開く（Apple の公証なし）。ソースからビルドする場合：',
 build_note='Rust 1.88 以降（edition 2024）が必要です。CI は Windows・Linux・macOS でビルドし、全テストを実行します。',
 plat_feat='**クロスプラットフォーム**：Windows・Linux・macOS で同じ機能 — Windows 以外の Authenticode 検証は内蔵の純 Rust 検証器（Microsoft ルート＋OS のルート）、VirusTotal キーは OS の資格情報ストア（Windows 資格情報マネージャー、macOS キーチェーン、Linux Secret Service）、ネットワーク／リムーバブルドライブと ACL の確認、OS の CJK フォント、macOS では ⌘ ショートカット。',
 usage_note='CLI は既定でサンプルの隣に `<input>.xml` を書き出します。',
 kb='PELens は独自の**オープンナレッジベース**（`kb/`、CC0）を内蔵しています。142 のインジケーター定義、約 2,500 の Windows API 関数、約 900 の不審な文字列、約 100 のシグネチャ、MITRE ATT&CK の対応付けを含みます。`tools/build_kb.py` で `kb/src` から生成され、すべての項目は公開情報に基づいて書かれています（[kb/SOURCES.md](../../kb/SOURCES.md) を参照）。第三者のナレッジベースはコピーしていません。`-xml:<dir>` で同じ形式の別の XML ナレッジファイルを使うこともできます。第三者のナレッジファイルは PELens に同梱されません。',
 vt='送信するのは**ハッシュだけ**で、サンプルはアップロードしません。API キーは設定ダイアログか `VT_API_KEY` で指定してください。既定は API v3 で、v2 も選べます。',
 roles=['PE 解析（境界チェック済み、パニックしない）とパッチ', 'XML ナレッジベース（書式を保ったまま読み書き）', 'インジケーター、シグネチャ、文字列、ビュー、レポート、アクション', 'VirusTotal、検索リンク、更新チェック', 'コマンドライン', 'eframe/egui GUI'],
 docs='設計資料：[機能一覧](../FEATURE_INVENTORY.md)（212 項目、それぞれ実装箇所へのリンク付き）· [開発計画](../DEVELOPMENT_PLAN.md) · [タスクリスト](../TASKLIST.md)。',
 cap_dis='逆アセンブル（IAT 経由の呼び出しに関数名）と 16 進ビュー',
 dis_feat='**逆アセンブル**（x86／x64、iced-x86）：エントリポイント、エクスポート関数、TLS コールバックから開始できます。IAT 経由の呼び出しは関数名を表示し、分岐先へ移動でき、16 進ビューでも確認できます。',
 yara_feat='**YARA スキャン**（YARA-X）：設定 > YARA または `-yara:<dir>` でルールのフォルダーを指定します。一致したルールごとにインジケーターを出し（重大度はルールの `severity` メタデータ）、一致位置は 16 進ビューで確認でき、レポートにも出力されます。',
 hex_feat='**16 進ビュー**（Ctrl+H）：表示中の行だけを描画するので大きなファイルでも軽快です。位置情報のある項目は右クリックの「16 進ビューで表示」から開け、オフセットや RVA への移動、16 進またはテキストでのコピーができます。',
 h_lang='表示言語',
 lang_note='表示言語は既定でシステムの言語（Windows の表示言語、macOS の優先言語、Linux の `LANG`）に従います。「表示 > 言語」または設定ダイアログで切り替えるか、`-lang:<コード>`（`en`・`zh-TW`・`zh-CN`・`ja`・`ko`・`es`・`de`・`fr`）で起動してください。解析結果（テーブルの内容、インジケーター、レポート）は、レポートや検索と一致するよう英語のままです。翻訳ファイルは `crates/pelens-gui/i18n/` にあります。',
 lang_caps=['繁體中文', '日本語'],
 q=['107 件のテスト', '約 97% の行カバレッジ', 'pefile とのクロスチェック'],
 disc='PELens は独立したプロジェクトです。解析する権限のあるファイルにのみ使用してください。',
 crate='crate', role='役割'),
'ko': dict(
 tagline='Portable Executable을 들여다보는 렌즈 — Rust로 다시 만든 Windows 바이너리 정적 악성코드 초기 분석 도구.',
 intro='PELens는 `.exe`, `.dll`, `.sys` 파일을 **실행하지 않고** 검사합니다. 헤더, 임포트, 리소스, 인증서, .NET 메타데이터, 문자열을 보여 주고 MITRE ATT&CK에 매핑된 지표를 생성합니다. Rust로 처음부터 구현했으며, 확장하거나 교체할 수 있는 XML 지식 베이스로 동작합니다.',
 h_shots='스크린샷', h_feat='기능', h_build='설치／빌드', h_usage='사용법', h_kb='지식 베이스', h_vt='VirusTotal', h_layout='프로젝트 구조', h_quality='품질', h_disc='면책 조항',
 cap=['임포트: 그룹, MITRE 기법, 플래그', '문자열: 레이블, 위치 맵, 그룹', '섹션(라이트 모드)과 펼친 트리 뷰', 'Authenticode 인증서 체인과 WinVerifyTrust 결과', '.NET 헤더, 메타데이터 스트림, 테이블, 네임스페이스', '지표(다크 모드)'],
 feat=[
  '**27개 뷰**: image, footprints, groups, indicators, MITRE, VirusTotal 점수, DOS stub/header, Rich header, file/optional header, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest, overlay.',
  'MITRE ATT&CK 전술·기법에 매핑된 **150개 지표**, 심각도 수정 가능.',
  '**시그니처 엔진**: 엔트리 포인트 시그니처(PEiD 방식, 니블 와일드카드 지원), 텍스트 시그니처, resources·sections·overlay·base64 안의 내장 파일 탐지.',
  '**패닉하지 않는 파서**: imports(INT/IAT, 지연 로드, bound), exports(forwarded, anonymous, gaps), resources(version, manifest, 문자열·메시지 테이블, 대화 상자, 메뉴, 아이콘), debug(RSDS, POGO, REPRO, CET), RFC 3161 타임스탬프를 포함한 Authenticode PKCS#7, .NET 메타데이터(45개 테이블 전부).',
  '**헌팅 도우미**: MD5/SHA-1/SHA-256 지문, imphash(pefile과 동일), VirusTotal·Google·Microsoft Learn·MITRE 링크.',
  '**파일 수정**: DLL ⇄ EXE 전환, 엔트리 포인트 설정, characteristics 전환, overlay 삭제, 항목 덤프, 내장 파일을 새 분석으로 열기.',
  '**보고서**: XML, JSON, 텍스트. GUI와 같은 테이블로 만듭니다.',
  '**GUI**: 트리 뷰, 다크·라이트 테마, 정렬·필터 가능한 테이블, 컨텍스트 메뉴, 드래그 앤 드롭, 단축키(Ctrl+O, S, E, R, X, Tab으로 트리 이동).',
  '**8개 인터페이스 언어**: English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch, Français. 기본값은 시스템 언어를 따릅니다.'],
 dl='**다운로드**: [Releases](https://github.com/taida957789/PELens/releases/latest)에서 플랫폼별 파일(`windows-x64.zip`, `linux-x86_64.tar.gz`, `macos-universal.zip`)을 받으세요. 각각 검증용 `.sha256`이 함께 제공됩니다. Windows: 압축을 풀고 `pelens.exe` 실행. Linux: 압축을 풀고 `./pelens`를 실행하거나 `./install.sh`로 `~/.local`에 설치(데스크톱 항목과 아이콘 포함). macOS(Apple silicon 및 Intel): 압축을 풀고 `PELens.app`을 응용 프로그램 폴더로 옮기세요. 처음에는 오른쪽 클릭 > 열기(Apple 공증 없음). 소스에서 빌드하려면:',
 build_note='Rust 1.88 이상(edition 2024)이 필요합니다. CI가 Windows, Linux, macOS에서 빌드하고 모든 테스트를 실행합니다.',
 plat_feat='**크로스 플랫폼**: Windows, Linux, macOS에서 같은 기능 — Windows 외 플랫폼의 Authenticode 검증은 내장된 순수 Rust 검증기(Microsoft 루트 + OS 루트), VirusTotal 키는 OS 자격 증명 저장소(Windows 자격 증명 관리자, macOS 키체인, Linux Secret Service), 네트워크/이동식 드라이브와 ACL 확인, OS CJK 글꼴, macOS에서는 ⌘ 단축키.',
 usage_note='CLI는 기본적으로 샘플 옆에 `<input>.xml`을 씁니다.',
 kb='PELens에는 자체 **오픈 지식 베이스**(`kb/`, CC0)가 내장되어 있습니다. 지표 정의 142개, Windows API 함수 약 2,500개, 의심 문자열 약 900개, 시그니처 약 100개와 MITRE ATT&CK 매핑을 담고 있습니다. `tools/build_kb.py`로 `kb/src`에서 생성하며, 모든 항목은 공개 자료를 바탕으로 작성했습니다([kb/SOURCES.md](../../kb/SOURCES.md) 참고). 제3자 지식 베이스는 복사하지 않았습니다. `-xml:<dir>`로 같은 형식의 다른 XML 지식 파일을 사용할 수도 있습니다. 제3자 지식 파일은 PELens와 함께 배포되지 않습니다.',
 vt='**해시만** 전송하며 샘플은 절대 업로드하지 않습니다. 설정 대화 상자나 `VT_API_KEY`에 본인의 API 키를 넣으세요. 기본은 API v3이며 v2도 선택할 수 있습니다.',
 roles=['PE 파싱(경계 검사, 패닉 없음)과 패치', 'XML 지식 베이스(서식을 유지한 채 읽기·쓰기)', '지표, 시그니처, 문자열, 뷰, 보고서, 동작', 'VirusTotal, 검색 링크, 업데이트 확인', '명령줄', 'eframe/egui GUI'],
 docs='설계 문서: [기능 목록](../FEATURE_INVENTORY.md)(212개 항목, 각 항목에 구현 위치 연결) · [개발 계획](../DEVELOPMENT_PLAN.md) · [작업 목록](../TASKLIST.md).',
 cap_dis='디스어셈블리(IAT 호출에 함수 이름 표시)와 16진수 보기',
 dis_feat='**디스어셈블리**(x86/x64, iced-x86): 진입점, 익스포트 함수, TLS 콜백에서 시작합니다. IAT를 통한 호출은 함수 이름을 보여 주고, 분기 대상을 따라가며, 16진수 보기에서도 볼 수 있습니다.',
 yara_feat='**YARA 검사**(YARA-X): 설정 > YARA 또는 `-yara:<dir>`로 규칙 폴더를 지정합니다. 일치한 규칙마다 지표를 만들고(심각도는 규칙의 `severity` 메타데이터), 일치 위치는 16진수 보기에서 바로 보며 보고서에도 기록됩니다.',
 hex_feat='**16진수 보기**(Ctrl+H): 보이는 행만 그려 큰 파일도 부드럽습니다. 위치 정보가 있는 항목은 오른쪽 클릭의 "16진수 보기에서 표시"로 열 수 있고, 오프셋이나 RVA로 이동하거나 16진수·텍스트로 복사할 수 있습니다.',
 h_lang='인터페이스 언어',
 lang_note='인터페이스는 기본적으로 시스템 언어(Windows 표시 언어, macOS 선호 언어, Linux `LANG`)를 따릅니다. "보기 > 언어" 또는 설정 대화 상자에서 바꾸거나 `-lang:<코드>`(`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`)로 시작하세요. 분석 결과(테이블 내용, 지표, 보고서)는 보고서 및 검색과 일치하도록 영어로 유지됩니다. 번역 파일은 `crates/pelens-gui/i18n/`에 있습니다.',
 lang_caps=['繁體中文', '日本語'],
 q=['테스트 107개', '라인 커버리지 약 97%', 'pefile과 교차 검증'],
 disc='PELens는 독립 프로젝트입니다. 분석 권한이 있는 파일에만 사용하세요.',
 crate='crate', role='역할'),
'es': dict(
 tagline='Una lente para Portable Executables: evaluación inicial estática de malware para binarios de Windows, reconstruida en Rust.',
 intro='PELens examina archivos `.exe`, `.dll` y `.sys` **sin ejecutarlos**. Muestra sus cabeceras, importaciones, recursos, certificados, metadatos .NET y cadenas, y genera indicadores asociados a MITRE ATT&CK. Está escrito desde cero en Rust y funciona con una base de conocimiento XML que puede ampliar o sustituir.',
 h_shots='Capturas', h_feat='Funciones', h_build='Instalación / compilación', h_usage='Uso', h_kb='Base de conocimiento', h_vt='VirusTotal', h_layout='Estructura del proyecto', h_quality='Calidad', h_disc='Aviso',
 cap=['Importaciones con grupos, técnicas MITRE y marcas', 'Cadenas con etiquetas, mapa de ubicación y grupos', 'Secciones (modo claro) con la vista de árbol expandida', 'Cadena de certificados Authenticode y resultado de WinVerifyTrust', 'Cabecera .NET, flujos de metadatos, tablas y espacios de nombres', 'Indicadores (modo oscuro)'],
 feat=[
  '**27 vistas**: image, footprints, groups, indicators, MITRE, puntuación de VirusTotal, DOS stub y header, Rich header, file y optional headers, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest y overlay.',
  '**150 indicadores**, asociados a tácticas y técnicas de MITRE ATT&CK, con severidad editable.',
  '**Motor de firmas**: firmas del punto de entrada (estilo PEiD, con comodines de nibble), firmas de texto y detección de archivos incrustados en recursos, secciones, el overlay y datos base64.',
  '**Analizador que nunca entra en pánico**: imports (INT/IAT, carga diferida, bound), exports (reenviados, anónimos, huecos), recursos (version, manifest, tablas de cadenas y mensajes, diálogos, menús, iconos), debug (RSDS, POGO, REPRO, CET), Authenticode PKCS#7 con sellos de tiempo RFC 3161 y metadatos .NET (las 45 tablas).',
  '**Ayudas para threat hunting**: huellas MD5/SHA-1/SHA-256, imphash (idéntico al de pefile) y enlaces a VirusTotal, Google, Microsoft Learn y MITRE.',
  '**Modificación de archivos**: cambiar entre DLL y EXE, fijar el punto de entrada, alternar characteristics, borrar el overlay, volcar cualquier elemento y abrir un archivo incrustado en un nuevo análisis.',
  '**Informes** en XML, JSON o texto, generados a partir de las mismas tablas que muestra la GUI.',
  '**GUI**: vista de árbol, temas oscuro y claro, tablas ordenables y filtrables, menús contextuales, arrastrar y soltar, y atajos (Ctrl+O, S, E, R, X; Tab recorre el árbol).',
  '**Interfaz en 8 idiomas**: English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch y Français; por defecto sigue el idioma del sistema.'],
 dl='**Descarga**: obtenga el archivo de su plataforma (`windows-x64.zip`, `linux-x86_64.tar.gz`, `macos-universal.zip`) en [Releases](https://github.com/taida957789/PELens/releases/latest); cada uno incluye un `.sha256` para verificarlo. Windows: descomprima y ejecute `pelens.exe`. Linux: descomprima y ejecute `./pelens`, o `./install.sh` para instalarlo en `~/.local` (con entrada de escritorio e icono). macOS (Apple silicon e Intel): descomprima y mueva `PELens.app` a Aplicaciones; la primera vez use clic derecho > Abrir (sin notarización de Apple). Para compilar desde el código fuente:',
 build_note='Requiere Rust 1.88 o posterior (edition 2024). La CI compila y ejecuta todas las pruebas en Windows, Linux y macOS.',
 plat_feat='**Multiplataforma**: las mismas funciones en Windows, Linux y macOS: fuera de Windows, Authenticode se verifica con un verificador propio en Rust puro (raíces de Microsoft + raíces del sistema); la clave de VirusTotal se guarda en el almacén de credenciales del sistema (Administrador de credenciales, Llavero de macOS, Secret Service de Linux); comprobación de unidades de red/extraíbles y ACL; fuentes CJK del sistema; atajos con ⌘ en macOS.',
 usage_note='Por defecto la CLI escribe `<input>.xml` junto a la muestra.',
 kb='PELens incluye su propia **base de conocimiento abierta** (`kb/`, CC0): 142 definiciones de indicadores, unas 2.500 funciones de la API de Windows, unas 900 cadenas sospechosas, unas 100 firmas y la correspondencia con MITRE ATT&CK. Se genera desde `kb/src` con `tools/build_kb.py` y cada entrada se escribió a partir de fuentes públicas (ver [kb/SOURCES.md](../../kb/SOURCES.md)); no copia ninguna base de conocimiento de terceros. También puede usar otros archivos de conocimiento XML con el mismo formato mediante `-xml:<dir>`; los archivos de terceros no se distribuyen con PELens.',
 vt='Solo se envía el **hash**; las muestras nunca se suben. Configura tu propia clave de API en el diálogo de ajustes o en `VT_API_KEY`. Se usa la API v3 por defecto; la v2 está disponible como opción.',
 roles=['análisis PE (con comprobación de límites, sin pánicos) y parcheo', 'base de conocimiento XML, lectura y escritura sin reformatear', 'indicadores, firmas, cadenas, vistas, informes, acciones', 'VirusTotal, enlaces de búsqueda, comprobación de actualizaciones', 'línea de comandos', 'GUI eframe/egui'],
 docs='Documentación de diseño: [inventario de funciones](../FEATURE_INVENTORY.md) (212 elementos, cada uno enlazado a su implementación) · [plan de desarrollo](../DEVELOPMENT_PLAN.md) · [lista de tareas](../TASKLIST.md).',
 cap_dis='Desensamblado (llamadas por la IAT con su nombre) y vista hexadecimal',
 dis_feat='**Desensamblado** (x86/x64, iced-x86): desde el punto de entrada, una función exportada o un callback TLS; las llamadas a través de la IAT muestran el nombre de la función, se pueden seguir los saltos y abrir en la vista hexadecimal.',
 yara_feat='**Análisis YARA** (YARA-X): indique la carpeta de reglas en configuración > YARA o con `-yara:<dir>`; cada regla que coincide genera un indicador (gravedad según el metadato `severity` de la regla), las coincidencias se abren en la vista hexadecimal y aparecen en los informes.',
 hex_feat='**Vista hexadecimal** (Ctrl+H): solo dibuja las filas visibles, también fluida con archivos grandes; los elementos con posición se abren con «mostrar en hexadecimal» del menú contextual, con salto a un desplazamiento o RVA y copia como hexadecimal o texto.',
 h_lang='Idiomas de la interfaz',
 lang_note='La interfaz sigue por defecto el idioma del sistema (idioma de Windows, idioma preferido de macOS, `LANG` en Linux). Cámbielo en «ver > idioma» o en la configuración, o inicie con `-lang:<código>` (`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`). Los resultados del análisis (contenido de las tablas, indicadores, informes) se mantienen en inglés para coincidir con los informes y las búsquedas. Las traducciones están en `crates/pelens-gui/i18n/`.',
 lang_caps=['繁體中文', '日本語'],
 q=['107 pruebas', '≈ 97 % de cobertura de líneas', 'verificación cruzada con pefile'],
 disc='PELens es un proyecto independiente. Úsalo solo con archivos que tengas autorización para analizar.',
 crate='crate', role='función'),
'de': dict(
 tagline='Eine Linse für Portable Executables: statische Malware-Ersteinschätzung für Windows-Binärdateien, neu gebaut in Rust.',
 intro='PELens untersucht `.exe`-, `.dll`- und `.sys`-Dateien, **ohne sie auszuführen**. Es zeigt Header, Importe, Ressourcen, Zertifikate, .NET-Metadaten und Strings und erzeugt Indikatoren, die auf MITRE ATT&CK abgebildet sind. Es ist von Grund auf in Rust geschrieben und arbeitet mit einer XML-Wissensbasis, die Sie erweitern oder ersetzen können.',
 h_shots='Screenshots', h_feat='Funktionen', h_build='Installation / Build', h_usage='Verwendung', h_kb='Wissensbasis', h_vt='VirusTotal', h_layout='Projektstruktur', h_quality='Qualität', h_disc='Haftungsausschluss',
 cap=['Importe mit Gruppen, MITRE-Techniken und Markierungen', 'Strings mit Labels, Positionskarte und Gruppen', 'Sections im hellen Modus mit aufgeklappter Baumansicht', 'Authenticode-Zertifikatskette und WinVerifyTrust-Ergebnis', '.NET-Header, Metadaten-Streams, Tabellen und Namespaces', 'Indikatoren (dunkler Modus)'],
 feat=[
  '**27 Ansichten**: image, footprints, groups, indicators, MITRE, VirusTotal-Bewertung, DOS-Stub und -Header, Rich-Header, File- und Optional-Header, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest und overlay.',
  '**150 Indikatoren**, abgebildet auf MITRE-ATT&CK-Taktiken und -Techniken, mit editierbarem Schweregrad.',
  '**Signatur-Engine**: Entry-Point-Signaturen (PEiD-Stil, mit Nibble-Wildcards), Textsignaturen und Erkennung eingebetteter Dateien in Ressourcen, Sections, Overlay und Base64-Daten.',
  '**Parser ohne Panics**: Importe (INT/IAT, Delay-Load, Bound), Exporte (weitergeleitet, anonym, Lücken), Ressourcen (Version, Manifest, String- und Message-Tabellen, Dialoge, Menüs, Icons), Debug (RSDS, POGO, REPRO, CET), Authenticode PKCS#7 mit RFC-3161-Zeitstempeln und .NET-Metadaten (alle 45 Tabellen).',
  '**Hilfen für Threat Hunting**: MD5/SHA-1/SHA-256-Fingerabdrücke, imphash (identisch zu pefile) und Links zu VirusTotal, Google, Microsoft Learn und MITRE.',
  '**Dateiänderungen**: zwischen DLL und EXE wechseln, Entry Point setzen, Characteristics umschalten, Overlay löschen, beliebige Elemente dumpen und eingebettete Dateien in einer neuen Analyse öffnen.',
  '**Berichte** als XML, JSON oder Text, erzeugt aus denselben Tabellen, die die GUI anzeigt.',
  '**GUI**: Baumansicht, dunkles und helles Design, sortier- und filterbare Tabellen, Kontextmenüs, Drag & Drop und Tastenkürzel (Strg+O, S, E, R, X; Tab bewegt sich durch den Baum).',
  '**Oberfläche in 8 Sprachen**: English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch und Français; standardmäßig die Systemsprache.'],
 dl='**Download**: Laden Sie unter [Releases](https://github.com/taida957789/PELens/releases/latest) die Datei Ihrer Plattform herunter (`windows-x64.zip`, `linux-x86_64.tar.gz`, `macos-universal.zip`); jeweils liegt eine `.sha256`-Datei zur Prüfung bei. Windows: entpacken und `pelens.exe` starten. Linux: entpacken und `./pelens` starten oder mit `./install.sh` nach `~/.local` installieren (mit Desktop-Eintrag und Symbol). macOS (Apple Silicon und Intel): entpacken und `PELens.app` in „Programme“ ziehen; beim ersten Mal Rechtsklick > Öffnen (nicht von Apple notariell beglaubigt). Aus dem Quellcode bauen:',
 build_note='Benötigt Rust 1.88 oder neuer (Edition 2024). Die CI baut und testet unter Windows, Linux und macOS.',
 plat_feat='**Plattformübergreifend**: dieselben Funktionen unter Windows, Linux und macOS – außerhalb von Windows prüft ein eingebauter Authenticode-Prüfer in reinem Rust (Microsoft- und System-Stammzertifikate); der VirusTotal-Schlüssel liegt im Anmeldeinformationsspeicher des Systems (Windows-Anmeldeinformationsverwaltung, macOS-Schlüsselbund, Linux Secret Service); Prüfung von Netzwerk-/Wechsellaufwerken und ACL; CJK-Schriften des Systems; ⌘-Kurzbefehle unter macOS.',
 usage_note='Standardmäßig schreibt die CLI `<input>.xml` neben die Probe.',
 kb='PELens bringt eine eigene **offene Wissensbasis** mit (`kb/`, CC0): 142 Indikatordefinitionen, etwa 2.500 Windows-API-Funktionen, etwa 900 verdächtige Strings, etwa 100 Signaturen und die Zuordnung zu MITRE ATT&CK. Sie wird mit `tools/build_kb.py` aus `kb/src` erzeugt; jeder Eintrag stammt aus öffentlichen Quellen (siehe [kb/SOURCES.md](../../kb/SOURCES.md)), nichts ist aus Wissensbasen Dritter kopiert. Mit `-xml:<dir>` können Sie stattdessen andere XML-Wissensdateien im selben Format verwenden; Dateien Dritter werden nicht mit PELens verteilt.',
 vt='Es wird nur der **Hash** gesendet; Proben werden nie hochgeladen. Trage deinen eigenen API-Schlüssel im Einstellungsdialog oder in `VT_API_KEY` ein. Standard ist API v3; v2 ist optional verfügbar.',
 roles=['PE-Parsing (mit Grenzprüfungen, ohne Panics) und Patching', 'XML-Wissensbasis, Lesen und Schreiben ohne Umformatierung', 'Indikatoren, Signaturen, Strings, Ansichten, Berichte, Aktionen', 'VirusTotal, Suchlinks, Update-Prüfung', 'Kommandozeile', 'eframe/egui-GUI'],
 docs='Designdokumente: [Funktionsinventar](../FEATURE_INVENTORY.md) (212 Punkte, jeweils mit Verweis auf die Implementierung) · [Entwicklungsplan](../DEVELOPMENT_PLAN.md) · [Aufgabenliste](../TASKLIST.md).',
 cap_dis='Disassemblierung (IAT-Aufrufe mit Funktionsnamen) und Hex-Ansicht',
 dis_feat='**Disassemblierung** (x86/x64, iced-x86): ab dem Einstiegspunkt, einer exportierten Funktion oder einem TLS-Callback; Aufrufe über die IAT zeigen den Funktionsnamen, Sprüngen kann gefolgt werden, und alles öffnet sich in der Hex-Ansicht.',
 yara_feat='**YARA-Scan** (YARA-X): Regelordner unter Einstellungen > YARA oder mit `-yara:<dir>` angeben; jede zutreffende Regel erzeugt einen Indikator (Schweregrad aus dem Metadatum `severity` der Regel), Treffer öffnen sich in der Hex-Ansicht und erscheinen in den Berichten.',
 hex_feat='**Hex-Ansicht** (Strg+H): zeichnet nur sichtbare Zeilen und bleibt auch bei großen Dateien flüssig; Einträge mit Position öffnen sich über „in der Hex-Ansicht zeigen“ im Kontextmenü, mit Sprung zu Offset oder RVA und Kopieren als Hex oder Text.',
 h_lang='Sprachen der Oberfläche',
 lang_note='Die Oberfläche folgt standardmäßig der Systemsprache (Windows-Anzeigesprache, bevorzugte Sprache von macOS, `LANG` unter Linux). Wechseln Sie sie unter „Ansicht > Sprache“ oder in den Einstellungen, oder starten Sie mit `-lang:<Code>` (`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`). Analyseergebnisse (Tabelleninhalte, Indikatoren, Berichte) bleiben auf Englisch, damit sie mit Berichten und der Suche übereinstimmen. Die Übersetzungen liegen in `crates/pelens-gui/i18n/`.',
 lang_caps=['繁體中文', '日本語'],
 q=['107 Tests', '≈ 97 % Zeilenabdeckung', 'Abgleich mit pefile'],
 disc='PELens ist ein unabhängiges Projekt. Verwende es nur für Dateien, die du analysieren darfst.',
 crate='Crate', role='Aufgabe'),
'fr': dict(
 tagline='Une loupe pour les Portable Executables : évaluation initiale statique des malwares pour les binaires Windows, réécrite en Rust.',
 intro='PELens examine les fichiers `.exe`, `.dll` et `.sys` **sans les exécuter**. Il affiche leurs en-têtes, imports, ressources, certificats, métadonnées .NET et chaînes, et génère des indicateurs associés à MITRE ATT&CK. Il est écrit de zéro en Rust et s\'appuie sur une base de connaissances XML que vous pouvez enrichir ou remplacer.',
 h_shots="Captures d'écran", h_feat='Fonctionnalités', h_build='Installation / compilation', h_usage='Utilisation', h_kb='Base de connaissances', h_vt='VirusTotal', h_layout='Structure du projet', h_quality='Qualité', h_disc='Avertissement',
 cap=['Imports avec groupes, techniques MITRE et marqueurs', 'Chaînes avec étiquettes, carte des emplacements et groupes', "Sections en mode clair avec l'arborescence dépliée", 'Chaîne de certificats Authenticode et résultat de WinVerifyTrust', 'En-tête .NET, flux de métadonnées, tables et espaces de noms', 'Indicateurs (mode sombre)'],
 feat=[
  '**27 vues** : image, footprints, groups, indicators, MITRE, score VirusTotal, stub et en-tête DOS, en-tête Rich, en-têtes file et optional, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest et overlay.',
  '**150 indicateurs**, associés aux tactiques et techniques MITRE ATT&CK, avec une gravité modifiable.',
  "**Moteur de signatures** : signatures du point d'entrée (style PEiD, avec jokers au niveau du quartet), signatures texte et détection de fichiers intégrés dans les ressources, les sections, l'overlay et les données base64.",
  '**Analyseur qui ne panique jamais** : imports (INT/IAT, chargement différé, bound), exports (redirigés, anonymes, trous), ressources (version, manifest, tables de chaînes et de messages, boîtes de dialogue, menus, icônes), debug (RSDS, POGO, REPRO, CET), Authenticode PKCS#7 avec horodatages RFC 3161 et métadonnées .NET (les 45 tables).',
  '**Aide au threat hunting** : empreintes MD5/SHA-1/SHA-256, imphash (identique à celui de pefile) et liens vers VirusTotal, Google, Microsoft Learn et MITRE.',
  "**Modification de fichiers** : basculer entre DLL et EXE, définir le point d'entrée, basculer les characteristics, supprimer l'overlay, extraire n'importe quel élément et ouvrir un fichier intégré dans une nouvelle analyse.",
  "**Rapports** en XML, JSON ou texte, construits à partir des mêmes tables que celles de l'interface.",
  "**Interface graphique** : arborescence, thèmes sombre et clair, tableaux triables et filtrables, menus contextuels, glisser-déposer et raccourcis (Ctrl+O, S, E, R, X ; Tab parcourt l'arborescence).",
  '**Interface en 8 langues** : English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch et Français ; par défaut, la langue du système.'],
 dl='**Téléchargement** : récupérez le fichier de votre plateforme (`windows-x64.zip`, `linux-x86_64.tar.gz`, `macos-universal.zip`) sur [Releases](https://github.com/taida957789/PELens/releases/latest) ; chacun est accompagné d’un `.sha256`. Windows : décompressez et lancez `pelens.exe`. Linux : décompressez et lancez `./pelens`, ou `./install.sh` pour l’installer dans `~/.local` (avec entrée de bureau et icône). macOS (Apple silicon et Intel) : décompressez et placez `PELens.app` dans Applications ; la première fois, clic droit > Ouvrir (pas de notarisation Apple). Pour compiler depuis les sources :',
 build_note='Nécessite Rust 1.88 ou plus récent (édition 2024). La CI compile et exécute tous les tests sous Windows, Linux et macOS.',
 plat_feat='**Multiplateforme** : les mêmes fonctions sous Windows, Linux et macOS — hors Windows, Authenticode est vérifié par un vérificateur intégré en Rust pur (racines Microsoft + racines du système) ; la clé VirusTotal est rangée dans le magasin d’identifiants du système (Gestionnaire d’identification Windows, trousseau macOS, Secret Service sous Linux) ; détection des lecteurs réseau/amovibles et ACL ; polices CJK du système ; raccourcis ⌘ sous macOS.',
 usage_note="Par défaut, la CLI écrit `<input>.xml` à côté de l'échantillon.",
 kb='PELens embarque sa propre **base de connaissances ouverte** (`kb/`, CC0) : 142 définitions d’indicateurs, environ 2 500 fonctions de l’API Windows, environ 900 chaînes suspectes, environ 100 signatures et la correspondance avec MITRE ATT&CK. Elle est générée depuis `kb/src` par `tools/build_kb.py` ; chaque entrée provient de sources publiques (voir [kb/SOURCES.md](../../kb/SOURCES.md)) et rien n’est copié d’une base de connaissances tierce. Vous pouvez aussi utiliser d’autres fichiers de connaissances XML au même format avec `-xml:<dir>` ; les fichiers tiers ne sont pas distribués avec PELens.',
 vt="Seul le **hash** est envoyé ; les échantillons ne sont jamais téléversés. Saisissez votre propre clé d'API dans la boîte de dialogue des réglages ou dans `VT_API_KEY`. L'API v3 est utilisée par défaut ; la v2 est disponible en option.",
 roles=['analyse PE (bornes vérifiées, jamais de panique) et modification', 'base de connaissances XML, lecture et écriture sans reformatage', 'indicateurs, signatures, chaînes, vues, rapports, actions', 'VirusTotal, liens de recherche, vérification des mises à jour', 'ligne de commande', 'interface eframe/egui'],
 docs='Documents de conception : [inventaire des fonctionnalités](../FEATURE_INVENTORY.md) (212 éléments, chacun relié à son implémentation) · [plan de développement](../DEVELOPMENT_PLAN.md) · [liste des tâches](../TASKLIST.md).',
 cap_dis='Désassemblage (appels via l’IAT nommés) et vue hexadécimale',
 dis_feat='**Désassemblage** (x86/x64, iced-x86) : depuis le point d’entrée, une fonction exportée ou un callback TLS ; les appels via l’IAT affichent le nom de la fonction, on peut suivre les branchements et ouvrir le tout dans la vue hexadécimale.',
 yara_feat='**Analyse YARA** (YARA-X) : indiquez le dossier de règles dans paramètres > YARA ou avec `-yara:<dir>` ; chaque règle correspondante produit un indicateur (gravité tirée de la métadonnée `severity` de la règle), les correspondances s’ouvrent dans la vue hexadécimale et figurent dans les rapports.',
 hex_feat='**Vue hexadécimale** (Ctrl+H) : seules les lignes visibles sont dessinées, fluide même avec de gros fichiers ; les éléments ayant une position s’ouvrent via « afficher en hexadécimal » du menu contextuel, avec saut vers un offset ou une RVA et copie en hexadécimal ou en texte.',
 h_lang='Langues de l’interface',
 lang_note='Par défaut, l’interface suit la langue du système (langue d’affichage de Windows, langue préférée de macOS, `LANG` sous Linux). Changez-la dans « affichage > langue » ou dans les paramètres, ou lancez PELens avec `-lang:<code>` (`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`). Les résultats d’analyse (contenu des tableaux, indicateurs, rapports) restent en anglais pour correspondre aux rapports et à la recherche. Les traductions se trouvent dans `crates/pelens-gui/i18n/`.',
 lang_caps=['繁體中文', '日本語'],
 q=['107 tests', '≈ 97 % de couverture des lignes', 'vérification croisée avec pefile'],
 disc="PELens est un projet indépendant. Ne l'utilisez que sur des fichiers que vous êtes autorisé à analyser.",
 crate='crate', role='rôle'),
}

SHOTS = ['imports-dark', 'strings-dark', 'sections-light', 'certificate-light', 'dotnet-dark']
CRATES = ['pe-parser', 'pe-db', 'pe-analysis', 'pe-online', 'pelens-cli', 'pelens-gui']


def lang_bar(cur):
    parts = []
    for code, name, link in LANGS:
        parts.append(f'<b>{name}</b>' if code == cur else f'<a href="{link}">{name}</a>')
    return ' ·\n  '.join(parts)


def render(code, t):
    s = '../screenshots/'
    rows = [
        f'| ![{SHOTS[0]}]({s}{SHOTS[0]}.png) | ![{SHOTS[1]}]({s}{SHOTS[1]}.png) |',
        f'| {t["cap"][0]} | {t["cap"][1]} |',
        f'| ![{SHOTS[2]}]({s}{SHOTS[2]}.png) | ![{SHOTS[3]}]({s}{SHOTS[3]}.png) |',
        f'| {t["cap"][2]} | {t["cap"][3]} |',
        f'| ![{SHOTS[4]}]({s}{SHOTS[4]}.png) | ![disassembly]({s}disassembly-hex-dark.png) |',
        f'| {t["cap"][4]} | {t["cap_dis"]} |',
    ]
    feats = '\n'.join(f'- {f}' for f in t['feat'])
    layout = '\n'.join(f'| `{c}` | {r} |' for c, r in zip(CRATES, t['roles']))
    return f'''<p align="center">
  <img src="../../assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">{t["tagline"]}</p>

<p align="center">
  <a href="https://github.com/taida957789/PELens/actions/workflows/ci.yml"><img src="https://github.com/taida957789/PELens/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  · <a href="https://taida957789.github.io/PELens/">Website</a>
</p>

<p align="center">
  {lang_bar(code)}
</p>

---

{t["intro"]}

![{t["cap"][5]}]({s}indicators-dark.png)

## {t["h_shots"]}

| | |
|---|---|
{chr(10).join(rows)}

## {t["h_lang"]}

| | |
|---|---|
| ![{t["lang_caps"][0]}]({s}strings-zh-TW.png) | ![{t["lang_caps"][1]}]({s}indicators-ja.png) |
| {t["lang_caps"][0]} | {t["lang_caps"][1]} |

{t["lang_note"]}

## {t["h_feat"]}

{feats}
- {t["hex_feat"]}
- {t["yara_feat"]}
- {t["dis_feat"]}
- {t["plat_feat"]}

## {t["h_build"]}

{t["dl"]}

```bash
cargo build --release
# target/release/pelens      (GUI; pelens.exe on Windows)
# target/release/pelens-cli  (CLI; pelens-cli.exe on Windows)
```

{t["build_note"]}

## {t["h_usage"]}

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-lang:zh-TW] [-expand] [-hex] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir] [-yara:dir]
```

{t["usage_note"]}

### {t["h_kb"]}

{t["kb"]}

### {t["h_vt"]}

{t["vt"]}

## {t["h_layout"]}

| {t["crate"]} | {t["role"]} |
|---|---|
{layout}

{t["docs"]}

## {t["h_quality"]}

```bash
cargo test --workspace                       # {t["q"][0]}
cargo llvm-cov --workspace --summary-only    # {t["q"][1]}
python tools/crossval.py 250                 # {t["q"][2]}
```

## {t["h_disc"]}

{t["disc"]}
'''


out = os.path.join(os.path.dirname(__file__), '..', 'docs', 'readme')
os.makedirs(out, exist_ok=True)
for code, t in T.items():
    with open(os.path.join(out, f'README.{code}.md'), 'w', encoding='utf-8', newline='\n') as f:
        f.write(render(code, t))
print('generated', sorted(T))
