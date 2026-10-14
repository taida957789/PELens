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
 intro='PELens **不執行**檔案，直接檢視 `.exe`、`.dll`、`.sys` 的標頭、匯入、資源、憑證、.NET metadata 與字串，並產生對應 MITRE ATT&CK 的指標。它是 **pestudio 9.61** 的 Rust 全新重製版，相容 pestudio 的 XML 知識庫與 `pestudiox` 命令列。',
 h_shots='截圖', h_feat='功能', h_build='安裝／建置', h_usage='使用方式', h_kb='知識庫', h_vt='VirusTotal', h_layout='專案結構', h_quality='品質', h_disc='免責聲明',
 cap=['匯入：群組、MITRE 技術與旗標', '字串：標籤、位置分佈圖與群組', '區段（亮色模式）與展開的 tree-view', 'Authenticode 憑證鏈與 WinVerifyTrust 結果', '.NET header、metadata streams、tables 與 namespaces', '指標（暗色模式）'],
 feat=[
  '**27 個檢視**（與 pestudio 相同）：image、footprints、groups、indicators、MITRE、VirusTotal 分數、DOS stub／header、Rich header、file／optional header、directories、sections、libraries、imports、exports、exceptions、certificate、relocations、TLS、.NET、resources、version、debug、strings、manifest、overlay。',
  '**150 個指標**，對應 MITRE ATT&CK 戰術與技術，嚴重度可調整。',
  '**簽章引擎**：entry-point 簽章（PEiD 風格，支援半位元組 wildcard）、文字簽章，以及 resources、sections、overlay、base64 中的嵌入檔偵測。',
  '**不會崩潰的解析器**：imports（INT/IAT、delay-load、bound）、exports（forwarded、anonymous、gaps）、resources（version、manifest、字串／訊息表、對話框、選單、圖示）、debug（RSDS、POGO、REPRO、CET）、含 RFC 3161 時間戳記的 Authenticode PKCS#7，以及 .NET metadata（全部 45 種表）。',
  '**威脅獵捕輔助**：MD5/SHA-1/SHA-256 指紋、imphash（與 pefile 相同），並可連結到 VirusTotal、Google、Microsoft Learn 與 MITRE。',
  '**檔案修改**：DLL ⇄ EXE 切換、設定 entry-point、切換 characteristics、刪除 overlay、匯出任何項目、在新分析中開啟嵌入檔。',
  '**報告**：XML、JSON、純文字，內容與 GUI 顯示的表格相同。',
  '**GUI**：tree-view、暗色／亮色主題、可排序與篩選的表格、右鍵選單、拖放、快捷鍵（Ctrl+O、S、E、R、X；Tab 在樹狀中移動）。',
  '**8 種介面語言**：English、繁體中文、简体中文、日本語、한국어、Español、Deutsch、Français，預設跟隨 Windows 顯示語言。'],
 build_note='需要 Rust 1.85 以上（edition 2024），於 Windows 11 x64 開發與測試。',
 usage_note='CLI 預設在樣本旁輸出 `<input>.xml`，與 pestudio 相同。',
 kb='PELens 從你自己安裝的 pestudio 讀取其 XML 檔（`settings.xml`、`indicators.xml`、`functions.xml`、`signatures.xml`…）：用 `-xml:<dir>` 指定，或在執行檔旁放一個 `xml` 資料夾。**這些檔案不隨 PELens 散佈**，它們屬於 pestudio 的作者。沒有它們時，PELens 仍會以內建預設值運作。',
 vt='只送出**雜湊值**，從不上傳樣本。在設定對話框或 `VT_API_KEY` 環境變數中填入你自己的 API key。預設使用 API v3，也可選 v2。',
 roles=['PE 解析（邊界檢查、不會 panic）與修改', 'pestudio XML 知識庫，讀寫時保留原格式', '指標、簽章、字串、檢視、報告、動作', 'VirusTotal、搜尋連結、更新檢查', '命令列（相容 pestudiox）', 'eframe/egui 圖形介面'],
 docs='設計文件：[功能盤點](../FEATURE_INVENTORY.md)（212 項，每項附對照）· [開發計畫](../DEVELOPMENT_PLAN.md) · [Tasklist](../TASKLIST.md)。',
 h_lang='介面語言',
 lang_note='介面預設跟隨 Windows 的顯示語言；可在「檢視 > 語言」或設定對話框中切換，或用 `-lang:<代碼>` 啟動（`en`、`zh-TW`、`zh-CN`、`ja`、`ko`、`es`、`de`、`fr`）。分析結果（表格內容、指標、報告）維持英文，與報告及搜尋一致。翻譯檔位於 `crates/pelens-gui/i18n/`。',
 lang_caps=['繁體中文', '日本語'],
 q=['87 個測試', '約 97% 行覆蓋率', '與 pefile 交叉驗證'],
 disc='PELens 是獨立專案，與 Winitor 及 pestudio 作者無關，也未獲其背書。請僅分析你有權限分析的檔案。',
 crate='crate', role='用途'),
'zh-CN': dict(
 tagline='看清 Portable Executable 的镜头 — 用 Rust 重新打造的 Windows 可执行文件静态恶意软件初步评估工具。',
 intro='PELens **不运行**文件，直接查看 `.exe`、`.dll`、`.sys` 的头部、导入、资源、证书、.NET 元数据和字符串，并生成映射到 MITRE ATT&CK 的指标。它是 **pestudio 9.61** 的 Rust 全新重制版，兼容 pestudio 的 XML 知识库和 `pestudiox` 命令行。',
 h_shots='截图', h_feat='功能', h_build='安装／构建', h_usage='使用方法', h_kb='知识库', h_vt='VirusTotal', h_layout='项目结构', h_quality='质量', h_disc='免责声明',
 cap=['导入：分组、MITRE 技术和标记', '字符串：标签、位置分布图和分组', '节区（浅色模式）与展开的树视图', 'Authenticode 证书链与 WinVerifyTrust 结果', '.NET header、metadata streams、tables 和 namespaces', '指标（深色模式）'],
 feat=[
  '**27 个视图**（与 pestudio 相同）：image、footprints、groups、indicators、MITRE、VirusTotal 分数、DOS stub／header、Rich header、file／optional header、directories、sections、libraries、imports、exports、exceptions、certificate、relocations、TLS、.NET、resources、version、debug、strings、manifest、overlay。',
  '**150 个指标**，映射到 MITRE ATT&CK 战术与技术，严重度可调整。',
  '**签名引擎**：入口点签名（PEiD 风格，支持半字节通配符）、文本签名，以及在 resources、sections、overlay、base64 中检测嵌入文件。',
  '**不会崩溃的解析器**：imports（INT/IAT、延迟加载、bound）、exports（转发、匿名、空缺）、resources（version、manifest、字符串／消息表、对话框、菜单、图标）、debug（RSDS、POGO、REPRO、CET）、带 RFC 3161 时间戳的 Authenticode PKCS#7，以及 .NET 元数据（全部 45 张表）。',
  '**威胁狩猎辅助**：MD5/SHA-1/SHA-256 指纹、imphash（与 pefile 一致），并可跳转到 VirusTotal、Google、Microsoft Learn 和 MITRE。',
  '**文件修改**：DLL ⇄ EXE 切换、设置入口点、切换 characteristics、删除 overlay、导出任意项目、在新分析中打开嵌入文件。',
  '**报告**：XML、JSON、纯文本，内容与 GUI 显示的表格一致。',
  '**GUI**：树视图、深色／浅色主题、可排序和筛选的表格、右键菜单、拖放、快捷键（Ctrl+O、S、E、R、X；Tab 在树中移动）。',
  '**8 种界面语言**：English、繁體中文、简体中文、日本語、한국어、Español、Deutsch、Français，默认跟随 Windows 显示语言。'],
 build_note='需要 Rust 1.85 或更高版本（edition 2024），在 Windows 11 x64 上开发和测试。',
 usage_note='CLI 默认在样本旁输出 `<input>.xml`，与 pestudio 相同。',
 kb='PELens 从你自己安装的 pestudio 读取其 XML 文件（`settings.xml`、`indicators.xml`、`functions.xml`、`signatures.xml`…）：用 `-xml:<dir>` 指定，或在可执行文件旁放一个 `xml` 文件夹。**这些文件不随 PELens 分发**，它们属于 pestudio 的作者。没有它们时，PELens 仍会使用内置默认值运行。',
 vt='只发送**哈希值**，从不上传样本。在设置对话框或 `VT_API_KEY` 环境变量中填入你自己的 API key。默认使用 API v3，也可选 v2。',
 roles=['PE 解析（边界检查、不会 panic）与修改', 'pestudio XML 知识库，读写时保留原格式', '指标、签名、字符串、视图、报告、操作', 'VirusTotal、搜索链接、更新检查', '命令行（兼容 pestudiox）', 'eframe/egui 图形界面'],
 docs='设计文档：[功能清单](../FEATURE_INVENTORY.md)（212 项，每项附对照）· [开发计划](../DEVELOPMENT_PLAN.md) · [任务清单](../TASKLIST.md)。',
 h_lang='界面语言',
 lang_note='界面默认跟随 Windows 的显示语言；可在“视图 > 语言”或设置对话框中切换，或用 `-lang:<代码>` 启动（`en`、`zh-TW`、`zh-CN`、`ja`、`ko`、`es`、`de`、`fr`）。分析结果（表格内容、指标、报告）保持英文，与报告及搜索一致。翻译文件位于 `crates/pelens-gui/i18n/`。',
 lang_caps=['繁體中文', '日本語'],
 q=['87 个测试', '约 97% 行覆盖率', '与 pefile 交叉验证'],
 disc='PELens 是独立项目，与 Winitor 及 pestudio 作者无关，也未获其认可。请仅分析你有权分析的文件。',
 crate='crate', role='用途'),
'ja': dict(
 tagline='Portable Executable のためのレンズ — Rust で作り直した、Windows バイナリ向けの静的マルウェア初期評価ツール。',
 intro='PELens は `.exe`・`.dll`・`.sys` を**実行せずに**調べます。ヘッダー、インポート、リソース、証明書、.NET メタデータ、文字列を表示し、MITRE ATT&CK に対応したインジケーターを出します。**pestudio 9.61** を Rust でゼロから再実装したもので、pestudio の XML ナレッジベースと `pestudiox` コマンドラインに対応しています。',
 h_shots='スクリーンショット', h_feat='機能', h_build='インストール／ビルド', h_usage='使い方', h_kb='ナレッジベース', h_vt='VirusTotal', h_layout='プロジェクト構成', h_quality='品質', h_disc='免責事項',
 cap=['インポート：グループ、MITRE テクニック、フラグ', '文字列：ラベル、位置マップ、グループ', 'セクション（ライトモード）と展開したツリービュー', 'Authenticode 証明書チェーンと WinVerifyTrust の結果', '.NET ヘッダー、メタデータストリーム、テーブル、名前空間', 'インジケーター（ダークモード）'],
 feat=[
  'pestudio と同じ **27 のビュー**：image、footprints、groups、indicators、MITRE、VirusTotal スコア、DOS stub／header、Rich header、file／optional header、directories、sections、libraries、imports、exports、exceptions、certificate、relocations、TLS、.NET、resources、version、debug、strings、manifest、overlay。',
  'MITRE ATT&CK の戦術・テクニックに対応した **150 のインジケーター**。重大度は編集できます。',
  '**シグネチャエンジン**：エントリポイントシグネチャ（PEiD 形式、ニブル単位のワイルドカード対応）、テキストシグネチャ、resources・sections・overlay・base64 内の埋め込みファイル検出。',
  '**パニックしないパーサー**：imports（INT/IAT、遅延ロード、bound）、exports（forwarded、anonymous、gaps）、resources（version、manifest、文字列／メッセージテーブル、ダイアログ、メニュー、アイコン）、debug（RSDS、POGO、REPRO、CET）、RFC 3161 タイムスタンプ付き Authenticode PKCS#7、.NET メタデータ（全 45 テーブル）。',
  '**ハンティング支援**：MD5/SHA-1/SHA-256 フットプリント、imphash（pefile と同一）、VirusTotal・Google・Microsoft Learn・MITRE へのリンク。',
  '**ファイル変更**：DLL ⇄ EXE の切り替え、エントリポイントの設定、characteristics の切り替え、overlay の削除、任意の項目のダンプ、埋め込みファイルを新しい解析で開く。',
  '**レポート**：XML・JSON・テキスト。GUI と同じテーブルから生成します。',
  '**GUI**：ツリービュー、ダーク／ライトテーマ、並べ替え・絞り込みできるテーブル、右クリックメニュー、ドラッグ＆ドロップ、ショートカット（Ctrl+O・S・E・R・X、Tab でツリーを移動）。',
  '**8 つの表示言語**：English、繁體中文、简体中文、日本語、한국어、Español、Deutsch、Français。既定では Windows の表示言語に合わせます。'],
 build_note='Rust 1.85 以降（edition 2024）が必要です。Windows 11 x64 で開発・テストしています。',
 usage_note='CLI は既定で、pestudio と同じくサンプルの隣に `<input>.xml` を書き出します。',
 kb='PELens は、お使いの pestudio に含まれる XML ファイル（`settings.xml`、`indicators.xml`、`functions.xml`、`signatures.xml` など）を読み込みます。`-xml:<dir>` で指定するか、実行ファイルの隣に `xml` フォルダーを置いてください。**これらのファイルは PELens には同梱されません**（pestudio の作者のものです）。ファイルがなくても、PELens は組み込みの既定値で動作します。',
 vt='送信するのは**ハッシュだけ**で、サンプルはアップロードしません。API キーは設定ダイアログか `VT_API_KEY` で指定してください。既定は API v3 で、v2 も選べます。',
 roles=['PE 解析（境界チェック済み、パニックしない）とパッチ', 'pestudio XML ナレッジベース（書式を保ったまま読み書き）', 'インジケーター、シグネチャ、文字列、ビュー、レポート、アクション', 'VirusTotal、検索リンク、更新チェック', 'コマンドライン（pestudiox 互換）', 'eframe/egui GUI'],
 docs='設計資料：[機能一覧](../FEATURE_INVENTORY.md)（212 項目、それぞれ実装箇所へのリンク付き）· [開発計画](../DEVELOPMENT_PLAN.md) · [タスクリスト](../TASKLIST.md)。',
 h_lang='表示言語',
 lang_note='表示言語は既定で Windows の表示言語に従います。「表示 > 言語」または設定ダイアログで切り替えるか、`-lang:<コード>`（`en`・`zh-TW`・`zh-CN`・`ja`・`ko`・`es`・`de`・`fr`）で起動してください。解析結果（テーブルの内容、インジケーター、レポート）は、レポートや検索と一致するよう英語のままです。翻訳ファイルは `crates/pelens-gui/i18n/` にあります。',
 lang_caps=['繁體中文', '日本語'],
 q=['87 件のテスト', '約 97% の行カバレッジ', 'pefile とのクロスチェック'],
 disc='PELens は独立したプロジェクトで、Winitor および pestudio の作者とは関係がなく、承認も受けていません。解析する権限のあるファイルにのみ使用してください。',
 crate='crate', role='役割'),
'ko': dict(
 tagline='Portable Executable을 들여다보는 렌즈 — Rust로 다시 만든 Windows 바이너리 정적 악성코드 초기 분석 도구.',
 intro='PELens는 `.exe`, `.dll`, `.sys` 파일을 **실행하지 않고** 검사합니다. 헤더, 임포트, 리소스, 인증서, .NET 메타데이터, 문자열을 보여 주고 MITRE ATT&CK에 매핑된 지표를 생성합니다. **pestudio 9.61**을 Rust로 처음부터 다시 구현했으며, pestudio의 XML 지식 베이스와 `pestudiox` 명령줄과 호환됩니다.',
 h_shots='스크린샷', h_feat='기능', h_build='설치／빌드', h_usage='사용법', h_kb='지식 베이스', h_vt='VirusTotal', h_layout='프로젝트 구조', h_quality='품질', h_disc='면책 조항',
 cap=['임포트: 그룹, MITRE 기법, 플래그', '문자열: 레이블, 위치 맵, 그룹', '섹션(라이트 모드)과 펼친 트리 뷰', 'Authenticode 인증서 체인과 WinVerifyTrust 결과', '.NET 헤더, 메타데이터 스트림, 테이블, 네임스페이스', '지표(다크 모드)'],
 feat=[
  'pestudio와 같은 **27개 뷰**: image, footprints, groups, indicators, MITRE, VirusTotal 점수, DOS stub/header, Rich header, file/optional header, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest, overlay.',
  'MITRE ATT&CK 전술·기법에 매핑된 **150개 지표**, 심각도 수정 가능.',
  '**시그니처 엔진**: 엔트리 포인트 시그니처(PEiD 방식, 니블 와일드카드 지원), 텍스트 시그니처, resources·sections·overlay·base64 안의 내장 파일 탐지.',
  '**패닉하지 않는 파서**: imports(INT/IAT, 지연 로드, bound), exports(forwarded, anonymous, gaps), resources(version, manifest, 문자열·메시지 테이블, 대화 상자, 메뉴, 아이콘), debug(RSDS, POGO, REPRO, CET), RFC 3161 타임스탬프를 포함한 Authenticode PKCS#7, .NET 메타데이터(45개 테이블 전부).',
  '**헌팅 도우미**: MD5/SHA-1/SHA-256 지문, imphash(pefile과 동일), VirusTotal·Google·Microsoft Learn·MITRE 링크.',
  '**파일 수정**: DLL ⇄ EXE 전환, 엔트리 포인트 설정, characteristics 전환, overlay 삭제, 항목 덤프, 내장 파일을 새 분석으로 열기.',
  '**보고서**: XML, JSON, 텍스트. GUI와 같은 테이블로 만듭니다.',
  '**GUI**: 트리 뷰, 다크·라이트 테마, 정렬·필터 가능한 테이블, 컨텍스트 메뉴, 드래그 앤 드롭, 단축키(Ctrl+O, S, E, R, X, Tab으로 트리 이동).',
  '**8개 인터페이스 언어**: English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch, Français. 기본값은 Windows 표시 언어를 따릅니다.'],
 build_note='Rust 1.85 이상(edition 2024)이 필요합니다. Windows 11 x64에서 개발·테스트했습니다.',
 usage_note='CLI는 기본적으로 pestudio처럼 샘플 옆에 `<input>.xml`을 씁니다.',
 kb='PELens는 사용자가 설치한 pestudio의 XML 파일(`settings.xml`, `indicators.xml`, `functions.xml`, `signatures.xml` 등)을 읽습니다. `-xml:<dir>`로 지정하거나 실행 파일 옆에 `xml` 폴더를 두세요. **이 파일들은 PELens와 함께 배포되지 않습니다**. pestudio 작성자의 소유입니다. 파일이 없어도 PELens는 내장 기본값으로 동작합니다.',
 vt='**해시만** 전송하며 샘플은 절대 업로드하지 않습니다. 설정 대화 상자나 `VT_API_KEY`에 본인의 API 키를 넣으세요. 기본은 API v3이며 v2도 선택할 수 있습니다.',
 roles=['PE 파싱(경계 검사, 패닉 없음)과 패치', 'pestudio XML 지식 베이스(서식을 유지한 채 읽기·쓰기)', '지표, 시그니처, 문자열, 뷰, 보고서, 동작', 'VirusTotal, 검색 링크, 업데이트 확인', '명령줄(pestudiox 호환)', 'eframe/egui GUI'],
 docs='설계 문서: [기능 목록](../FEATURE_INVENTORY.md)(212개 항목, 각 항목에 구현 위치 연결) · [개발 계획](../DEVELOPMENT_PLAN.md) · [작업 목록](../TASKLIST.md).',
 h_lang='인터페이스 언어',
 lang_note='인터페이스는 기본적으로 Windows 표시 언어를 따릅니다. "보기 > 언어" 또는 설정 대화 상자에서 바꾸거나 `-lang:<코드>`(`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`)로 시작하세요. 분석 결과(테이블 내용, 지표, 보고서)는 보고서 및 검색과 일치하도록 영어로 유지됩니다. 번역 파일은 `crates/pelens-gui/i18n/`에 있습니다.',
 lang_caps=['繁體中文', '日本語'],
 q=['테스트 87개', '라인 커버리지 약 97%', 'pefile과 교차 검증'],
 disc='PELens는 독립 프로젝트이며 Winitor 및 pestudio 작성자와 관련이 없고 보증을 받지 않았습니다. 분석 권한이 있는 파일에만 사용하세요.',
 crate='crate', role='역할'),
'es': dict(
 tagline='Una lente para Portable Executables: evaluación inicial estática de malware para binarios de Windows, reconstruida en Rust.',
 intro='PELens examina archivos `.exe`, `.dll` y `.sys` **sin ejecutarlos**. Muestra sus cabeceras, importaciones, recursos, certificados, metadatos .NET y cadenas, y genera indicadores asociados a MITRE ATT&CK. Es una reimplementación desde cero en Rust de **pestudio 9.61**, compatible con su base de conocimiento XML y con la línea de comandos `pestudiox`.',
 h_shots='Capturas', h_feat='Funciones', h_build='Instalación / compilación', h_usage='Uso', h_kb='Base de conocimiento', h_vt='VirusTotal', h_layout='Estructura del proyecto', h_quality='Calidad', h_disc='Aviso',
 cap=['Importaciones con grupos, técnicas MITRE y marcas', 'Cadenas con etiquetas, mapa de ubicación y grupos', 'Secciones (modo claro) con la vista de árbol expandida', 'Cadena de certificados Authenticode y resultado de WinVerifyTrust', 'Cabecera .NET, flujos de metadatos, tablas y espacios de nombres', 'Indicadores (modo oscuro)'],
 feat=[
  '**27 vistas** como en pestudio: image, footprints, groups, indicators, MITRE, puntuación de VirusTotal, DOS stub y header, Rich header, file y optional headers, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest y overlay.',
  '**150 indicadores**, asociados a tácticas y técnicas de MITRE ATT&CK, con severidad editable.',
  '**Motor de firmas**: firmas del punto de entrada (estilo PEiD, con comodines de nibble), firmas de texto y detección de archivos incrustados en recursos, secciones, el overlay y datos base64.',
  '**Analizador que nunca entra en pánico**: imports (INT/IAT, carga diferida, bound), exports (reenviados, anónimos, huecos), recursos (version, manifest, tablas de cadenas y mensajes, diálogos, menús, iconos), debug (RSDS, POGO, REPRO, CET), Authenticode PKCS#7 con sellos de tiempo RFC 3161 y metadatos .NET (las 45 tablas).',
  '**Ayudas para threat hunting**: huellas MD5/SHA-1/SHA-256, imphash (idéntico al de pefile) y enlaces a VirusTotal, Google, Microsoft Learn y MITRE.',
  '**Modificación de archivos**: cambiar entre DLL y EXE, fijar el punto de entrada, alternar characteristics, borrar el overlay, volcar cualquier elemento y abrir un archivo incrustado en un nuevo análisis.',
  '**Informes** en XML, JSON o texto, generados a partir de las mismas tablas que muestra la GUI.',
  '**GUI**: vista de árbol, temas oscuro y claro, tablas ordenables y filtrables, menús contextuales, arrastrar y soltar, y atajos (Ctrl+O, S, E, R, X; Tab recorre el árbol).',
  '**Interfaz en 8 idiomas**: English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch y Français; por defecto sigue el idioma de Windows.'],
 build_note='Requiere Rust 1.85 o posterior (edition 2024). Desarrollado y probado en Windows 11 x64.',
 usage_note='Por defecto la CLI escribe `<input>.xml` junto a la muestra, igual que pestudio.',
 kb='PELens lee los archivos XML de pestudio (`settings.xml`, `indicators.xml`, `functions.xml`, `signatures.xml`, …) de tu propia instalación de pestudio. Indícalos con `-xml:<dir>` o coloca una carpeta `xml` junto al ejecutable. **Estos archivos no se distribuyen con PELens**: pertenecen al autor de pestudio. Sin ellos, PELens funciona con valores predeterminados integrados.',
 vt='Solo se envía el **hash**; las muestras nunca se suben. Configura tu propia clave de API en el diálogo de ajustes o en `VT_API_KEY`. Se usa la API v3 por defecto; la v2 está disponible como opción.',
 roles=['análisis PE (con comprobación de límites, sin pánicos) y parcheo', 'base de conocimiento XML de pestudio, lectura y escritura sin reformatear', 'indicadores, firmas, cadenas, vistas, informes, acciones', 'VirusTotal, enlaces de búsqueda, comprobación de actualizaciones', 'línea de comandos (compatible con pestudiox)', 'GUI eframe/egui'],
 docs='Documentación de diseño: [inventario de funciones](../FEATURE_INVENTORY.md) (212 elementos, cada uno enlazado a su implementación) · [plan de desarrollo](../DEVELOPMENT_PLAN.md) · [lista de tareas](../TASKLIST.md).',
 h_lang='Idiomas de la interfaz',
 lang_note='La interfaz sigue por defecto el idioma de visualización de Windows. Cámbielo en «ver > idioma» o en la configuración, o inicie con `-lang:<código>` (`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`). Los resultados del análisis (contenido de las tablas, indicadores, informes) se mantienen en inglés para coincidir con los informes y las búsquedas. Las traducciones están en `crates/pelens-gui/i18n/`.',
 lang_caps=['繁體中文', '日本語'],
 q=['87 pruebas', '≈ 97 % de cobertura de líneas', 'verificación cruzada con pefile'],
 disc='PELens es un proyecto independiente. No está afiliado a Winitor ni al autor de pestudio, ni cuenta con su respaldo. Úsalo solo con archivos que tengas autorización para analizar.',
 crate='crate', role='función'),
'de': dict(
 tagline='Eine Linse für Portable Executables: statische Malware-Ersteinschätzung für Windows-Binärdateien, neu gebaut in Rust.',
 intro='PELens untersucht `.exe`-, `.dll`- und `.sys`-Dateien, **ohne sie auszuführen**. Es zeigt Header, Importe, Ressourcen, Zertifikate, .NET-Metadaten und Strings und erzeugt Indikatoren, die auf MITRE ATT&CK abgebildet sind. Es ist eine komplette Neuimplementierung von **pestudio 9.61** in Rust, kompatibel mit dessen XML-Wissensbasis und der Kommandozeile `pestudiox`.',
 h_shots='Screenshots', h_feat='Funktionen', h_build='Installation / Build', h_usage='Verwendung', h_kb='Wissensbasis', h_vt='VirusTotal', h_layout='Projektstruktur', h_quality='Qualität', h_disc='Haftungsausschluss',
 cap=['Importe mit Gruppen, MITRE-Techniken und Markierungen', 'Strings mit Labels, Positionskarte und Gruppen', 'Sections im hellen Modus mit aufgeklappter Baumansicht', 'Authenticode-Zertifikatskette und WinVerifyTrust-Ergebnis', '.NET-Header, Metadaten-Streams, Tabellen und Namespaces', 'Indikatoren (dunkler Modus)'],
 feat=[
  '**27 Ansichten** wie in pestudio: image, footprints, groups, indicators, MITRE, VirusTotal-Bewertung, DOS-Stub und -Header, Rich-Header, File- und Optional-Header, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest und overlay.',
  '**150 Indikatoren**, abgebildet auf MITRE-ATT&CK-Taktiken und -Techniken, mit editierbarem Schweregrad.',
  '**Signatur-Engine**: Entry-Point-Signaturen (PEiD-Stil, mit Nibble-Wildcards), Textsignaturen und Erkennung eingebetteter Dateien in Ressourcen, Sections, Overlay und Base64-Daten.',
  '**Parser ohne Panics**: Importe (INT/IAT, Delay-Load, Bound), Exporte (weitergeleitet, anonym, Lücken), Ressourcen (Version, Manifest, String- und Message-Tabellen, Dialoge, Menüs, Icons), Debug (RSDS, POGO, REPRO, CET), Authenticode PKCS#7 mit RFC-3161-Zeitstempeln und .NET-Metadaten (alle 45 Tabellen).',
  '**Hilfen für Threat Hunting**: MD5/SHA-1/SHA-256-Fingerabdrücke, imphash (identisch zu pefile) und Links zu VirusTotal, Google, Microsoft Learn und MITRE.',
  '**Dateiänderungen**: zwischen DLL und EXE wechseln, Entry Point setzen, Characteristics umschalten, Overlay löschen, beliebige Elemente dumpen und eingebettete Dateien in einer neuen Analyse öffnen.',
  '**Berichte** als XML, JSON oder Text, erzeugt aus denselben Tabellen, die die GUI anzeigt.',
  '**GUI**: Baumansicht, dunkles und helles Design, sortier- und filterbare Tabellen, Kontextmenüs, Drag & Drop und Tastenkürzel (Strg+O, S, E, R, X; Tab bewegt sich durch den Baum).',
  '**Oberfläche in 8 Sprachen**: English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch und Français; standardmäßig die Anzeigesprache von Windows.'],
 build_note='Benötigt Rust 1.85 oder neuer (Edition 2024). Entwickelt und getestet unter Windows 11 x64.',
 usage_note='Standardmäßig schreibt die CLI wie pestudio `<input>.xml` neben die Probe.',
 kb='PELens liest die XML-Dateien von pestudio (`settings.xml`, `indicators.xml`, `functions.xml`, `signatures.xml`, …) aus deiner eigenen pestudio-Installation. Gib sie mit `-xml:<dir>` an oder lege einen Ordner `xml` neben die ausführbare Datei. **Diese Dateien werden nicht mit PELens verteilt**: Sie gehören dem Autor von pestudio. Ohne sie läuft PELens mit eingebauten Standardwerten.',
 vt='Es wird nur der **Hash** gesendet; Proben werden nie hochgeladen. Trage deinen eigenen API-Schlüssel im Einstellungsdialog oder in `VT_API_KEY` ein. Standard ist API v3; v2 ist optional verfügbar.',
 roles=['PE-Parsing (mit Grenzprüfungen, ohne Panics) und Patching', 'pestudio-XML-Wissensbasis, Lesen und Schreiben ohne Umformatierung', 'Indikatoren, Signaturen, Strings, Ansichten, Berichte, Aktionen', 'VirusTotal, Suchlinks, Update-Prüfung', 'Kommandozeile (pestudiox-kompatibel)', 'eframe/egui-GUI'],
 docs='Designdokumente: [Funktionsinventar](../FEATURE_INVENTORY.md) (212 Punkte, jeweils mit Verweis auf die Implementierung) · [Entwicklungsplan](../DEVELOPMENT_PLAN.md) · [Aufgabenliste](../TASKLIST.md).',
 h_lang='Sprachen der Oberfläche',
 lang_note='Die Oberfläche folgt standardmäßig der Anzeigesprache von Windows. Wechseln Sie sie unter „Ansicht > Sprache“ oder in den Einstellungen, oder starten Sie mit `-lang:<Code>` (`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`). Analyseergebnisse (Tabelleninhalte, Indikatoren, Berichte) bleiben auf Englisch, damit sie mit Berichten und der Suche übereinstimmen. Die Übersetzungen liegen in `crates/pelens-gui/i18n/`.',
 lang_caps=['繁體中文', '日本語'],
 q=['87 Tests', '≈ 97 % Zeilenabdeckung', 'Abgleich mit pefile'],
 disc='PELens ist ein unabhängiges Projekt. Es steht in keiner Verbindung zu Winitor oder dem Autor von pestudio und wird von ihnen nicht unterstützt. Verwende es nur für Dateien, die du analysieren darfst.',
 crate='Crate', role='Aufgabe'),
'fr': dict(
 tagline='Une loupe pour les Portable Executables : évaluation initiale statique des malwares pour les binaires Windows, réécrite en Rust.',
 intro='PELens examine les fichiers `.exe`, `.dll` et `.sys` **sans les exécuter**. Il affiche leurs en-têtes, imports, ressources, certificats, métadonnées .NET et chaînes, et génère des indicateurs associés à MITRE ATT&CK. C\'est une réécriture complète de **pestudio 9.61** en Rust, compatible avec sa base de connaissances XML et avec la ligne de commande `pestudiox`.',
 h_shots="Captures d'écran", h_feat='Fonctionnalités', h_build='Installation / compilation', h_usage='Utilisation', h_kb='Base de connaissances', h_vt='VirusTotal', h_layout='Structure du projet', h_quality='Qualité', h_disc='Avertissement',
 cap=['Imports avec groupes, techniques MITRE et marqueurs', 'Chaînes avec étiquettes, carte des emplacements et groupes', "Sections en mode clair avec l'arborescence dépliée", 'Chaîne de certificats Authenticode et résultat de WinVerifyTrust', 'En-tête .NET, flux de métadonnées, tables et espaces de noms', 'Indicateurs (mode sombre)'],
 feat=[
  '**27 vues** comme dans pestudio : image, footprints, groups, indicators, MITRE, score VirusTotal, stub et en-tête DOS, en-tête Rich, en-têtes file et optional, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest et overlay.',
  '**150 indicateurs**, associés aux tactiques et techniques MITRE ATT&CK, avec une gravité modifiable.',
  "**Moteur de signatures** : signatures du point d'entrée (style PEiD, avec jokers au niveau du quartet), signatures texte et détection de fichiers intégrés dans les ressources, les sections, l'overlay et les données base64.",
  '**Analyseur qui ne panique jamais** : imports (INT/IAT, chargement différé, bound), exports (redirigés, anonymes, trous), ressources (version, manifest, tables de chaînes et de messages, boîtes de dialogue, menus, icônes), debug (RSDS, POGO, REPRO, CET), Authenticode PKCS#7 avec horodatages RFC 3161 et métadonnées .NET (les 45 tables).',
  '**Aide au threat hunting** : empreintes MD5/SHA-1/SHA-256, imphash (identique à celui de pefile) et liens vers VirusTotal, Google, Microsoft Learn et MITRE.',
  "**Modification de fichiers** : basculer entre DLL et EXE, définir le point d'entrée, basculer les characteristics, supprimer l'overlay, extraire n'importe quel élément et ouvrir un fichier intégré dans une nouvelle analyse.",
  "**Rapports** en XML, JSON ou texte, construits à partir des mêmes tables que celles de l'interface.",
  "**Interface graphique** : arborescence, thèmes sombre et clair, tableaux triables et filtrables, menus contextuels, glisser-déposer et raccourcis (Ctrl+O, S, E, R, X ; Tab parcourt l'arborescence)."],
 build_note='Nécessite Rust 1.85 ou plus récent (édition 2024). Développé et testé sous Windows 11 x64.',
 usage_note="Par défaut, la CLI écrit `<input>.xml` à côté de l'échantillon, comme pestudio.",
 kb="PELens lit les fichiers XML de pestudio (`settings.xml`, `indicators.xml`, `functions.xml`, `signatures.xml`…) depuis votre propre installation de pestudio. Indiquez-les avec `-xml:<dir>` ou placez un dossier `xml` à côté de l'exécutable. **Ces fichiers ne sont pas distribués avec PELens** : ils appartiennent à l'auteur de pestudio. Sans eux, PELens fonctionne avec des valeurs par défaut intégrées.",
 vt="Seul le **hash** est envoyé ; les échantillons ne sont jamais téléversés. Saisissez votre propre clé d'API dans la boîte de dialogue des réglages ou dans `VT_API_KEY`. L'API v3 est utilisée par défaut ; la v2 est disponible en option.",
 roles=['analyse PE (bornes vérifiées, jamais de panique) et modification', 'base de connaissances XML de pestudio, lecture et écriture sans reformatage', 'indicateurs, signatures, chaînes, vues, rapports, actions', 'VirusTotal, liens de recherche, vérification des mises à jour', 'ligne de commande (compatible pestudiox)', 'interface eframe/egui',
  '**Interface en 8 langues** : English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch et Français ; par défaut, la langue d’affichage de Windows.'],
 docs='Documents de conception : [inventaire des fonctionnalités](../FEATURE_INVENTORY.md) (212 éléments, chacun relié à son implémentation) · [plan de développement](../DEVELOPMENT_PLAN.md) · [liste des tâches](../TASKLIST.md).',
 h_lang='Langues de l’interface',
 lang_note='Par défaut, l’interface suit la langue d’affichage de Windows. Changez-la dans « affichage > langue » ou dans les paramètres, ou lancez PELens avec `-lang:<code>` (`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`). Les résultats d’analyse (contenu des tableaux, indicateurs, rapports) restent en anglais pour correspondre aux rapports et à la recherche. Les traductions se trouvent dans `crates/pelens-gui/i18n/`.',
 lang_caps=['繁體中文', '日本語'],
 q=['87 tests', '≈ 97 % de couverture des lignes', 'vérification croisée avec pefile'],
 disc="PELens est un projet indépendant. Il n'est ni affilié à Winitor ni à l'auteur de pestudio, ni approuvé par eux. Ne l'utilisez que sur des fichiers que vous êtes autorisé à analyser.",
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
        f'| ![{SHOTS[4]}]({s}{SHOTS[4]}.png) | |',
        f'| {t["cap"][4]} | |',
    ]
    feats = '\n'.join(f'- {f}' for f in t['feat'])
    layout = '\n'.join(f'| `{c}` | {r} |' for c, r in zip(CRATES, t['roles']))
    return f'''<p align="center">
  <img src="../../assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">{t["tagline"]}</p>

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

## {t["h_build"]}

```bash
cargo build --release
# target/release/pelens.exe      (GUI)
# target/release/pelens-cli.exe  (CLI)
```

{t["build_note"]}

## {t["h_usage"]}

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-lang:zh-TW] [-expand] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir]
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
