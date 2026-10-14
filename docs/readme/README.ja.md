<p align="center">
  <img src="../../assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">Portable Executable のためのレンズ — Rust で作り直した、Windows バイナリ向けの静的マルウェア初期評価ツール。</p>

<p align="center">
  [![CI](https://github.com/taida957789/PELens/actions/workflows/ci.yml/badge.svg)](https://github.com/taida957789/PELens/actions/workflows/ci.yml)
</p>

<p align="center">
  <a href="../../README.md">English</a> ·
  <a href="README.zh-TW.md">繁體中文</a> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <b>日本語</b> ·
  <a href="README.ko.md">한국어</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.de.md">Deutsch</a> ·
  <a href="README.fr.md">Français</a>
</p>

---

PELens は `.exe`・`.dll`・`.sys` を**実行せずに**調べます。ヘッダー、インポート、リソース、証明書、.NET メタデータ、文字列を表示し、MITRE ATT&CK に対応したインジケーターを出します。**pestudio 9.61** を Rust でゼロから再実装したもので、pestudio の XML ナレッジベースと `pestudiox` コマンドラインに対応しています。

![インジケーター（ダークモード）](../screenshots/indicators-dark.png)

## スクリーンショット

| | |
|---|---|
| ![imports-dark](../screenshots/imports-dark.png) | ![strings-dark](../screenshots/strings-dark.png) |
| インポート：グループ、MITRE テクニック、フラグ | 文字列：ラベル、位置マップ、グループ |
| ![sections-light](../screenshots/sections-light.png) | ![certificate-light](../screenshots/certificate-light.png) |
| セクション（ライトモード）と展開したツリービュー | Authenticode 証明書チェーンと WinVerifyTrust の結果 |
| ![dotnet-dark](../screenshots/dotnet-dark.png) | |
| .NET ヘッダー、メタデータストリーム、テーブル、名前空間 | |

## 表示言語

| | |
|---|---|
| ![繁體中文](../screenshots/strings-zh-TW.png) | ![日本語](../screenshots/indicators-ja.png) |
| 繁體中文 | 日本語 |

表示言語は既定で Windows の表示言語に従います。「表示 > 言語」または設定ダイアログで切り替えるか、`-lang:<コード>`（`en`・`zh-TW`・`zh-CN`・`ja`・`ko`・`es`・`de`・`fr`）で起動してください。解析結果（テーブルの内容、インジケーター、レポート）は、レポートや検索と一致するよう英語のままです。翻訳ファイルは `crates/pelens-gui/i18n/` にあります。

## 機能

- pestudio と同じ **27 のビュー**：image、footprints、groups、indicators、MITRE、VirusTotal スコア、DOS stub／header、Rich header、file／optional header、directories、sections、libraries、imports、exports、exceptions、certificate、relocations、TLS、.NET、resources、version、debug、strings、manifest、overlay。
- MITRE ATT&CK の戦術・テクニックに対応した **150 のインジケーター**。重大度は編集できます。
- **シグネチャエンジン**：エントリポイントシグネチャ（PEiD 形式、ニブル単位のワイルドカード対応）、テキストシグネチャ、resources・sections・overlay・base64 内の埋め込みファイル検出。
- **パニックしないパーサー**：imports（INT/IAT、遅延ロード、bound）、exports（forwarded、anonymous、gaps）、resources（version、manifest、文字列／メッセージテーブル、ダイアログ、メニュー、アイコン）、debug（RSDS、POGO、REPRO、CET）、RFC 3161 タイムスタンプ付き Authenticode PKCS#7、.NET メタデータ（全 45 テーブル）。
- **ハンティング支援**：MD5/SHA-1/SHA-256 フットプリント、imphash（pefile と同一）、VirusTotal・Google・Microsoft Learn・MITRE へのリンク。
- **ファイル変更**：DLL ⇄ EXE の切り替え、エントリポイントの設定、characteristics の切り替え、overlay の削除、任意の項目のダンプ、埋め込みファイルを新しい解析で開く。
- **レポート**：XML・JSON・テキスト。GUI と同じテーブルから生成します。
- **GUI**：ツリービュー、ダーク／ライトテーマ、並べ替え・絞り込みできるテーブル、右クリックメニュー、ドラッグ＆ドロップ、ショートカット（Ctrl+O・S・E・R・X、Tab でツリーを移動）。
- **8 つの表示言語**：English、繁體中文、简体中文、日本語、한국어、Español、Deutsch、Français。既定では Windows の表示言語に合わせます。
- **16 進ビュー**（Ctrl+H）：表示中の行だけを描画するので大きなファイルでも軽快です。位置情報のある項目は右クリックの「16 進ビューで表示」から開け、オフセットや RVA への移動、16 進またはテキストでのコピーができます。

## インストール／ビルド

**ダウンロード**：[Releases](https://github.com/taida957789/PELens/releases/latest) から `PELens-<バージョン>-windows-x64.zip` を入手し、展開して `pelens.exe` を実行します（インストール不要）。検証用の `.sha256` も付いています。ソースからビルドする場合：

```bash
cargo build --release
# target/release/pelens.exe      (GUI)
# target/release/pelens-cli.exe  (CLI)
```

Rust 1.88 以降（edition 2024）が必要です。Windows 11 x64 で開発・テストしています。

## 使い方

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-lang:zh-TW] [-expand] [-hex] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir]
```

CLI は既定で、pestudio と同じくサンプルの隣に `<input>.xml` を書き出します。

### ナレッジベース

PELens は独自の**オープンナレッジベース**（`kb/`、CC0）を内蔵しています。142 のインジケーター定義、約 2,500 の Windows API 関数、約 900 の不審な文字列、約 100 のシグネチャ、MITRE ATT&CK の対応付けを含みます。`tools/build_kb.py` で `kb/src` から生成され、すべての項目は公開情報に基づいて書かれています（[kb/SOURCES.md](../../kb/SOURCES.md) を参照）。pestudio の XML はコピーしていません。`-xml:<dir>` でご自身の pestudio の XML ファイルを使うこともできます。これらは pestudio の作者のもので、PELens には同梱されません。

### VirusTotal

送信するのは**ハッシュだけ**で、サンプルはアップロードしません。API キーは設定ダイアログか `VT_API_KEY` で指定してください。既定は API v3 で、v2 も選べます。

## プロジェクト構成

| crate | 役割 |
|---|---|
| `pe-parser` | PE 解析（境界チェック済み、パニックしない）とパッチ |
| `pe-db` | pestudio XML ナレッジベース（書式を保ったまま読み書き） |
| `pe-analysis` | インジケーター、シグネチャ、文字列、ビュー、レポート、アクション |
| `pe-online` | VirusTotal、検索リンク、更新チェック |
| `pelens-cli` | コマンドライン（pestudiox 互換） |
| `pelens-gui` | eframe/egui GUI |

設計資料：[機能一覧](../FEATURE_INVENTORY.md)（212 項目、それぞれ実装箇所へのリンク付き）· [開発計画](../DEVELOPMENT_PLAN.md) · [タスクリスト](../TASKLIST.md)。

## 品質

```bash
cargo test --workspace                       # 102 件のテスト
cargo llvm-cov --workspace --summary-only    # 約 97% の行カバレッジ
python tools/crossval.py 250                 # pefile とのクロスチェック
```

## 免責事項

PELens は独立したプロジェクトで、Winitor および pestudio の作者とは関係がなく、承認も受けていません。解析する権限のあるファイルにのみ使用してください。
