<p align="center">
  <img src="assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">
  <b>A lens for Portable Executables</b> — static malware initial assessment for Windows binaries, rebuilt in Rust.
</p>

<p align="center">
  <a href="https://github.com/taida957789/PELens/actions/workflows/ci.yml"><img src="https://github.com/taida957789/PELens/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  · <a href="https://taida957789.github.io/PELens/">Website</a>
</p>

<p align="center">
  <b>English</b> ·
  <a href="docs/readme/README.zh-TW.md">繁體中文</a> ·
  <a href="docs/readme/README.zh-CN.md">简体中文</a> ·
  <a href="docs/readme/README.ja.md">日本語</a> ·
  <a href="docs/readme/README.ko.md">한국어</a> ·
  <a href="docs/readme/README.es.md">Español</a> ·
  <a href="docs/readme/README.de.md">Deutsch</a> ·
  <a href="docs/readme/README.fr.md">Français</a>
</p>

---

PELens inspects `.exe`, `.dll` and `.sys` files **without running them**. It shows their
headers, imports, resources, certificates, .NET metadata and strings, and it raises
indicators mapped to MITRE ATT&CK. It is written from scratch in Rust and driven by an XML
knowledge base that you can extend or replace.

![Indicators (dark mode)](docs/screenshots/indicators-dark.png)

## Screenshots

| | |
|---|---|
| ![Imports](docs/screenshots/imports-dark.png) | ![Strings](docs/screenshots/strings-dark.png) |
| Imports with groups, MITRE techniques and flags | Strings with labels, location map and groups |
| ![Sections (light)](docs/screenshots/sections-light.png) | ![Certificate (light)](docs/screenshots/certificate-light.png) |
| Sections, light mode, with the expanded tree-view | Authenticode certificate chain and WinVerifyTrust result |
| ![.NET](docs/screenshots/dotnet-dark.png) | ![Disassembly](docs/screenshots/disassembly-hex-dark.png) |
| .NET header, metadata streams, tables and namespaces | Disassembly (calls through the IAT named) and hex view |

## Interface languages

| | |
|---|---|
| ![繁體中文](docs/screenshots/strings-zh-TW.png) | ![日本語](docs/screenshots/indicators-ja.png) |
| 繁體中文 | 日本語 |

The interface follows the system language by default (the Windows display language, the macOS
preferred language, `LANG` on Linux). Change it in view > language or
in the settings dialog, or start with `-lang:<code>` (`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`,
`de`, `fr`). Analysis results (table contents, indicators, reports) stay in English so they
match the reports and what the search box finds. The translations live in
`crates/pelens-gui/i18n/`.

## Features

- **27 views**: image, footprints, groups, indicators, MITRE, VirusTotal score,
  DOS stub and header, Rich header, file and optional headers, directories, sections,
  libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources,
  version, debug, strings, manifest and overlay, plus YARA and disassembly views.
- **150 indicators**, mapped to MITRE ATT&CK tactics and techniques, with severities you can edit.
- **Signature engine**: entry-point signatures (PEiD style, with nibble wildcards), text
  signatures, and embedded-file detection in resources, sections, the overlay and base64 data.
- **Parser that never panics**: imports (INT/IAT, delay-load, bound), exports (forwarded,
  anonymous, gaps), resources (version, manifest, string and message tables, dialogs, menus,
  icons), debug (RSDS, POGO, REPRO, CET), Authenticode PKCS#7 with RFC 3161 timestamps,
  and .NET metadata (all 45 tables).
- **Hunting helpers**: MD5/SHA-1/SHA-256 footprints, imphash (identical to pefile's), and links
  to VirusTotal, Google, Microsoft Learn and MITRE.
- **File modifications**: switch between DLL and EXE, set the entry point, toggle characteristics,
  delete the overlay, dump any item, and open an embedded file in a new analysis.
- **Reports** in XML, JSON or text, built from the same tables the GUI shows.
- **GUI**: tree-view, dark and light themes, sortable and filterable tables, context menus,
  drag and drop, and shortcuts (Ctrl+O, S, E, R, X; Tab moves through the tree).
- **Hex view** (Ctrl+H): draws only the visible lines, so it stays smooth on large files. Items
  with a position open there from the context menu ("show in hex"); go to an offset or an RVA,
  copy as hex or text.
- **YARA scan** (YARA-X): set a rules folder in settings > YARA or with `-yara:<dir>`. Every
  matching rule raises an indicator (severity from the rule's `severity` metadata); the matches
  open in the hex view and are part of the reports.
- **Disassembly** (x86/x64, iced-x86): from the entry point, an exported function or a TLS
  callback; calls through the IAT show the imported function, branches can be followed, and every
  instruction opens in the hex view.
- **Interface in 8 languages**: English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch and
  Français; by default the system language.
- **Cross-platform**: the same features on Windows, Linux and macOS. Outside Windows, Authenticode
  signatures are checked by a built-in pure-Rust verifier (Microsoft roots plus the system's
  roots); the VirusTotal key is kept in the system credential store (Windows Credential Manager,
  macOS Keychain, Linux Secret Service); network/removable drives and file ACLs are detected; the
  system's CJK fonts are used; shortcuts use ⌘ on macOS.

## Install / build

**Download** the file for your platform from [Releases](https://github.com/taida957789/PELens/releases/latest); each has a `.sha256`
file next to it.

| Platform | File | Run |
|---|---|---|
| Windows x64 | `PELens-<version>-windows-x64.zip` | unzip, run `pelens.exe`; nothing to install |
| Linux x86_64 | `PELens-<version>-linux-x86_64.tar.gz` | extract, run `./pelens`, or `./install.sh` to install into `~/.local` (desktop entry and icon) |
| macOS (Apple silicon and Intel) | `PELens-<version>-macos-universal.zip` | unzip, move `PELens.app` to Applications; the first time, right-click > Open (the app is not notarized) |

To build from source:

```bash
cargo build --release
# target/release/pelens      (GUI; pelens.exe on Windows)
# target/release/pelens-cli  (command line; pelens-cli.exe on Windows)
```

You need Rust 1.88 or newer (edition 2024). CI builds it and runs every test on Windows, Linux
and macOS. On Linux, file dialogs use the XDG desktop portal and the VirusTotal key the Secret
Service (GNOME Keyring, KWallet); without them, use `VT_API_KEY`.

## Usage

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-lang:zh-TW] [-expand] [-hex] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir] [-yara:dir]
```

By default the CLI writes `<input>.xml` next to the sample.

### Knowledge base

PELens ships its own **open knowledge base** (`kb/`, CC0): 142 indicator definitions, about 2,500
Windows API functions, about 900 suspicious strings, about 100 signatures and the MITRE ATT&CK
mapping. `tools/build_kb.py` builds it from `kb/src`; every entry was written from public sources
(see [kb/SOURCES.md](kb/SOURCES.md)); nothing is copied from third-party knowledge bases.

You can use other XML knowledge files in the same format instead: pass `-xml:<dir>` or put an
`xml` folder next to the executable. Third-party knowledge files are not distributed with PELens.

### VirusTotal

Only the **hash** is sent; samples are never uploaded. Set your own API key in the settings
dialog or in `VT_API_KEY`. API v3 is the default; v2 is available as an option.

## Project layout

| crate | role |
|---|---|
| `pe-parser` | PE parsing (bounds-checked, never panics) and patching |
| `pe-db` | XML knowledge base, read and write without reformatting |
| `pe-analysis` | indicators, signatures, strings, views, reports, actions |
| `pe-online` | VirusTotal, search links, update check |
| `pelens-cli` | command line |
| `pelens-gui` | eframe/egui GUI |

Design notes: [feature inventory](docs/FEATURE_INVENTORY.md) (212 items, each with a
traceability link) · [development plan](docs/DEVELOPMENT_PLAN.md) · [task list](docs/TASKLIST.md).

## Quality

```bash
cargo test --workspace                       # 107 tests
cargo llvm-cov --workspace --summary-only    # ≈ 97 % line coverage
python tools/crossval.py 250                 # cross-check against pefile
```

## Disclaimer

PELens is an independent project. Use it only on files you are authorised to analyse.
