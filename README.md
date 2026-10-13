# PELens

![PELens](assets/pelens.png)

**PELens** (PE + lens: a lens for Portable Executables) is a Rust remake of **pestudio 9.61** (Malware Initial Assessment): static analysis of
Windows executables without running them. It includes a GUI (`pelens`), a command line
tool (`pelens-cli`, pestudiox-compatible arguments) and the analysis libraries behind both.

- Feature inventory of the original: [`docs/FEATURE_INVENTORY.md`](docs/FEATURE_INVENTORY.md)
- Development plan: [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md)
- Task tracking: [`docs/TASKLIST.md`](docs/TASKLIST.md)

## Build

```
cargo build --release
```

This produces `target/release/pelens.exe` (GUI) and `target/release/pelens-cli.exe` (CLI); both embed the PELens icon (`assets/`, regenerated with `python tools/make_icon.py`).
You need Rust 1.85 or newer (edition 2024). The project was built and tested with 1.97 on Windows 11 x64.

## Knowledge base (XML)

pestudio's behaviour comes from its XML files (`settings.xml`, `indicators.xml`,
`functions.xml`, `signatures.xml`, `strings.xml`, `mitre.xml`, …). Those files belong to
the original author and may not be used outside pestudio without his authorisation, so
**they are not part of this repository**. PELens reads them from your own pestudio
installation:

1. `-xml:<dir>` on the command line, or
2. an `xml` folder next to the executable, `./xml`, or `../xml`.

Without them, PELens still runs on built-in defaults: all parsing and views work,
and indicators use a smaller built-in set. Edits made from the GUI, such as changing a
severity, toggling a flag or changing a setting, are written back to these files the
same way pestudio does it.

## GUI

```
pelens [file] [-xml:dir] [-renderer:wgpu]
```

- Dark mode is the default (view menu or the toolbar sun/moon toggles it; stored as `<theme dark="…">`). The UI uses Segoe UI, Consolas for hashes, offsets and hex, and Microsoft JhengHei as a CJK fallback when those fonts are installed.
- The left pane is a tree-view: the file is the root, and indicators, sections, libraries and resources expand to their items. Clicking an item filters the list.

- Use the file menu or drag and drop to open a file. The shortcuts are Ctrl+O (open),
  Ctrl+S (save), Ctrl+E (close), Ctrl+R (report) and Ctrl+X (exit). Tab and Shift+Tab move
  through the tree.
- The tree shows the 27 views of pestudio: image, footprints, groups, indicators, mitre,
  score, dos-stub, dos-header, rich-header, file-header, optional-header, directories,
  sections, libraries, imports, exports, exceptions, certificate, relocations,
  thread-local-storage, dotnet, resources, version, debug, strings, manifest and overlay.
  The number after a view counts its flagged items.
- Tables can be sorted by clicking a header and filtered with the search box. You can
  also hide columns, show or hide duplicates, and save the view to a text file.
- The right-click menu offers copy (line, value, detail, …) and lookups on VirusTotal,
  Google, Microsoft Learn and MITRE. It also lets you dump an item to a file, open an
  embedded file in a new analysis, set a severity, toggle a flag (library, function,
  namespace or language), toggle a characteristic, set the entry point, delete the
  overlay and query a VirusTotal score.
- The settings dialog has the same tabs as pestudio: General, Footprints, First-bytes and
  Virustotal.
- `-renderer:wgpu` (or `PELENS_RENDERER=wgpu`) switches from OpenGL to the
  wgpu/DirectX renderer.

## CLI

```
pelens-cli -file:input [-report:output] [-banner] [-xml:dir] [-format:xml|json|text] [-vt] [-stdout]
```

By default the report is written next to the input file as `<input>.xml`, like pestudio
does. The XML report serialises the same tables the GUI shows, so the two stay in sync.

## VirusTotal

Only the **hash** of a file is sent; the file itself is never uploaded. You supply the
API key: set it in the settings dialog (`<score key="…">`) or in the `VT_API_KEY`
environment variable. API v3 is the default and `<score api="2">` switches to v2.
PELens does not ship the vendor's built-in key.

## Architecture

| crate | role |
|---|---|
| `pe-parser` | Parses PE files without panicking on malformed input. It covers the headers, Rich header, sections, imports (INT/IAT, delay-load, bound), exports, resources and their contents, debug, TLS, relocations, exceptions, load-config, Authenticode PKCS#7 and .NET metadata. It also patches files. |
| `pe-db` | Loads the pestudio XML knowledge base and writes changes back without reformatting the files. |
| `pe-analysis` | Builds hashes, imphash, entropy, signatures, embedded-file detection, strings and labels, groups, MITRE mapping, footprints and the indicators. It also produces the views, the reports (XML, JSON, text) and the dump and modify actions. |
| `pe-online` | VirusTotal v2/v3 queries, search links, the update check and the proxy. |
| `pelens-cli` | The CLI. |
| `pelens-gui` | The eframe/egui GUI, split into a testable model and the egui rendering layer. |

## Tests

```
cargo test --workspace
cargo llvm-cov --workspace --summary-only     # coverage (cargo install cargo-llvm-cov)
python tools/crossval.py 250                  # cross-validation against pefile
```

The tests build their PE samples synthetically with `pe_parser::testutil`, including
certificates, .NET metadata and malformed files. They use a fixture knowledge base
written for this project and replace the network with mocks. The GUI is exercised
headless with `egui_kittest`. Some extra tests run on `C:\Windows\System32` when that
folder exists.
