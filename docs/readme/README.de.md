<p align="center">
  <img src="../../assets/pelens.png" width="128" alt="PELens logo">
</p>

<h1 align="center">PELens</h1>

<p align="center">Eine Linse für Portable Executables: statische Malware-Ersteinschätzung für Windows-Binärdateien, neu gebaut in Rust.</p>

<p align="center">
  <a href="https://github.com/taida957789/PELens/actions/workflows/ci.yml"><img src="https://github.com/taida957789/PELens/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  · <a href="https://taida957789.github.io/PELens/">Website</a>
</p>

<p align="center">
  <a href="../../README.md">English</a> ·
  <a href="README.zh-TW.md">繁體中文</a> ·
  <a href="README.zh-CN.md">简体中文</a> ·
  <a href="README.ja.md">日本語</a> ·
  <a href="README.ko.md">한국어</a> ·
  <a href="README.es.md">Español</a> ·
  <b>Deutsch</b> ·
  <a href="README.fr.md">Français</a>
</p>

---

PELens untersucht `.exe`-, `.dll`- und `.sys`-Dateien, **ohne sie auszuführen**. Es zeigt Header, Importe, Ressourcen, Zertifikate, .NET-Metadaten und Strings und erzeugt Indikatoren, die auf MITRE ATT&CK abgebildet sind. Es ist eine komplette Neuimplementierung von **pestudio 9.61** in Rust, kompatibel mit dessen XML-Wissensbasis und der Kommandozeile `pestudiox`.

![Indikatoren (dunkler Modus)](../screenshots/indicators-dark.png)

## Screenshots

| | |
|---|---|
| ![imports-dark](../screenshots/imports-dark.png) | ![strings-dark](../screenshots/strings-dark.png) |
| Importe mit Gruppen, MITRE-Techniken und Markierungen | Strings mit Labels, Positionskarte und Gruppen |
| ![sections-light](../screenshots/sections-light.png) | ![certificate-light](../screenshots/certificate-light.png) |
| Sections im hellen Modus mit aufgeklappter Baumansicht | Authenticode-Zertifikatskette und WinVerifyTrust-Ergebnis |
| ![dotnet-dark](../screenshots/dotnet-dark.png) | ![disassembly](../screenshots/disassembly-hex-dark.png) |
| .NET-Header, Metadaten-Streams, Tabellen und Namespaces | Disassemblierung (IAT-Aufrufe mit Funktionsnamen) und Hex-Ansicht |

## Sprachen der Oberfläche

| | |
|---|---|
| ![繁體中文](../screenshots/strings-zh-TW.png) | ![日本語](../screenshots/indicators-ja.png) |
| 繁體中文 | 日本語 |

Die Oberfläche folgt standardmäßig der Systemsprache (Windows-Anzeigesprache, bevorzugte Sprache von macOS, `LANG` unter Linux). Wechseln Sie sie unter „Ansicht > Sprache“ oder in den Einstellungen, oder starten Sie mit `-lang:<Code>` (`en`, `zh-TW`, `zh-CN`, `ja`, `ko`, `es`, `de`, `fr`). Analyseergebnisse (Tabelleninhalte, Indikatoren, Berichte) bleiben auf Englisch, damit sie mit Berichten und der Suche übereinstimmen. Die Übersetzungen liegen in `crates/pelens-gui/i18n/`.

## Funktionen

- **27 Ansichten** wie in pestudio: image, footprints, groups, indicators, MITRE, VirusTotal-Bewertung, DOS-Stub und -Header, Rich-Header, File- und Optional-Header, directories, sections, libraries, imports, exports, exceptions, certificate, relocations, TLS, .NET, resources, version, debug, strings, manifest und overlay.
- **150 Indikatoren**, abgebildet auf MITRE-ATT&CK-Taktiken und -Techniken, mit editierbarem Schweregrad.
- **Signatur-Engine**: Entry-Point-Signaturen (PEiD-Stil, mit Nibble-Wildcards), Textsignaturen und Erkennung eingebetteter Dateien in Ressourcen, Sections, Overlay und Base64-Daten.
- **Parser ohne Panics**: Importe (INT/IAT, Delay-Load, Bound), Exporte (weitergeleitet, anonym, Lücken), Ressourcen (Version, Manifest, String- und Message-Tabellen, Dialoge, Menüs, Icons), Debug (RSDS, POGO, REPRO, CET), Authenticode PKCS#7 mit RFC-3161-Zeitstempeln und .NET-Metadaten (alle 45 Tabellen).
- **Hilfen für Threat Hunting**: MD5/SHA-1/SHA-256-Fingerabdrücke, imphash (identisch zu pefile) und Links zu VirusTotal, Google, Microsoft Learn und MITRE.
- **Dateiänderungen**: zwischen DLL und EXE wechseln, Entry Point setzen, Characteristics umschalten, Overlay löschen, beliebige Elemente dumpen und eingebettete Dateien in einer neuen Analyse öffnen.
- **Berichte** als XML, JSON oder Text, erzeugt aus denselben Tabellen, die die GUI anzeigt.
- **GUI**: Baumansicht, dunkles und helles Design, sortier- und filterbare Tabellen, Kontextmenüs, Drag & Drop und Tastenkürzel (Strg+O, S, E, R, X; Tab bewegt sich durch den Baum).
- **Oberfläche in 8 Sprachen**: English, 繁體中文, 简体中文, 日本語, 한국어, Español, Deutsch und Français; standardmäßig die Systemsprache.
- **Hex-Ansicht** (Strg+H): zeichnet nur sichtbare Zeilen und bleibt auch bei großen Dateien flüssig; Einträge mit Position öffnen sich über „in der Hex-Ansicht zeigen“ im Kontextmenü, mit Sprung zu Offset oder RVA und Kopieren als Hex oder Text.
- **YARA-Scan** (YARA-X): Regelordner unter Einstellungen > YARA oder mit `-yara:<dir>` angeben; jede zutreffende Regel erzeugt einen Indikator (Schweregrad aus dem Metadatum `severity` der Regel), Treffer öffnen sich in der Hex-Ansicht und erscheinen in den Berichten.
- **Disassemblierung** (x86/x64, iced-x86): ab dem Einstiegspunkt, einer exportierten Funktion oder einem TLS-Callback; Aufrufe über die IAT zeigen den Funktionsnamen, Sprüngen kann gefolgt werden, und alles öffnet sich in der Hex-Ansicht.
- **Plattformübergreifend**: dieselben Funktionen unter Windows, Linux und macOS – außerhalb von Windows prüft ein eingebauter Authenticode-Prüfer in reinem Rust (Microsoft- und System-Stammzertifikate); der VirusTotal-Schlüssel liegt im Anmeldeinformationsspeicher des Systems (Windows-Anmeldeinformationsverwaltung, macOS-Schlüsselbund, Linux Secret Service); Prüfung von Netzwerk-/Wechsellaufwerken und ACL; CJK-Schriften des Systems; ⌘-Kurzbefehle unter macOS.

## Installation / Build

**Download**: Laden Sie unter [Releases](https://github.com/taida957789/PELens/releases/latest) die Datei Ihrer Plattform herunter (`windows-x64.zip`, `linux-x86_64.tar.gz`, `macos-universal.zip`); jeweils liegt eine `.sha256`-Datei zur Prüfung bei. Windows: entpacken und `pelens.exe` starten. Linux: entpacken und `./pelens` starten oder mit `./install.sh` nach `~/.local` installieren (mit Desktop-Eintrag und Symbol). macOS (Apple Silicon und Intel): entpacken und `PELens.app` in „Programme“ ziehen; beim ersten Mal Rechtsklick > Öffnen (nicht von Apple notariell beglaubigt). Aus dem Quellcode bauen:

```bash
cargo build --release
# target/release/pelens      (GUI; pelens.exe on Windows)
# target/release/pelens-cli  (CLI; pelens-cli.exe on Windows)
```

Benötigt Rust 1.88 oder neuer (Edition 2024). Die CI baut und testet unter Windows, Linux und macOS.

## Verwendung

```bash
pelens  [file] [-xml:dir] [-view:strings] [-theme:dark|light] [-lang:zh-TW] [-expand] [-hex] [-renderer:wgpu]
pelens-cli -file:sample.exe [-report:out.xml] [-format:xml|json|text] [-vt] [-stdout] [-banner] [-xml:dir] [-yara:dir]
```

Standardmäßig schreibt die CLI wie pestudio `<input>.xml` neben die Probe.

### Wissensbasis

PELens bringt eine eigene **offene Wissensbasis** mit (`kb/`, CC0): 142 Indikatordefinitionen, etwa 2.500 Windows-API-Funktionen, etwa 900 verdächtige Strings, etwa 100 Signaturen und die Zuordnung zu MITRE ATT&CK. Sie wird mit `tools/build_kb.py` aus `kb/src` erzeugt; jeder Eintrag stammt aus öffentlichen Quellen (siehe [kb/SOURCES.md](../../kb/SOURCES.md)), nichts ist aus den XML-Dateien von pestudio kopiert. Mit `-xml:<dir>` können Sie stattdessen die XML-Dateien Ihrer eigenen pestudio-Installation verwenden; sie gehören dem Autor von pestudio und werden nicht mit PELens verteilt.

### VirusTotal

Es wird nur der **Hash** gesendet; Proben werden nie hochgeladen. Trage deinen eigenen API-Schlüssel im Einstellungsdialog oder in `VT_API_KEY` ein. Standard ist API v3; v2 ist optional verfügbar.

## Projektstruktur

| Crate | Aufgabe |
|---|---|
| `pe-parser` | PE-Parsing (mit Grenzprüfungen, ohne Panics) und Patching |
| `pe-db` | pestudio-XML-Wissensbasis, Lesen und Schreiben ohne Umformatierung |
| `pe-analysis` | Indikatoren, Signaturen, Strings, Ansichten, Berichte, Aktionen |
| `pe-online` | VirusTotal, Suchlinks, Update-Prüfung |
| `pelens-cli` | Kommandozeile (pestudiox-kompatibel) |
| `pelens-gui` | eframe/egui-GUI |

Designdokumente: [Funktionsinventar](../FEATURE_INVENTORY.md) (212 Punkte, jeweils mit Verweis auf die Implementierung) · [Entwicklungsplan](../DEVELOPMENT_PLAN.md) · [Aufgabenliste](../TASKLIST.md).

## Qualität

```bash
cargo test --workspace                       # 107 Tests
cargo llvm-cov --workspace --summary-only    # ≈ 97 % Zeilenabdeckung
python tools/crossval.py 250                 # Abgleich mit pefile
```

## Haftungsausschluss

PELens ist ein unabhängiges Projekt. Es steht in keiner Verbindung zu Winitor oder dem Autor von pestudio und wird von ihnen nicht unterstützt. Verwende es nur für Dateien, die du analysieren darfst.
